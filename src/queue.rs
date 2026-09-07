//! Approval lock, FIFO ordering, queue-depth broadcast.
//!
//! Several agents can be sandboxed against one daemon, so several requests can
//! arrive at once, and only one of them may be an approval window on screen.
//! This module is the lock that picks which, and the counter that tells the
//! window on screen how many are behind it.
//!
//! # The lock is released at Approve, not at completion
//!
//! [`ApprovalQueue::acquire`] hands back an [`Admission`]: a permit, the badge
//! number for [`crate::protocol::Request::queue_depth`], and the receiver that
//! feeds later badge updates through [`crate::prompter::Prompter::prompt`]. The
//! permit is dropped when the *verdict* arrives, not when the approved command
//! finishes. A five-minute `pacman -Syu` must not hold every other agent behind
//! it, and the window that stays on screen while it runs is a running
//! indicator, not an approval. The accepted consequence is several running
//! indicators at once.
//!
//! No type here can force that, because the permit is an opaque guard the
//! daemon holds for as long as it likes. What this module can do is make the
//! right shape the easy one to write, which is why [`Admission::into_parts`]
//! exists: it splits the thing to release from the thing to keep, so the
//! release site is a `drop` of one named value at the verdict rather than a
//! scope that happens to end in the right place.
//!
//! # What "depth" counts
//!
//! Waiters. Only waiters. The window holding the permit is not waiting, so it
//! is never in the count, and the badge it draws -- "N more waiting" -- is the
//! published number with nothing subtracted from it.
//!
//! That is the entire reason there is no subtraction anywhere in hatch. A depth
//! that included the holder would need one decrement per window, in two places
//! that are hours apart in the code: the initial figure in
//! [`crate::protocol::Request::queue_depth`] and every later
//! [`crate::protocol::DaemonMsg::QueueDepth`]. Two subtractions, each easy to
//! forget, and forgetting either shows an off-by-one to a human being asked to
//! approve something. Counting waiters only means every way of asking gives the
//! same already-correct answer: [`ApprovalQueue::depth`],
//! [`Admission::queue_depth`], and every value on the broadcast.
//!
//! One consequence for whoever draws the window: after Approve the permit is
//! gone but the receiver is not, so a running indicator keeps receiving numbers
//! that now describe the queue behind *someone else's* window. A running
//! indicator must not draw the badge. The channel is not closed per-window
//! here because the daemon has no per-window sender to close, and a badge the
//! UI simply stops drawing is a smaller mechanism than one the queue would have
//! to track windows to silence.
//!
//! # Fairness
//!
//! `tokio::sync::Semaphore` is documented fair -- "permits are given out in the
//! order they were requested" -- and is implemented as an intrusive waiter list
//! pushed at the back and popped at the front. So there is no separate waiter
//! queue in this module. The counter is a counter and not a queue: it decides
//! nothing about order, and exists only because the semaphore does not expose
//! how many tasks are parked on it.
//!
//! The order is *registration* order, and a task registers on the first poll of
//! its `acquire` future, not when it is spawned. Nothing in the daemon depends
//! on that distinction -- a request that has not been polled has not arrived --
//! but a test asserting fairness does, and this module's does.
//!
//! Under the request flood the spec accepts rather than throttles, FIFO is also
//! the whole starvation answer: a parked waiter is ahead of every request that
//! has not yet registered, and an arrival is by definition later than what is
//! already parked, so the queue drains oldest-first however fast it fills. New
//! arrivals cannot jump ahead, and a flood makes the wait long, never
//! unbounded.
//!
//! # A waiter that goes away
//!
//! An agent disconnects; a request's deadline passes while it is still queued.
//! Either way the daemon drops the `acquire` future. Being counted is a guard
//! local to that future, so dropping it decrements and republishes on exactly
//! the path that being admitted does. There is no phantom waiter and no
//! permanently wrong badge -- which is the failure this module is most able to
//! cause and least able to notice, since nothing downstream would ever
//! contradict a badge that is quietly one too high forever.
//!
//! # A badge is allowed to lag
//!
//! `tokio::sync::broadcast` drops values for a receiver that has fallen behind
//! and reports `Lagged`. That is acceptable here, because this is a
//! latest-value display and not a log: every dropped value has been superseded
//! by one still in the buffer, and a receiver that keeps reading after a
//! `Lagged` ends on the current figure. [`crate::prompter`] treats `Lagged` as
//! `continue` for that reason. It is not the channel closing -- treating it as
//! closing would freeze the badge for the life of the window -- and
//! resubscribing would be worse than reading on, since it discards the buffered
//! values that were about to correct the display.
//!
//! A reader of a stale badge is therefore misled about one thing: how many
//! *other* agents are waiting, briefly, while the true number is on its way.
//! Never about the request in the window, and nothing is gated on the number.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast};

/// How many depth updates a window may fall behind by before it is lagged.
///
/// Generous for a value that changes once per arrival and once per admission,
/// and cheap: the buffer is `usize`s. Exceeding it costs a stale badge for as
/// long as it takes the window to read again, which is the reason this is a
/// number and not a design question.
const DEPTH_UPDATES: usize = 64;

// ---- the queue -------------------------------------------------------------

/// The one approval window at a time, and the count of what is behind it.
pub struct ApprovalQueue {
    /// One permit: the approval lock itself. `Arc` because the permit it hands
    /// out is `'static`, so the daemon can hold an approval across a task
    /// boundary without borrowing the queue.
    lock: Arc<Semaphore>,
    /// The waiter count and its broadcast, under one lock so that a subscriber
    /// cannot be created in the gap between a change and its publication. A
    /// window that subscribed in that gap would miss the update and draw a
    /// stale badge for as long as nothing else changed.
    state: Mutex<State>,
}

struct State {
    /// Tasks parked in [`ApprovalQueue::acquire`]. Never the holder.
    waiting: usize,
    updates: broadcast::Sender<usize>,
}

impl State {
    fn publish(&self) {
        // No receivers is the normal case with no window open, and is not a
        // failure: the next window's initial badge comes from `Admission`.
        let _ = self.updates.send(self.waiting);
    }
}

impl ApprovalQueue {
    /// An empty queue with the lock free.
    #[must_use]
    pub fn new() -> Self {
        let (updates, _) = broadcast::channel(DEPTH_UPDATES);
        Self { lock: Arc::new(Semaphore::new(1)), state: Mutex::new(State { waiting: 0, updates }) }
    }

    /// Wait for the approval lock, in arrival order.
    ///
    /// Cancel-safe in the way that matters: dropping this future before it
    /// resolves -- a deadline, a disconnected agent, an aborted task -- removes
    /// its waiter from the count and publishes the new depth. It never leaves a
    /// phantom behind.
    pub async fn acquire(&self) -> Admission {
        let waiting = Waiting::enter(&self.state);
        let permit = Arc::clone(&self.lock)
            .acquire_owned()
            .await
            .expect("the approval lock is never closed");
        // Stop being a waiter, read the depth and subscribe, all under one lock
        // -- see `State`. From here this task is the holder, so the depth it
        // reads already excludes it.
        let (depth, updates) = waiting.admitted();
        Admission { permit: ApprovalPermit(permit), depth, updates }
    }

    /// How many approvals are waiting right now, excluding whichever holds the
    /// lock.
    #[must_use]
    pub fn depth(&self) -> usize {
        locked(&self.state).waiting
    }

    /// Watch the depth for changes.
    ///
    /// Changes only: a new receiver sees nothing until the next arrival or
    /// admission. The value to start from is [`Admission::queue_depth`], taken
    /// atomically with the subscription that [`ApprovalQueue::acquire`] hands
    /// back, so there is no gap between the two. This method is for everything
    /// else -- diagnostics, and tests.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<usize> {
        locked(&self.state).updates.subscribe()
    }
}

impl Default for ApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---- what a request gets when its turn comes -------------------------------

/// The approval lock, held.
///
/// Drop it when the verdict arrives. Not when the command it authorised ends:
/// see this module's header.
#[must_use = "the approval lock is held only while this is alive"]
pub struct ApprovalPermit(#[allow(dead_code)] OwnedSemaphorePermit);

/// One request's turn: the lock, the badge, and the badge's updates.
#[must_use = "the approval lock is held only while this, or the permit inside it, is alive"]
pub struct Admission {
    permit: ApprovalPermit,
    depth: usize,
    updates: broadcast::Receiver<usize>,
}

impl Admission {
    /// The initial badge, for [`crate::protocol::Request::queue_depth`].
    ///
    /// Saturating rather than wrapping, on the same grounds as the conversion
    /// [`crate::prompter`] applies to the later updates: a queue this deep is
    /// not reachable, and if it somehow were, a badge reading "3 more waiting"
    /// for four billion would be a lie where an implausible number is merely
    /// surprising.
    #[must_use]
    pub fn queue_depth(&self) -> u32 {
        badge(self.depth)
    }

    /// Split into the permit to release at the verdict and the receiver to hand
    /// [`crate::prompter::Prompter::prompt`].
    ///
    /// The split is the point: it puts the release on a named value, so the
    /// verdict site reads as a release rather than as a scope that ends.
    pub fn into_parts(self) -> (ApprovalPermit, broadcast::Receiver<usize>) {
        (self.permit, self.updates)
    }
}

fn badge(depth: usize) -> u32 {
    u32::try_from(depth).unwrap_or(u32::MAX)
}

// ---- being counted ---------------------------------------------------------

/// One task's membership of the waiter count, for as long as it is waiting.
///
/// A guard and not a pair of calls, because the two ways to stop waiting are
/// being admitted and being dropped, and only one of them is on a path anyone
/// remembers to write.
struct Waiting<'a> {
    /// `None` once the count has been left, so being admitted and then dropped
    /// decrements once rather than twice.
    state: Option<&'a Mutex<State>>,
}

impl<'a> Waiting<'a> {
    fn enter(state: &'a Mutex<State>) -> Self {
        let mut s = locked(state);
        s.waiting += 1;
        s.publish();
        drop(s);
        Self { state: Some(state) }
    }

    /// Leave the count as the new holder: the depth read here is the badge for
    /// the window about to open, and the subscription is taken under the same
    /// lock so nothing can change between the two.
    fn admitted(mut self) -> (usize, broadcast::Receiver<usize>) {
        let state = self.state.take().expect("a waiter leaves the count exactly once");
        let s = leave(state);
        (s.waiting, s.updates.subscribe())
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state {
            drop(leave(state));
        }
    }
}

/// Take one off the count and publish, returning the still-held lock.
///
/// The only decrement in the module, so admission and cancellation cannot
/// disagree about what leaving costs.
fn leave(state: &Mutex<State>) -> MutexGuard<'_, State> {
    let mut s = locked(state);
    s.waiting -= 1;
    s.publish();
    s
}

/// The state, whether or not a previous holder panicked.
///
/// Poisoning would mean a panic between a change and its publication, and the
/// worst it can leave behind is a badge that is briefly wrong. Refusing to
/// serve approvals for the rest of the daemon's life over that would be the
/// larger failure.
fn locked(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time::timeout;

    /// A hard ceiling on anything that waits on the lock or on a channel.
    ///
    /// Every one of these finishes in microseconds when the code works. When it
    /// does not -- which is what most of this module's mutants do -- the wait is
    /// on a permit that will never be handed over, and a test that can hang
    /// forever is a test that takes the whole run with it.
    const PATIENCE: Duration = Duration::from_secs(10);

    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        timeout(PATIENCE, fut).await.expect("this waited on something that never happened")
    }

    /// Park a waiter on `q` and return once it is on the semaphore's list.
    ///
    /// Spawn order is not queue order: a task joins the waiter list on the
    /// first poll of `acquire`, not when it is spawned. The depth update is
    /// published on that same poll and immediately before the registration, and
    /// these are current-thread runtimes, so a caller that has seen the update
    /// has seen a task that ran past the registration and parked. Waiting for
    /// it is what makes an ordering assertion a fairness check rather than a
    /// check that some tasks happened to be polled in the order they were
    /// created.
    async fn park(
        q: &Arc<ApprovalQueue>,
        depth: &mut broadcast::Receiver<usize>,
        expected: usize,
        body: impl FnOnce(Admission) + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let q = Arc::clone(q);
        let handle = tokio::spawn(async move { body(q.acquire().await) });
        assert_eq!(within(depth.recv()).await.unwrap(), expected, "a waiter did not park");
        handle
    }

    // ---- the lock ----------------------------------------------------------

    #[tokio::test]
    async fn only_one_approval_runs_at_a_time() {
        let q = ApprovalQueue::new();
        let _open = q.acquire().await;

        // Real time, and it costs the suite the full 100 ms. The alternative is
        // a paused clock, which needs tokio's `test-util` and buys nothing: this
        // assertion is that a future never completes, so there is no race to
        // lose and no length of wait that could make it flaky in either
        // direction.
        let second = timeout(Duration::from_millis(100), q.acquire()).await;

        assert!(second.is_err(), "a second approval window opened while one was already up");
    }

    #[tokio::test]
    async fn the_lock_releases_at_approve_not_at_completion() {
        let q = ApprovalQueue::new();
        let (permit, _updates) = q.acquire().await.into_parts();

        // The verdict has arrived. What it authorised has not run yet -- and on
        // a `pacman -Syu` it will not have run for another five minutes -- so
        // the lock goes back now, at the verdict, and the window that stays on
        // screen from here is a running indicator, not an approval.
        drop(permit);
        let command_still_running = true;

        let next = within(q.acquire()).await;

        assert!(command_still_running, "this test is about a lock released mid-command");
        assert_eq!(next.queue_depth(), 0);
    }

    #[tokio::test]
    async fn waiters_are_served_in_order() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();
        let (served_tx, mut served_rx) = mpsc::unbounded_channel();

        for i in 0..3usize {
            let served_tx = served_tx.clone();
            let _parked = park(&q, &mut depth, i + 1, move |admitted| {
                let _ = served_tx.send(i);
                drop(admitted);
            })
            .await;
        }
        drop(served_tx);

        drop(open);

        let mut served = Vec::new();
        while let Some(i) = within(served_rx.recv()).await {
            served.push(i);
        }
        assert_eq!(served, [0, 1, 2]);
    }

    #[tokio::test]
    async fn a_flood_of_arrivals_cannot_jump_the_oldest_waiter() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();
        let (served_tx, mut served_rx) = mpsc::unbounded_channel();

        // The spec accepts a flood rather than throttling one, so the question
        // FIFO has to answer is whether the first request through the door is
        // ever served at all once forty more pile up behind it.
        for i in 0..40usize {
            let served_tx = served_tx.clone();
            let _parked = park(&q, &mut depth, i + 1, move |admitted| {
                let _ = served_tx.send(i);
                drop(admitted);
            })
            .await;
        }
        drop(served_tx);

        drop(open);

        let mut served = Vec::new();
        while let Some(i) = within(served_rx.recv()).await {
            served.push(i);
        }
        assert_eq!(served, (0..40).collect::<Vec<_>>());
    }

    // ---- the badge ---------------------------------------------------------

    #[tokio::test]
    async fn depth_updates_are_broadcast_to_the_open_window() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        assert_eq!(open.queue_depth(), 0, "nothing had arrived when this window opened");

        let mut updates = q.subscribe();
        let waiter = tokio::spawn({
            let q = Arc::clone(&q);
            async move { q.acquire().await }
        });

        assert_eq!(within(updates.recv()).await.unwrap(), 1);

        drop(open);
        let admitted = within(waiter).await.unwrap();
        assert_eq!(admitted.queue_depth(), 0);
    }

    #[tokio::test]
    async fn the_badge_never_counts_the_window_it_is_drawn_in() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();
        let (badges_tx, mut badges_rx) = mpsc::unbounded_channel();

        for i in 0..2usize {
            let badges_tx = badges_tx.clone();
            let _parked = park(&q, &mut depth, i + 1, move |admitted| {
                let _ = badges_tx.send(admitted.queue_depth());
                drop(admitted);
            })
            .await;
        }
        drop(badges_tx);

        // Three requests exist and one of them is this window, so the number it
        // shows is two, not three.
        assert_eq!(open.queue_depth(), 0, "this window opened before either waiter arrived");
        assert_eq!(q.depth(), 2);
        drop(open);

        // Same again one turn later: the first waiter becomes the window, and
        // what it shows is the one still behind it.
        let mut badges = Vec::new();
        while let Some(badge) = within(badges_rx.recv()).await {
            badges.push(badge);
        }
        assert_eq!(badges, [1, 0]);
    }

    #[tokio::test]
    async fn a_waiter_that_goes_away_stops_being_counted() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();

        // An agent that disconnected, or a task the daemon gave up on.
        let waiter = park(&q, &mut depth, 1, drop).await;
        waiter.abort();
        let _ = waiter.await;

        assert_eq!(within(depth.recv()).await.unwrap(), 0, "leaving was not published");
        assert_eq!(q.depth(), 0, "a phantom waiter is left in the count");
        drop(open);
        assert_eq!(within(q.acquire()).await.queue_depth(), 0);
    }

    #[tokio::test]
    async fn a_waiter_whose_deadline_passes_stops_being_counted() {
        let q = ApprovalQueue::new();
        let open = q.acquire().await;
        let mut depth = q.subscribe();

        // The daemon's own shape for a queued request that ran out of time: the
        // `acquire` future is simply dropped where it stands.
        let timed_out = timeout(Duration::from_millis(50), q.acquire()).await;

        assert!(timed_out.is_err(), "the lock was free while it was held");
        assert_eq!(within(depth.recv()).await.unwrap(), 1);
        assert_eq!(within(depth.recv()).await.unwrap(), 0);
        assert_eq!(q.depth(), 0, "a phantom waiter is left in the count");
        drop(open);
    }

    #[tokio::test]
    async fn an_admitted_waiter_is_not_counted_out_twice() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();

        // Being admitted leaves the count, and so does being dropped. If both
        // ran, this waiter would take the arrival below down with it and the
        // badge would read zero with a window still queued.
        let (opened_tx, mut opened_rx) = mpsc::unbounded_channel();
        let first = park(&q, &mut depth, 1, move |admitted| {
            let _ = opened_tx.send(admitted);
        })
        .await;
        drop(open);
        within(first).await.unwrap();
        assert_eq!(within(depth.recv()).await.unwrap(), 0);
        let still_open = within(opened_rx.recv()).await.expect("the first waiter was admitted");

        let _second = park(&q, &mut depth, 1, drop).await;
        assert_eq!(q.depth(), 1, "leaving the count was counted more than once");
        drop(still_open);
    }

    #[test]
    fn an_unreachable_depth_saturates_rather_than_wrapping() {
        assert_eq!(badge(0), 0);
        assert_eq!(badge(3), 3);
        assert_eq!(badge(usize::MAX), u32::MAX, "a huge queue must not read as a small one");
    }

    #[tokio::test]
    async fn a_window_that_falls_behind_ends_on_the_current_depth() {
        let q = Arc::new(ApprovalQueue::new());
        let open = q.acquire().await;
        let mut depth = q.subscribe();

        // More arrivals than the channel holds, and a receiver that reads none
        // of them until they are all in. This is the lagging window, and the
        // claim being tested is the one the header makes: what it missed was
        // superseded, so reading on lands it on the truth.
        let mut waiters = Vec::new();
        for i in 0..DEPTH_UPDATES + 4 {
            let queued = Arc::clone(&q);
            waiters.push(tokio::spawn(async move { queued.acquire().await }));
            // Not `park`: the point of this test is a receiver that is not
            // being drained, so the arrivals are ordered by polling the queue's
            // own count instead. Under a ceiling, because a count that never
            // reaches the next arrival is exactly what several of this module's
            // mutants produce, and a spin with no ceiling is a hung suite.
            within(async {
                while q.depth() < i + 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await;
        }

        assert!(
            matches!(within(depth.recv()).await, Err(broadcast::error::RecvError::Lagged(_))),
            "this test needs a receiver that actually fell behind"
        );
        let mut last = None;
        while let Ok(seen) = depth.try_recv() {
            last = Some(seen);
        }
        assert_eq!(last, Some(q.depth()), "reading on did not land on the current depth");

        drop(open);
        for waiter in waiters {
            drop(within(waiter).await.unwrap());
        }
    }
}
