//! Typing guard.
//!
//! A prompt window appears while you are typing somewhere else. Wayland does
//! not let a client raise or focus itself, so hatch cannot promise the window
//! is on top, and it cannot promise the compositor did not just hand it your
//! keyboard. What it can promise is that the keystroke already in flight when
//! the window arrived does not decide anything.
//!
//! That promise is this module, and it is the only thing between a stray
//! Enter and a root command running on the machine.
//!
//! # The rule
//!
//! For [`GUARD`] after the window becomes able to receive input, every event
//! is inert. Not deferred — inert. An event that arrives while the guard is
//! closed is dropped where it is judged and is never delivered to anything,
//! then or later. [`Guard::pending_count`] exists so a test can say so out
//! loud: there is no queue to drain, and adding one would undo the module.
//!
//! # What starts the clock
//!
//! The window is created shut, not opened by a focus event that may never
//! arrive: on Wayland a client cannot focus itself, and a guard waiting for
//! news it may never get is not a guard. From there:
//!
//! * **Focus is gained** — the clock restarts at that instant, and [`GUARD`]
//!   later the window is live. This is the dangerous moment, not the
//!   window's creation: the click that granted focus, and the keys already
//!   travelling towards whatever held it before, all land now.
//! * **Focus is known to be absent** — the compositor never gave the window
//!   the keyboard, or took it away. The window then opens
//!   [`UNFOCUSED_GRACE`] after it was *created*, which is deliberately much
//!   longer: when hatch cannot tell whether a human is looking at it, that
//!   deserves more caution, not less. It is a floor, not a licence — it
//!   exists only so that a window nothing ever focuses is slow rather than
//!   dead, because a window that can never be operated cannot be denied
//!   either.
//!
//! So neither failure mode is open: a window that is never focused is
//! guarded for four times as long as one that is, and no window is guarded
//! forever.
//!
//! # One door
//!
//! [`Guard::classify`] is the only path from an input event to an action. The
//! egui layer does not read keys; it hands every event of the frame to
//! [`intercept`], which classifies each one and puts back into egui's own
//! queue only what the guard is willing for a widget to see. So the code the
//! tests below exercise is the code that ships, and there is no second path
//! that ships untested.
//!
//! Three things have to be true for that to hold, and all three are here:
//!
//! * **Enter and Escape are the guard's alone.** They are taken out of the
//!   frame whether or not the guard is open, so egui's "Space or Enter
//!   activates the focused widget" handling can never see one. What they
//!   mean is judged exactly: approving is Enter with *either* Control or
//!   Shift and nothing else at all, denying is Escape with nothing at all.
//!   Not a contains-check — Ctrl+Shift+Enter is neither of the two chords and
//!   is not what anybody meant by "approve", and someone part-way into a
//!   chord in another window must not find that half of it decided this one.
//! * **The two boxes have chords too, judged in the same place.** Alt+S and
//!   Alt+C flip "stream output to this window" and "close when I decide" —
//!   see [`toggle_chord`], which also says why something that decides nothing
//!   still waits the whole guard. They are chords rather than bare letters
//!   because the note field holds the text focus, and the letters themselves
//!   are left alone: what is taken out of the frame is `Alt+S`, never `s`.
//! * **The verdict buttons are not focusable.** egui only fakes a click on a
//!   focused widget, so a button that never holds focus cannot be activated
//!   by Space either — which is the hole that stripping Enter alone leaves
//!   open. See `verdict_buttons` in the parent module.
//! * **While the guard is closed the frame is emptied and the buttons are
//!   disabled.** egui computes pointer clicks before the frame's events reach
//!   us, so emptying the queue does not stop a mouse; a disabled widget
//!   reports neither a real click nor a fake one.
//!
//! # Once, not maybe
//!
//! An [`Action`] is a decision, not a suggestion. [`intercept`] *takes* the
//! events rather than reading them, so an event is judged exactly once even
//! if egui runs a second pass over the same frame, and a physical keypress
//! reaches egui once. Behind that, [`crate::prompt_ui::PromptState::decide`]
//! answers only while the window is awaiting a verdict and leaves that phase
//! on the way out, so even a doubled action costs one frame on the wire.

use std::time::{Duration, Instant};

use eframe::egui::{self, Key, Modifiers};

/// How long input is inert after the window becomes able to receive it.
///
/// Deliberately a constant and not a config key. This is a safety property,
/// and a setting is an invitation to set it to zero — by a user in a hurry,
/// by an agent that can write the config file, or by whoever inherits both.
/// 750 ms is longer than the tail of a keystroke burst and shorter than the
/// time it takes to read what the window is asking. Public so that the number
/// is visible in the documentation; visible is not the same as adjustable.
pub const GUARD: Duration = Duration::from_millis(750);

/// How long a window the compositor never focused stays shut.
///
/// A constant for the same reason [`GUARD`] is, and four times as long on
/// purpose. This is the case where hatch does not know whether anyone is
/// looking at the window, so it is the case that deserves the most patience;
/// it is here only so that such a window eventually becomes operable rather
/// than being a dialog nobody can answer or dismiss.
pub const UNFOCUSED_GRACE: Duration = Duration::from_secs(3);

/// What the Approve button says the keyboard shortcuts are.
///
/// Here rather than beside the button, because a shortcut nobody can see is a
/// shortcut nobody has, and a shortcut printed loosely is worse than none: a
/// reader who is told "Ctrl+Enter" and finds that Ctrl+Shift+Enter works too
/// has learned that the window is approximate about what it accepts. It is
/// not. [`is_approve_chord`] takes Control *or* Shift and refuses every other
/// modifier held with either, and this string names exactly that and nothing
/// else.
///
/// # Why both are printed, on two lines
///
/// There are two chords and one button, so the label either names both or
/// hides one. It names both: a shortcut that works and is not written down is
/// exactly the state this label was added to end, and adding a second
/// undocumented one would be undoing that while claiming to extend it.
///
/// One line was tried first and does not fit. The hint may not widen the
/// button — the two buttons that decide are centred in a rect measured from
/// the button minimum, and a hint that outgrew it would move them.
/// `Ctrl/Shift+Enter` overflows
/// that minimum at the smaller font sizes a reader may configure, and the
/// alternatives that do fit on one line are abbreviations — a `⇧` or a `↵`,
/// which is a glyph gamble and a puzzle in a window whose whole job is to be
/// unambiguous. Two short lines fit at every size, spell both chords out, and
/// use the height the button already has and was not using.
///
/// So the label is a chord per line. That it still fits the button the window
/// already had is `the_shortcut_hints_fit_the_buttons_that_were_already_there`;
/// `the_buttons_name_exactly_the_chords_the_guard_takes` reads it the way a
/// user does — both lines — and holds the rule to it, so the two cannot drift
/// apart.
pub const APPROVE_CHORD: &str = "Ctrl+Enter\nShift+Enter";

/// What the Deny button says the keyboard shortcut is.
///
/// Bare, and the label says so by naming no modifier at all: Escape with
/// anything held is [`Action::Ignored`]. Pinned to the rule alongside
/// [`APPROVE_CHORD`].
pub const DENY_CHORD: &str = "Esc";

/// What toggles "stream output to this window".
///
/// A modifier chord and not a bare letter, because the note field has the
/// text focus and a window where `s` means something other than the letter
/// `s` is a window that eats what you type into it. Alt, because Ctrl+S and
/// Ctrl+C are already two of the most reflexive chords on a keyboard and
/// neither of them means this.
pub const STREAM_CHORD: &str = "Alt+S";

/// What toggles "close when I decide". Alt, for [`STREAM_CHORD`]'s reasons.
pub const CLOSE_CHORD: &str = "Alt+C";

/// What the window should do about one input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing. The event is dropped here: no widget sees it, and nothing
    /// delivers it later.
    Ignored,
    /// Not the guard's business. Hand it back to the widgets.
    Passthrough,
    /// A human asked to approve.
    Approve,
    /// A human asked to deny.
    Deny,
    /// A human asked to flip one of the boxes. Decides nothing by itself.
    Toggle(Toggle),
}

/// Which of the window's boxes a chord flips.
///
/// Only two of the three. The terminal box has no chord, and that absence is
/// a decision: it is the one control on this window that changes how the
/// command *executes* rather than what the reader sees, and a control like
/// that should cost a deliberate click rather than two keys pressed together.
/// See `crate::prefs::Prefs`, which sets out the same difference for the
/// preference the box writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    /// "Stream output to this window".
    Stream,
    /// "Close when I decide".
    Close,
}

/// The window's guard against input it did not mean.
///
/// Every method takes the instant to judge by, so the whole of this module is
/// tested without sleeping and without a display.
#[derive(Debug)]
pub struct Guard {
    /// When the window was made. The one instant that is always known, and
    /// what [`UNFOCUSED_GRACE`] is measured from.
    created_at: Instant,
    /// When the window was last told it can receive input, or `None` once it
    /// has been told it cannot. `None` is not "shut forever" — it is
    /// "governed by the grace period instead".
    armed_at: Option<Instant>,
}

impl Guard {
    /// A guard for a window that has just been created: shut, and counting.
    ///
    /// The clock starts here rather than at a focus event, because a window
    /// can be given focus before it has drawn a frame and a guard waiting for
    /// news it may already have missed is not a guard. What the window is
    /// then told overrides this: focus gained restarts the clock, and focus
    /// known to be absent hands the window to [`UNFOCUSED_GRACE`]. Since the
    /// integration reports focus every frame — see [`intercept`] — this
    /// starting assumption only governs the first frame or two.
    pub fn new(now: Instant) -> Guard {
        Guard { created_at: now, armed_at: Some(now) }
    }

    /// The window can receive input again. Restart the clock.
    ///
    /// This is the dangerous instant, not the window's creation: the click
    /// that gave the window focus, and the keys that were already travelling
    /// towards whatever had it before, land now.
    pub fn focus_gained(&mut self, now: Instant) {
        self.armed_at = Some(now);
    }

    /// The window cannot receive input, and hatch has been told so.
    ///
    /// `now` is taken for symmetry and ignored on purpose: what governs an
    /// unfocused window is [`UNFOCUSED_GRACE`] from when it was created, not
    /// a period starting at the loss. Recording the loss instant would let a
    /// window that flickers out of focus restart its own long timer over and
    /// over and never open.
    pub fn focus_lost(&mut self, _now: Instant) {
        self.armed_at = None;
    }

    /// Whether input is being acted on yet.
    ///
    /// The boundary belongs to the closed side: at exactly the guard's length
    /// the window is still shut. Ties go to the safe answer.
    pub fn is_open(&self, now: Instant) -> bool {
        match self.armed_at {
            Some(armed) => now.duration_since(armed) > GUARD,
            None => now.duration_since(self.created_at) > UNFOCUSED_GRACE,
        }
    }

    /// Whether the guard currently believes the window holds focus.
    ///
    /// For reconciling with what the window actually is; a focus change is
    /// only acted on when it is a change, so that a compositor repeating
    /// itself every frame cannot restart the clock every frame and leave the
    /// window shut for as long as it is looked at.
    fn believes_focused(&self) -> bool {
        self.armed_at.is_some()
    }

    /// How many events the guard is holding to deliver later.
    ///
    /// Always zero, and that is the point. A guard that buffered would turn
    /// the burst you typed at another window into a verdict 750 ms later,
    /// which is the accident it exists to prevent. This is here so a test can
    /// assert the absence of the buffer, and so that anyone tempted to add
    /// one has to delete a documented promise first.
    pub fn pending_count(&self) -> usize {
        0
    }

    /// Decide what one event means. The only path from input to action.
    ///
    /// `modifiers` is the state to judge the chord by; the caller passes the
    /// event's own modifiers for a key press, which is the same source egui
    /// matches its own shortcuts against.
    pub fn classify(&self, event: &egui::Event, modifiers: Modifiers, now: Instant) -> Action {
        let open = self.is_open(now);
        let key = match event {
            // Key repeats included: a held-down key is exactly the thing this
            // guard exists to ignore.
            egui::Event::Key { key, pressed: true, .. } => Some(*key),
            _ => None,
        };
        match key {
            // Never a passthrough, open or closed. If Enter reached a widget,
            // egui would activate whatever holds focus with it, and the guard
            // would be advice rather than a rule.
            Some(Key::Enter) => {
                if open && is_approve_chord(modifiers) {
                    Action::Approve
                } else {
                    Action::Ignored
                }
            }
            Some(Key::Escape) => {
                if open && modifiers.is_none() {
                    Action::Deny
                } else {
                    Action::Ignored
                }
            }
            // The two boxes. Judged on the same clock as the two verdicts and
            // by the same kind of exact chord match — see [`toggle_chord`] for
            // why a control that decides nothing still waits the full guard.
            Some(key) if toggle_chord(key, modifiers).is_some() => {
                match (open, toggle_chord(key, modifiers)) {
                    (true, Some(toggle)) => Action::Toggle(toggle),
                    _ => Action::Ignored,
                }
            }
            // Everything else — other keys, and every pointer event, which is
            // in flight in just the same way when someone is double-clicking
            // in another window.
            _ => {
                if open {
                    Action::Passthrough
                } else {
                    Action::Ignored
                }
            }
        }
    }
}

/// Is this one of the two deliberate approval chords?
///
/// Control *or* Shift, and in each case nothing else. Exact, not a
/// contains-check: `Ctrl+Shift+Enter` and `Ctrl+Alt+Enter` are not approvals,
/// because "either of two chords" is a list of two and not a licence to hold
/// whatever else is under the hand.
///
/// # Why Shift as well
///
/// Ctrl+Enter was the whole rule and is the better chord on paper; Shift is
/// the one a right hand reaches without leaving the arrow keys, on more
/// keyboards, and the person answering these windows is usually holding
/// something else. Two chords for one meaning is a cost — it is one more
/// thing the label has to say, and one more combination in flight that can
/// land here — and it is paid because approving with one hand is the ordinary
/// case and refusing to support it sends people to the mouse.
///
/// Shift+Enter is a more *reachable* chord than Ctrl+Enter and therefore a
/// more *likely* one to be mid-flight when this window appears: it is how
/// half the chat clients on the machine start a new line. Nothing in this
/// function guards against that and nothing in it should. What does is the
/// clock above it — [`GUARD`] from the instant the window could receive
/// input — which does not care which chord was in the air.
///
/// `ctrl`, `command` and `mac_cmd` are three spellings of one modifier and
/// not three modifiers — a Linux backend sets `ctrl` and `command` together
/// for a single key — so any of them counts as Control being held, and the
/// exactness that matters is that nothing else is.
fn is_approve_chord(m: Modifiers) -> bool {
    let control = m.ctrl || m.command || m.mac_cmd;
    (control && !m.alt && !m.shift) || (m.shift && !m.alt && !control)
}

/// Which box, if any, this key and these modifiers flip.
///
/// Alt held, and nothing else: the same exactness [`is_approve_chord`] applies,
/// for the same reason. `Ctrl+Alt+S` is a compositor's chord on half the
/// desktops there are and `Alt+Shift+S` is somebody part-way through a
/// different one, and a window that took both would be a window that acts on
/// chords aimed elsewhere.
///
/// # Why a control that decides nothing still waits the whole guard
///
/// It is tempting to let a box be flipped sooner than a command may be run:
/// a tick is visible, it is one click to undo, and nothing happens because of
/// it until a verdict is given afterwards. That argument is about the box.
/// What these two chords write is not the box — it is `prefs.toml`, which
/// outlives this window and is read by every window after it. The undo for
/// the box is on screen; the undo for the file is a checkbox in a request
/// that has not been made yet, which nobody knows to look for. So the burst
/// of keystrokes that arrives as the window appears — the one thing this
/// module exists to stop — must not reach these either, and they wait exactly
/// as long as Approve does, on both clocks.
///
/// The leniency a toggle does get is at the other end, and it is the state
/// machine's rather than the guard's: [`crate::prompt_ui::PromptState::decide`]
/// spends a window's one and only verdict, so a doubled Approve has to be
/// made harmless. A doubled toggle is its own undo. Nothing here needs the
/// "once, not maybe" machinery, and nothing here is a decision that outruns
/// the person who made it.
fn toggle_chord(key: Key, m: Modifiers) -> Option<Toggle> {
    let control = m.ctrl || m.command || m.mac_cmd;
    if !m.alt || m.shift || control {
        return None;
    }
    match key {
        Key::S => Some(Toggle::Stream),
        Key::C => Some(Toggle::Close),
        _ => None,
    }
}

/// Run every event of this frame past the guard, and leave in egui's queue
/// only what a widget may see.
///
/// The events are taken, not read. An event the guard has judged is gone from
/// the frame, so nothing can act on it afterwards and a second pass over the
/// same frame cannot judge it twice.
///
/// Returns the decisions, in the order they were made.
pub fn intercept(guard: &mut Guard, ctx: &egui::Context, now: Instant) -> Vec<Action> {
    // What the window actually is, rather than only what it was told. This
    // is how a window the compositor never focuses learns that it is
    // unfocused at all — and so gets the longer grace rather than the short
    // guard — and it is what heals a focus event that never arrived. Acted
    // on only when it is a change, because a compositor repeating itself
    // every frame must not restart the clock every frame.
    match ctx.input(|i| i.viewport().focused) {
        Some(true) if !guard.believes_focused() => guard.focus_gained(now),
        Some(false) if guard.believes_focused() => guard.focus_lost(now),
        _ => {}
    }

    let (events, frame_modifiers) =
        ctx.input_mut(|i| (std::mem::take(&mut i.events), i.modifiers));

    let mut actions = Vec::new();
    let mut kept = Vec::with_capacity(events.len());
    for event in events {
        // Focus first, so the event that restarts the clock does so before
        // the guard judges the keys that arrived with it. Kept, because it is
        // egui's news as much as ours.
        if let egui::Event::WindowFocused(focused) = event {
            if focused {
                guard.focus_gained(now);
            } else {
                guard.focus_lost(now);
            }
            kept.push(event);
            continue;
        }
        let modifiers = match &event {
            egui::Event::Key { modifiers, .. } => *modifiers,
            _ => frame_modifiers,
        };
        match guard.classify(&event, modifiers, now) {
            Action::Passthrough => kept.push(event),
            Action::Ignored => {}
            decided => actions.push(decided),
        }
    }
    ctx.input_mut(|i| i.events = kept);
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock the test drives by hand, so nothing here sleeps.
    struct Clock(Instant);

    impl Clock {
        fn new() -> Clock {
            Clock(Instant::now())
        }

        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    fn press(key: Key, modifiers: Modifiers) -> egui::Event {
        egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
    }

    #[test]
    fn input_is_inert_before_the_guard_expires() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(749)), Action::Ignored);
    }

    #[test]
    fn input_is_accepted_after_the_guard_expires() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(751)), Action::Approve);
    }

    #[test]
    fn a_burst_during_the_guard_is_ignored_and_never_arrives_late() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let event = press(Key::Enter, Modifiers::CTRL);
        for _ in 0..20 {
            assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(100)), Action::Ignored);
        }
        assert_eq!(guard.pending_count(), 0);
    }

    #[test]
    fn the_guard_restarts_when_focus_is_regained() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        guard.focus_lost(clock.at(1000));
        guard.focus_gained(clock.at(2000));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2100)), Action::Ignored);
    }

    #[test]
    fn plain_enter_never_activates_approve_even_after_the_guard() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let plain = press(Key::Enter, Modifiers::NONE);
        assert_eq!(guard.classify(&plain, Modifiers::NONE, clock.at(5000)), Action::Ignored);
        let chord = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&chord, Modifiers::CTRL, clock.at(5000)), Action::Approve);
    }

    #[test]
    fn escape_during_the_guard_does_not_deny() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let event = press(Key::Escape, Modifiers::NONE);
        assert_eq!(guard.classify(&event, Modifiers::NONE, clock.at(100)), Action::Ignored);
    }

    #[test]
    fn escape_after_the_guard_denies() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let event = press(Key::Escape, Modifiers::NONE);
        assert_eq!(guard.classify(&event, Modifiers::NONE, clock.at(800)), Action::Deny);
    }

    // ---- the two ways a focus rule fails --------------------------------

    #[test]
    fn focus_returning_opens_the_window_again_rather_than_shutting_it_forever() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        guard.focus_lost(clock.at(1000));
        guard.focus_gained(clock.at(2000));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2800)), Action::Approve);
    }

    #[test]
    fn a_window_the_compositor_never_focuses_waits_longer_but_not_forever() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        // The compositor's answer to "am I taking the keyboard": no.
        guard.focus_lost(clock.at(0));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2900)), Action::Ignored);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(3100)), Action::Approve);
    }

    #[test]
    fn a_window_that_is_given_focus_waits_the_ordinary_guard_from_that_moment() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        guard.focus_gained(clock.at(1000));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(1500)), Action::Ignored);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(1800)), Action::Approve);
    }

    #[test]
    fn losing_focus_is_governed_by_the_grace_period_not_by_a_fresh_short_guard() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        guard.focus_lost(clock.at(1000));
        let event = press(Key::Enter, Modifiers::CTRL);
        // 750 ms after the loss, and still shut: the loss started nothing.
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(1800)), Action::Ignored);
        // And still shut right up to the grace, which runs from creation.
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2900)), Action::Ignored);
    }

    #[test]
    fn the_moment_the_guard_expires_still_belongs_to_the_closed_side() {
        let clock = Clock::new();
        let mut shut = Guard::new(clock.at(0));
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(shut.classify(&event, Modifiers::CTRL, clock.at(750)), Action::Ignored);
        shut.focus_lost(clock.at(0));
        assert_eq!(shut.classify(&event, Modifiers::CTRL, clock.at(3000)), Action::Ignored);
    }

    // ---- exactly one way to say each thing -------------------------------

    /// Every combination of the modifier keys egui models.
    ///
    /// Built by naming each field, so a modifier added to egui breaks this
    /// build rather than quietly slipping past an untested case.
    fn every_modifier_combination() -> Vec<Modifiers> {
        (0..32u8)
            .map(|bits| Modifiers {
                alt: bits & 1 != 0,
                ctrl: bits & 2 != 0,
                shift: bits & 4 != 0,
                mac_cmd: bits & 8 != 0,
                command: bits & 16 != 0,
            })
            .collect()
    }

    #[test]
    fn enter_approves_under_control_or_under_shift_and_under_nothing_else() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);

        let approving: Vec<Modifiers> = every_modifier_combination()
            .into_iter()
            .filter(|m| guard.classify(&press(Key::Enter, *m), *m, now) == Action::Approve)
            .collect();

        assert!(!approving.is_empty(), "there is no way to approve at all");
        for m in &approving {
            let control = m.ctrl || m.command || m.mac_cmd;
            assert!(control || m.shift, "{m:?} approved holding neither Control nor Shift");
            assert!(!m.alt, "{m:?} approved with Alt held");
            assert!(!(control && m.shift), "{m:?} approved holding both halves of two chords");
        }

        // Control has three spellings and a backend may send any of them; all
        // three are Control alone, and all three must work. Shift has one.
        for m in [Modifiers::CTRL, Modifiers::COMMAND, Modifiers::MAC_CMD, Modifiers::SHIFT] {
            assert!(approving.contains(&m), "{m:?} is one chord held alone and did not approve");
        }

        // The near misses, spelled out so the intent survives a rewrite.
        // Ctrl+Shift is the one two chords make tempting and is still inert:
        // two halves of two different chords are not a third chord.
        for m in [
            Modifiers::NONE,
            Modifiers::ALT,
            Modifiers::CTRL | Modifiers::SHIFT,
            Modifiers::CTRL | Modifiers::ALT,
            Modifiers::SHIFT | Modifiers::ALT,
        ] {
            assert_eq!(
                guard.classify(&press(Key::Enter, m), m, now),
                Action::Ignored,
                "Enter with {m:?}"
            );
        }
    }

    // ---- the two boxes ---------------------------------------------------

    #[test]
    fn the_box_chords_are_inert_for_exactly_as_long_as_a_verdict_is() {
        // The whole of the leniency question, asserted rather than argued:
        // what these write persists, so the burst that cannot approve cannot
        // tick either — on the short clock and on the long one.
        let clock = Clock::new();
        for (key, toggle) in [(Key::S, Toggle::Stream), (Key::C, Toggle::Close)] {
            let event = press(key, Modifiers::ALT);
            let focused = Guard::new(clock.at(0));
            assert_eq!(focused.classify(&event, Modifiers::ALT, clock.at(749)), Action::Ignored);
            assert_eq!(
                focused.classify(&event, Modifiers::ALT, clock.at(751)),
                Action::Toggle(toggle)
            );

            let mut unfocused = Guard::new(clock.at(0));
            unfocused.focus_lost(clock.at(0));
            assert_eq!(
                unfocused.classify(&event, Modifiers::ALT, clock.at(2900)),
                Action::Ignored,
                "a window nobody is looking at ticked a box that outlives it"
            );
            assert_eq!(
                unfocused.classify(&event, Modifiers::ALT, clock.at(3100)),
                Action::Toggle(toggle)
            );
        }
    }

    #[test]
    fn the_letters_the_chords_are_built_from_are_still_letters() {
        // The note field has the text focus. A window in which `s` means
        // something other than the letter `s` is a window that eats what you
        // type into it, which is why these are chords at all.
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);
        for key in [Key::S, Key::C] {
            let bare = press(key, Modifiers::NONE);
            assert_eq!(guard.classify(&bare, Modifiers::NONE, now), Action::Passthrough);
            let shifted = press(key, Modifiers::SHIFT);
            assert_eq!(guard.classify(&shifted, Modifiers::SHIFT, now), Action::Passthrough);
        }
        // And the text itself, which is a different event and never the
        // guard's business at all.
        let typed = egui::Event::Text("sc".to_string());
        assert_eq!(guard.classify(&typed, Modifiers::NONE, now), Action::Passthrough);
    }

    #[test]
    fn only_alt_and_the_letter_flips_a_box() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);
        for m in [
            Modifiers::CTRL | Modifiers::ALT,
            Modifiers::SHIFT | Modifiers::ALT,
            Modifiers::COMMAND | Modifiers::ALT,
            Modifiers::MAC_CMD | Modifiers::ALT,
            Modifiers::CTRL,
            Modifiers::NONE,
        ] {
            for key in [Key::S, Key::C] {
                assert_eq!(
                    guard.classify(&press(key, m), m, now),
                    Action::Passthrough,
                    "{key:?} with {m:?} flipped a box",
                );
            }
        }
    }

    #[test]
    fn a_box_chord_is_never_left_in_the_frame_for_a_widget() {
        // It is acted on, so it is gone; the same rule Enter and Escape keep.
        // A chord that both ticked a box and reached a widget would be one
        // keypress doing two things.
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let events = vec![press(Key::S, Modifiers::ALT), press(Key::C, Modifiers::ALT)];
        let (actions, left, _) = one_frame(&mut guard, clock.at(5000), events);
        assert_eq!(actions, vec![Action::Toggle(Toggle::Stream), Action::Toggle(Toggle::Close)]);
        assert!(left.is_empty(), "{left:?}");
    }

    /// The chords a label names, read the way a user reads it.
    ///
    /// A parser and not a table on purpose: what has to be checked is the
    /// string that reaches the screen, so a label that grew a modifier, lost
    /// one, or started naming a key this window does not act on fails here
    /// rather than becoming a promise nothing keeps. `Ctrl` is Control in the
    /// one spelling the label uses; the three spellings the backends send are
    /// the rule's business and are covered below.
    ///
    /// A label is one chord per line, so this returns one [`Modifiers`] per
    /// line: a label naming one chord gives a list of one, and the same rule
    /// covers both kinds of label. Every line has to name the same key, which
    /// is checked here rather than assumed — a button whose two lines named
    /// two different keys would be two promises pretending to be one.
    fn named(label: &str) -> (Key, Vec<Modifiers>) {
        let mut key: Option<Key> = None;
        let mut chords = Vec::new();
        for line in label.lines() {
            let mut wanted = Modifiers::NONE;
            let mut parts = line.split('+').peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    let named = match part {
                        "Enter" => Key::Enter,
                        "Esc" => Key::Escape,
                        "S" => Key::S,
                        "C" => Key::C,
                        other => panic!("{label:?} names a key this test cannot read: {other:?}"),
                    };
                    assert_eq!(*key.get_or_insert(named), named, "{label:?} names two keys");
                    break;
                }
                match part {
                    "Ctrl" => wanted.ctrl = true,
                    "Shift" => wanted.shift = true,
                    "Alt" => wanted.alt = true,
                    other => {
                        panic!("{label:?} names a modifier this test cannot read: {other:?}")
                    }
                }
            }
            chords.push(wanted);
        }
        (key.expect("a label names a key"), chords)
    }

    #[test]
    fn the_buttons_name_exactly_the_chords_the_guard_takes() {
        // The labels and the rule, held together. A user who reads
        // "Ctrl+Enter" and "Shift+Enter" off the button expects each of them
        // to approve and expects nothing else to — so every one of the
        // modifier combinations the label does not name has to be refused,
        // including Ctrl+Shift+Enter, which is deliberately inert and which a
        // looser label would be quietly promising.
        //
        // The two box chords are held to the same rule, because they are
        // written down in the same way — on the control they flip — and a
        // hint that named a chord the guard refuses would be no better there
        // than it is on Approve.
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);

        for (label, decides) in [
            (APPROVE_CHORD, Action::Approve),
            (DENY_CHORD, Action::Deny),
            (STREAM_CHORD, Action::Toggle(Toggle::Stream)),
            (CLOSE_CHORD, Action::Toggle(Toggle::Close)),
        ] {
            let (key, alternatives) = named(label);
            for m in every_modifier_combination() {
                // Control has three spellings and a backend may send any of
                // them; they are one modifier, and the label spells it once.
                let control = m.ctrl || m.command || m.mac_cmd;
                let is_named = alternatives.iter().any(|wanted| {
                    control == wanted.ctrl && m.shift == wanted.shift && m.alt == wanted.alt
                });
                assert_eq!(
                    guard.classify(&press(key, m), m, now) == decides,
                    is_named,
                    "{label:?} and the guard disagree about {m:?}"
                );
            }
        }
    }

    #[test]
    fn a_label_with_two_chords_in_it_is_read_as_two_and_not_as_one() {
        // The parser above is the whole of what holds the labels to the rule,
        // so a parser that quietly read a two-line label as one chord with
        // both modifiers held would agree with any rule at all.
        let (key, chords) = named("Ctrl+Enter\nShift+Enter");
        assert_eq!(key, Key::Enter);
        assert_eq!(chords, vec![Modifiers::CTRL, Modifiers::SHIFT]);
        assert_eq!(named("Alt+S").1, vec![Modifiers::ALT]);
    }

    #[test]
    fn only_a_bare_escape_denies() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);

        let denying: Vec<Modifiers> = every_modifier_combination()
            .into_iter()
            .filter(|m| guard.classify(&press(Key::Escape, *m), *m, now) == Action::Deny)
            .collect();

        // A denial nobody chose still spends the one decision this window has.
        assert_eq!(denying, vec![Modifiers::NONE]);
    }

    // ---- what else is in flight -----------------------------------------

    #[test]
    fn the_guard_covers_the_mouse_as_well_as_the_keyboard() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let click = egui::Event::PointerButton {
            pos: egui::pos2(10.0, 10.0),
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: Modifiers::NONE,
        };
        assert_eq!(guard.classify(&click, Modifiers::NONE, clock.at(100)), Action::Ignored);
        assert_eq!(guard.classify(&click, Modifiers::NONE, clock.at(800)), Action::Passthrough);
    }

    #[test]
    fn nearly_the_chord_is_not_the_chord() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        for m in [
            Modifiers::CTRL | Modifiers::ALT,
            Modifiers::CTRL | Modifiers::SHIFT,
            Modifiers::SHIFT | Modifiers::ALT,
            Modifiers::ALT,
        ] {
            let event = press(Key::Enter, m);
            assert_eq!(guard.classify(&event, m, clock.at(5000)), Action::Ignored, "{m:?}");
        }
    }

    #[test]
    fn letting_go_of_the_chord_is_not_a_second_approval() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let release = egui::Event::Key {
            key: Key::Enter,
            physical_key: None,
            pressed: false,
            repeat: false,
            modifiers: Modifiers::CTRL,
        };
        assert_eq!(guard.classify(&release, Modifiers::CTRL, clock.at(5000)), Action::Passthrough);
    }

    // ---- the wiring, against a real egui context -------------------------
    //
    // No display is needed for any of this: egui's own input handling is what
    // is under test, so these run wherever the unit tests run.

    /// Finish a pass and throw away what a real integration would upload.
    fn end_pass(ctx: &egui::Context) {
        // epaint refuses to be dropped holding texture deltas nobody applied.
        ctx.end_pass().textures_delta.clear();
    }

    /// Hand `events` to a real egui frame, run [`intercept`] where the app
    /// runs it, and report what came out and what egui was left holding.
    fn one_frame(
        guard: &mut Guard,
        now: Instant,
        events: Vec<egui::Event>,
    ) -> (Vec<Action>, Vec<egui::Event>, bool) {
        let ctx = egui::Context::default();
        ctx.begin_pass(egui::RawInput { events, ..Default::default() });
        let actions = intercept(guard, &ctx, now);
        let left = ctx.input(|i| i.events.clone());
        // egui's own "Space or Enter activates the focused widget" test.
        let would_activate = ctx.input(|i| i.key_pressed(Key::Enter) || i.key_pressed(Key::Space));
        end_pass(&ctx);
        (actions, left, would_activate)
    }

    #[test]
    fn a_burst_the_guard_shut_out_is_not_left_in_eguis_queue_for_a_widget() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let burst = vec![press(Key::Enter, Modifiers::CTRL); 20];
        let (actions, left, would_activate) = one_frame(&mut guard, clock.at(100), burst);
        assert!(actions.is_empty(), "{actions:?}");
        assert!(left.is_empty(), "{left:?}");
        assert!(!would_activate, "egui would still have activated a focused widget");
    }

    #[test]
    fn enter_is_taken_out_of_the_frame_even_once_the_guard_is_open() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let events = vec![press(Key::Enter, Modifiers::NONE)];
        let (actions, left, would_activate) = one_frame(&mut guard, clock.at(5000), events);
        assert!(actions.is_empty(), "{actions:?}");
        assert!(left.is_empty(), "{left:?}");
        assert!(!would_activate, "a plain Enter could still activate a focused widget");
    }

    #[test]
    fn ordinary_typing_still_reaches_the_widgets_once_the_guard_is_open() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let typed = vec![egui::Event::Text("no thanks".to_string())];
        let (actions, left, _) = one_frame(&mut guard, clock.at(5000), typed.clone());
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!(left, typed, "the note field would never see a keystroke");
    }

    #[test]
    fn the_frame_that_hands_the_window_focus_shuts_the_guard_before_it_judges_the_burst() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let arriving =
            vec![egui::Event::WindowFocused(true), press(Key::Enter, Modifiers::CTRL)];
        let (actions, _, _) = one_frame(&mut guard, clock.at(5000), arriving);
        assert!(actions.is_empty(), "focus arrived with the keystroke and did not stop it");
    }

    #[test]
    fn one_keypress_is_judged_once_however_many_passes_the_frame_takes() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let ctx = egui::Context::default();
        ctx.begin_pass(egui::RawInput {
            events: vec![press(Key::Enter, Modifiers::CTRL)],
            ..Default::default()
        });
        let first = intercept(&mut guard, &ctx, clock.at(5000));
        let second = intercept(&mut guard, &ctx, clock.at(5000));
        end_pass(&ctx);
        assert_eq!(first, vec![Action::Approve]);
        assert!(second.is_empty(), "the same keypress was judged twice: {second:?}");
    }

    #[test]
    fn a_window_the_compositor_says_is_unfocused_acts_on_nothing() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        let ctx = egui::Context::default();
        let mut raw = egui::RawInput {
            events: vec![press(Key::Enter, Modifiers::CTRL)],
            ..Default::default()
        };
        raw.viewports.get_mut(&raw.viewport_id).expect("root viewport").focused = Some(false);
        ctx.begin_pass(raw);
        // Well past the ordinary guard, well inside the unfocused grace.
        let actions = intercept(&mut guard, &ctx, clock.at(2000));
        end_pass(&ctx);
        assert!(actions.is_empty(), "{actions:?}");
    }

    #[test]
    fn a_compositor_saying_focused_every_frame_does_not_restart_the_clock() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        // Every frame reports the same thing, because that is what a viewport
        // does. Nothing has changed, so nothing may restart the guard: a
        // clock reset once a frame is a clock that never runs out, and a
        // window whose buttons never enable cannot be denied either.
        for ms in [100, 300, 500, 700, 900] {
            let ctx = egui::Context::default();
            let mut raw = egui::RawInput::default();
            raw.viewports.get_mut(&raw.viewport_id).expect("root viewport").focused = Some(true);
            ctx.begin_pass(raw);
            intercept(&mut guard, &ctx, clock.at(ms));
            end_pass(&ctx);
        }
        let event = press(Key::Enter, Modifiers::CTRL);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(900)), Action::Approve);
    }

    #[test]
    fn a_focus_change_the_compositor_never_announced_still_reaches_the_guard() {
        let clock = Clock::new();
        let mut guard = Guard::new(clock.at(0));
        // Focus was lost and the event never arrived; only the viewport says so.
        guard.focus_lost(clock.at(1000));
        let ctx = egui::Context::default();
        let mut raw = egui::RawInput::default();
        raw.viewports.get_mut(&raw.viewport_id).expect("root viewport").focused = Some(true);
        ctx.begin_pass(raw);
        intercept(&mut guard, &ctx, clock.at(2000));
        end_pass(&ctx);
        let event = press(Key::Enter, Modifiers::CTRL);
        // Re-armed at 2000: shut just after, open well after. Never stuck shut.
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2100)), Action::Ignored);
        assert_eq!(guard.classify(&event, Modifiers::CTRL, clock.at(2800)), Action::Approve);
    }
}
