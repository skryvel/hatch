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
//!   mean is judged exactly: approving is Ctrl and Enter with no other
//!   modifier held, denying is Escape with none at all. Not a contains-check
//!   — someone typing with Shift down in another window is an ordinary
//!   thing, and Ctrl+Shift+Enter is not what anybody meant by "approve".
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

/// What the Approve button says the keyboard shortcut is.
///
/// Here rather than beside the button, because a shortcut nobody can see is a
/// shortcut nobody has, and a shortcut printed loosely is worse than none: a
/// reader who is told "Ctrl+Enter" and finds that Ctrl+Shift+Enter works too
/// has learned that the window is approximate about what it accepts. It is
/// not. [`is_approve_chord`] takes Control and refuses every other modifier
/// held with it, and this string names exactly that and nothing else.
///
/// `the_buttons_name_exactly_the_chords_the_guard_takes` reads this label the
/// way a user does and holds the rule to it, so the two cannot drift apart.
pub const APPROVE_CHORD: &str = "Ctrl+Enter";

/// What the Deny button says the keyboard shortcut is.
///
/// Bare, and the label says so by naming no modifier at all: Escape with
/// anything held is [`Action::Ignored`]. Pinned to the rule alongside
/// [`APPROVE_CHORD`].
pub const DENY_CHORD: &str = "Esc";

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

/// Is this the deliberate approval chord?
///
/// Control has to be held and nothing else may be. Exact, not a
/// contains-check: `Ctrl+Shift+Enter` and `Ctrl+Alt+Enter` are not approvals,
/// and someone holding Shift while typing at another window is an ordinary
/// thing to be doing when this window appears.
///
/// `ctrl`, `command` and `mac_cmd` are three spellings of one modifier and
/// not three modifiers — a Linux backend sets `ctrl` and `command` together
/// for a single key — so any of them counts as Control being held, and the
/// exactness that matters is that nothing else is.
fn is_approve_chord(m: Modifiers) -> bool {
    let control = m.ctrl || m.command || m.mac_cmd;
    control && !m.alt && !m.shift
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
    fn only_control_and_enter_approves_whatever_else_is_held() {
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);

        let approving: Vec<Modifiers> = every_modifier_combination()
            .into_iter()
            .filter(|m| guard.classify(&press(Key::Enter, *m), *m, now) == Action::Approve)
            .collect();

        assert!(!approving.is_empty(), "there is no way to approve at all");
        for m in &approving {
            assert!(m.ctrl || m.command || m.mac_cmd, "{m:?} approved without Control");
            assert!(!m.alt, "{m:?} approved with Alt held");
            assert!(!m.shift, "{m:?} approved with Shift held");
        }

        // Control has three spellings and a backend may send any of them; all
        // three are Control alone, and all three must work.
        for m in [Modifiers::CTRL, Modifiers::COMMAND, Modifiers::MAC_CMD] {
            assert!(approving.contains(&m), "{m:?} is Control held alone and did not approve");
        }

        // The near misses, spelled out so the intent survives a rewrite.
        for m in [
            Modifiers::NONE,
            Modifiers::SHIFT,
            Modifiers::ALT,
            Modifiers::CTRL | Modifiers::SHIFT,
            Modifiers::CTRL | Modifiers::ALT,
        ] {
            assert_eq!(
                guard.classify(&press(Key::Enter, m), m, now),
                Action::Ignored,
                "Enter with {m:?}"
            );
        }
    }

    /// The chord a button's label names, read the way a user reads it.
    ///
    /// A parser and not a table on purpose: what has to be checked is the
    /// string that reaches the screen, so a label that grew a modifier, lost
    /// one, or started naming a key this window does not act on fails here
    /// rather than becoming a promise nothing keeps. `Ctrl` is Control in the
    /// one spelling the label uses; the three spellings the backends send are
    /// the rule's business and are covered below.
    fn named(label: &str) -> (Key, Modifiers) {
        let mut wanted = Modifiers::NONE;
        let mut parts = label.split('+').peekable();
        let mut key = None;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                key = Some(match part {
                    "Enter" => Key::Enter,
                    "Esc" => Key::Escape,
                    other => panic!("{label:?} names a key this test cannot read: {other:?}"),
                });
                break;
            }
            match part {
                "Ctrl" => wanted.ctrl = true,
                "Shift" => wanted.shift = true,
                "Alt" => wanted.alt = true,
                other => panic!("{label:?} names a modifier this test cannot read: {other:?}"),
            }
        }
        (key.expect("a label names a key"), wanted)
    }

    #[test]
    fn the_buttons_name_exactly_the_chords_the_guard_takes() {
        // The labels and the rule, held together. A user who reads
        // "Ctrl+Enter" off the button expects Control and Enter to approve
        // and expects nothing else to, so every one of the modifier
        // combinations the label does not name has to be refused — including
        // Ctrl+Shift+Enter, which is deliberately inert and which a looser
        // label would be quietly promising.
        let clock = Clock::new();
        let guard = Guard::new(clock.at(0));
        let now = clock.at(5000);

        for (label, decides) in [(APPROVE_CHORD, Action::Approve), (DENY_CHORD, Action::Deny)] {
            let (key, wanted) = named(label);
            for m in every_modifier_combination() {
                // Control has three spellings and a backend may send any of
                // them; they are one modifier, and the label spells it once.
                let control = m.ctrl || m.command || m.mac_cmd;
                let is_named = control == wanted.ctrl
                    && m.shift == wanted.shift
                    && m.alt == wanted.alt;
                assert_eq!(
                    guard.classify(&press(key, m), m, now) == decides,
                    is_named,
                    "{label:?} and the guard disagree about {m:?}"
                );
            }
        }
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
            Modifiers::ALT,
            Modifiers::SHIFT,
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
