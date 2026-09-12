//! The two palettes the approval window draws in, and the egui `Visuals`
//! built from them.
//!
//! # Why a palette of our own
//!
//! egui's own dark theme draws grey text on a near-black panel and gives a
//! group frame no fill at all, so a pane is a hairline over the same colour
//! as the window behind it. That reads as one undifferentiated field, and the
//! thing being read here — a command somebody is about to let run unsandboxed
//! — is exactly the thing that should have an edge around it. Two numbers say
//! it: egui's body text is 5.1:1 against its panel, and its pane surface is
//! 1.00:1 against the window chrome, which is to say there is no pane.
//!
//! So the colours are named here rather than inherited. [`Palette`] is the
//! whole of what this window draws with, [`Palette::visuals`] turns one into
//! the `Visuals` egui needs, and every widget in the window reads its colours
//! back out of those `Visuals` — so the chrome and the panes cannot drift
//! apart, and neither can the two themes.
//!
//! # The three surfaces
//!
//! * **chrome** — the panels: the headline, the header, the controls. A
//!   mid-grey in dark and a light grey in light, in both cases *not* the
//!   colour of a pane. It is one of three grounds — see [`Mood`].
//! * **surface** — inside a pane. The darkest thing on a dark screen and the
//!   lightest on a light one, so the command has the most contrast available
//!   to it, and the pane reads as an object of its own.
//! * **border** — the pane's frame and the separators. Held at 3:1 or better
//!   against the chrome, which is what WCAG 1.4.11 asks of the boundary of a
//!   component, so the edge does the work even for a reader who cannot see
//!   the fill difference.
//!
//! # What the meanings are, and what may change
//!
//! The *roles* are fixed and are the same in both themes: danger is red, warn
//! is orange, quiet is a grey below body text, quoted is the coolest hue on
//! screen, and the command word is contrast rather than a hue. What changes
//! between themes is the luminance each one needs to keep those roles
//! legible. Two rules hold in both:
//!
//! * **Danger and warn are never the same lightness.** Red against orange is
//!   the classic collision, so the two are separated by luminance as well as
//!   by hue — warn is the lighter of the pair on dark and on light alike —
//!   and both are additionally carried by words (`Marked:`) and by a chip's
//!   background, never by colour alone.
//! * **Quiet stays readable.** It is not decoration: the structural chips
//!   that make an invisible character visible are drawn in it. egui's own
//!   weak text is 2.7:1, which is a glyph a reader can miss; here it is above
//!   7:1 on a pane in both themes.
//!
//! # Three grounds, one luminance
//!
//! A window that is asking, a window whose command is running and a window
//! showing a finished run are three different things, and they used to be one
//! picture. [`Mood`] is that difference, and it is carried by the ground the
//! panels are drawn on.
//!
//! The three grounds are separated by **hue and not by lightness**, and that
//! is a constraint rather than a taste. Every meaning above is pinned to a
//! contrast ratio against the chrome, several of them within a tenth of their
//! floor — a mid grey is the one ground a saturated hue cannot get far from
//! in either direction — so a ground that moved in luminance would push one
//! of them under. Holding the luminance and turning the hue leaves every
//! ratio where it was: `every_meaning_survives_every_ground` is the same
//! assertions again, once per ground, and `the_three_grounds_are_told_apart`
//! is what stops a tint so slight that nobody sees it.
//!
//! Nothing about the moods says whether anything *worked*. A finished run is
//! a violet window whether it exited zero or not; what happened is said in
//! words, and in the danger and warn colours, by the row that reports the
//! outcome. A green ground over "Failed — exit 1" is exactly the kind of
//! second voice this window does not have.
//!
//! # Root is not a fourth ground
//!
//! A command that will run as root is the one loud fact about this window
//! that is not a phase. It is true while the window asks, true while the
//! command runs, and true while the result sits on screen — which is exactly
//! the axis [`Mood`] moves along, so the two are orthogonal and root cannot
//! be a fourth [`Mood`]. It would not be one ground but three, and there are
//! no three left: the grounds are held at one luminance because several
//! meanings clear their floor on them by a tenth, and a fourth hue at that
//! luminance would also have to be told apart from the other three by
//! `the_three_grounds_are_told_apart`.
//!
//! So root is said the other way round, in the two places the window has that
//! cost it no rows: a filled block where the header had tinted text, and an
//! edge the window does not otherwise have. Both are [`Palette::root_mark`],
//! and both are a change of *shape* — a block where there was none, a line
//! where there was none — which is the point of them. A reader who cannot
//! tell this red from this grey still sees a solid rectangle, and still sees
//! that the window is framed. Colour *and* shape, never colour alone, which
//! is the same promise the countdown keeps with size.

use eframe::egui::{self, Color32, Stroke};
use serde::{Deserialize, Serialize};

/// Which of the two palettes the window draws in.
///
/// A preference and nothing more: no colour here decides anything, and both
/// themes carry every meaning the window has. Default is [`Theme::Dark`],
/// which is what the window has always been.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

impl Theme {
    /// The colours this theme draws with.
    pub fn palette(self) -> Palette {
        match self {
            Theme::Dark => DARK,
            Theme::Light => LIGHT,
        }
    }

    /// Which theme a `Ui` is currently drawing in.
    ///
    /// Read back from the `Visuals` rather than carried alongside them, so a
    /// widget deep in the window cannot be handed a palette that disagrees
    /// with the panel it is drawn on.
    pub fn of(visuals: &egui::Visuals) -> Theme {
        match visuals.dark_mode {
            true => Theme::Dark,
            false => Theme::Light,
        }
    }
}

/// What the window is doing, which is what its ground says.
///
/// Three states and not two: if a running window and a finished one looked
/// alike, the change would teach a reader that the window had stopped asking
/// and nothing more, which they can already see from the buttons being gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    /// Waiting for a person. The window has a question on it.
    Asking,
    /// The approved command is running. Nothing on screen is a question any
    /// more, and nothing a reader does here decides anything.
    Running,
    /// It is over. The window is showing what happened, and is on its way
    /// out or has been kept.
    Finished,
}

/// Every colour the approval window draws with.
///
/// One struct rather than a scattering of constants, because the claims that
/// matter are relations between two of these — text against surface, border
/// against chrome, danger against warn — and a test can only check a relation
/// if both sides are in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// The panels: everything that is not a pane, while the window is asking
    /// something.
    pub chrome: Color32,
    /// The same panels while the approved command is running.
    pub running: Color32,
    /// The same panels once it is over and the window is only showing what
    /// happened.
    pub finished: Color32,
    /// Inside a pane: the surface the command itself is drawn on.
    pub surface: Color32,
    /// The pane's frame, and every separator.
    pub border: Color32,
    /// Ordinary text, on either surface.
    pub text: Color32,
    /// Captions, structural chips, and anything that is a note about the
    /// window rather than part of the command.
    pub quiet: Color32,
    /// A danger marker.
    pub danger: Color32,
    /// A warning: an unusual character, dropped output.
    pub warn: Color32,
    /// The word that names what runs. Contrast and an underline, never a hue.
    pub command: Color32,
    /// A quoted string, delimiters included.
    pub quoted: Color32,
    /// Behind a chip.
    pub chip_bg: Color32,
    /// Behind a separator's own characters.
    pub separator_bg: Color32,
    /// Behind a resolved variable's value.
    pub value_bg: Color32,
    /// Behind a side-by-side cell for a row that side has no line on.
    ///
    /// Deliberately not [`Palette::separator_bg`], and deliberately tinted
    /// rather than grey: a gap has to be distinguishable from a line whose
    /// content happens to be empty *and* from the faint block a separator
    /// sits on, and two neutral greys a few steps apart are not. Nothing is
    /// wrong with a gap, so the tint carries no meaning of its own.
    pub gap_bg: Color32,
    /// Button faces, in the three states egui asks for.
    pub button: Color32,
    pub button_hovered: Color32,
    pub button_active: Color32,
}

/// The dark palette: a grey window with black panes in it.
///
/// Body text is 15.3:1 on a pane and 8.9:1 on the chrome; the pane surface is
/// 1.7:1 against the chrome and its border is 3.0:1 against it. egui's own
/// dark theme is 5.1:1 and 1.00:1 for the first and third of those.
pub const DARK: Palette = Palette {
    chrome: Color32::from_rgb(58, 58, 58),
    running: Color32::from_rgb(38, 58, 82),
    finished: Color32::from_rgb(72, 48, 78),
    surface: Color32::from_rgb(13, 13, 13),
    border: Color32::from_rgb(132, 132, 132),
    text: Color32::from_rgb(228, 228, 228),
    quiet: Color32::from_rgb(172, 172, 172),
    danger: Color32::from_rgb(255, 105, 100),
    warn: Color32::from_rgb(255, 170, 45),
    command: Color32::from_rgb(255, 255, 255),
    quoted: Color32::from_rgb(110, 185, 255),
    chip_bg: Color32::from_rgb(72, 72, 72),
    separator_bg: Color32::from_rgb(60, 60, 60),
    value_bg: Color32::from_rgb(52, 52, 52),
    gap_bg: Color32::from_rgb(36, 46, 66),
    button: Color32::from_rgb(88, 88, 88),
    button_hovered: Color32::from_rgb(108, 108, 108),
    button_active: Color32::from_rgb(128, 128, 128),
};

/// The light palette: a grey window with white panes in it.
///
/// The same shape as [`DARK`] rather than its inverse in every particular:
/// orange on white is the one colour that cannot simply be lightened, so warn
/// here is a dark amber, and it is still the *lighter* of the danger/warn
/// pair — which is the relation a reader learns, in either theme.
pub const LIGHT: Palette = Palette {
    chrome: Color32::from_rgb(201, 201, 201),
    running: Color32::from_rgb(184, 204, 224),
    finished: Color32::from_rgb(216, 198, 220),
    surface: Color32::from_rgb(255, 255, 255),
    border: Color32::from_rgb(110, 110, 110),
    text: Color32::from_rgb(26, 26, 26),
    quiet: Color32::from_rgb(80, 80, 80),
    danger: Color32::from_rgb(176, 0, 0),
    warn: Color32::from_rgb(166, 92, 0),
    command: Color32::from_rgb(0, 0, 0),
    quoted: Color32::from_rgb(0, 90, 180),
    chip_bg: Color32::from_rgb(224, 224, 224),
    separator_bg: Color32::from_rgb(232, 232, 232),
    value_bg: Color32::from_rgb(238, 238, 238),
    gap_bg: Color32::from_rgb(214, 226, 246),
    button: Color32::from_rgb(240, 240, 240),
    button_hovered: Color32::from_rgb(250, 250, 250),
    button_active: Color32::from_rgb(176, 176, 176),
};

impl Palette {
    /// The ground this window draws its panels on in `mood`.
    pub fn ground(self, mood: Mood) -> Color32 {
        match mood {
            Mood::Asking => self.chrome,
            Mood::Running => self.running,
            Mood::Finished => self.finished,
        }
    }

    /// The two colours a root mark is drawn in: what it is filled with, and
    /// the ink reversed out of that fill.
    ///
    /// The fill is `danger`, which is the colour that already means *be
    /// careful*. The ink is `surface` — the pane colour — and not `chrome`,
    /// which is the colour actually behind the mark: the chrome is the one
    /// thing in this palette that moves, and a mark whose ink changed at the
    /// moment the command started running would be saying something about the
    /// phase. It says nothing about the phase. `surface` is the far end of
    /// the palette from `danger` in both themes, so the word inside the block
    /// is read at body contrast against it.
    ///
    /// Returned as a pair rather than as two fields because they are only
    /// ever a relation: the claim worth testing is that the second is legible
    /// on the first.
    pub fn root_mark(self) -> (Color32, Color32) {
        (self.danger, self.surface)
    }

    /// The same palette with `mood`'s ground as its chrome.
    ///
    /// A substitution and not a second palette: every other colour is a
    /// meaning, and a meaning that changed with the phase would be a second
    /// vocabulary for a reader to learn. Only the ground moves.
    pub fn in_mood(self, mood: Mood) -> Palette {
        Palette { chrome: self.ground(mood), ..self }
    }

    /// The egui `Visuals` that draw this palette.
    ///
    /// Every colour the window reads back — through `ui.visuals()` and
    /// through [`Palette::of`] — comes from here, so there is exactly one
    /// definition of each and no way for the panel behind a widget to
    /// disagree with the widget.
    pub fn visuals(self, theme: Theme) -> egui::Visuals {
        let base = match theme {
            Theme::Dark => egui::Visuals::dark(),
            Theme::Light => egui::Visuals::light(),
        };
        let mut widgets = base.widgets;

        // The pane frame and the separators, at 3:1 or better against the
        // chrome: this is the edge that says where a pane starts, and on a
        // dark screen the fill difference alone cannot carry that.
        widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.border);
        widgets.noninteractive.weak_bg_fill = self.chrome;
        widgets.noninteractive.bg_fill = self.chrome;
        widgets.noninteractive.fg_stroke = Stroke::new(1.0, self.text);

        // Buttons have to read as raised against a chrome that is no longer
        // near-black, so their faces are named here rather than left at
        // egui's, which sit within a step or two of the panel.
        widgets.inactive.weak_bg_fill = self.button;
        widgets.inactive.bg_fill = self.button;
        widgets.inactive.fg_stroke = Stroke::new(1.0, self.text);
        widgets.hovered.weak_bg_fill = self.button_hovered;
        widgets.hovered.bg_fill = self.button_hovered;
        widgets.hovered.fg_stroke = Stroke::new(1.5, self.command);
        widgets.hovered.bg_stroke = Stroke::new(1.0, self.border);
        widgets.active.weak_bg_fill = self.button_active;
        widgets.active.bg_fill = self.button_active;
        // `strong_text_color` is read off this one, and the command word is
        // the palette's `command`: the two must be the same colour or the
        // headline's strong text and the pane's command word disagree.
        widgets.active.fg_stroke = Stroke::new(2.0, self.command);
        widgets.active.bg_stroke = Stroke::new(1.0, self.command);
        widgets.open.weak_bg_fill = self.button;
        widgets.open.bg_fill = self.chrome;
        widgets.open.bg_stroke = Stroke::new(1.0, self.border);
        widgets.open.fg_stroke = Stroke::new(1.0, self.text);

        egui::Visuals {
            widgets,
            panel_fill: self.chrome,
            window_fill: self.chrome,
            window_stroke: Stroke::new(1.0, self.border),
            // The pane surface. `extreme_bg_color` is also what a `TextEdit`
            // sits on, which is the same claim in a different place: the box
            // you read or type in is not the panel around it.
            extreme_bg_color: self.surface,
            faint_bg_color: self.separator_bg,
            code_bg_color: self.chip_bg,
            warn_fg_color: self.warn,
            error_fg_color: self.danger,
            hyperlink_color: self.quoted,
            // Named rather than derived. egui's weak text is the body colour
            // at 0.6 alpha, which lands at 2.7:1 on its own panel — and weak
            // text here draws the structural chips that make an invisible
            // character visible.
            weak_text_color: Some(self.quiet),
            ..base
        }
    }
}

/// The palette a `Ui` is drawing with, ground included.
///
/// The chrome is read back out of the `Visuals` rather than taken from the
/// constant, so that `palette.chrome` is the colour actually behind the
/// widget asking — a palette that named the asking ground while the window
/// was running would be a fact about the screen that is not true of it.
pub fn of(ui: &egui::Ui) -> Palette {
    let visuals = ui.visuals();
    Palette { chrome: visuals.panel_fill, ..Theme::of(visuals).palette() }
}

/// Put a `Ui` and everything drawn in it into `mood`.
///
/// On the `Ui` and not on the context, because this is a property of the
/// frame being drawn and the phase can change between two of them. egui
/// resolves a panel's frame from the style of the `Ui` it is shown in — see
/// `Panel::resolve_frame` — so setting it here reaches the panels, the widgets
/// in them and [`of`], which is what keeps the ground and the colours drawn
/// against it from disagreeing.
pub fn wear(ui: &mut egui::Ui, mood: Mood) {
    let theme = Theme::of(ui.visuals());
    ui.style_mut().visuals = theme.palette().in_mood(mood).visuals(theme);
}

/// How thick the root edge is drawn, in points.
///
/// Thick enough to be a frame rather than a hairline somebody takes for the
/// compositor's own border, and thin enough to sit inside the margin every
/// panel already leaves around its contents — so it covers no text and costs
/// no row. Three points is about a third of that margin.
pub const ROOT_EDGE: f32 = 3.0;

/// Frame `window` in the colour that says the command in it runs as root.
///
/// Painted rather than laid out, and painted last: it takes nothing from the
/// space the panels divided up, which is the whole reason it is an edge and
/// not a banner. The window has no border of its own — a maximised viewport
/// is drawn to its edges — so the line is new geometry and not a recolouring
/// of something already there, and that is what a reader who cannot see the
/// hue is left with.
///
/// Every phase, because a root command that is *running* is still root and so
/// is one that has finished; the caller is the window itself rather than any
/// of the panels, so no phase can forget to ask. See [`Palette::root_mark`]
/// for why this is not a [`Mood`].
pub fn mark_root(ui: &egui::Ui, window: egui::Rect) {
    let (fill, _) = of(ui).root_mark();
    ui.painter().with_clip_rect(window).rect_stroke(
        window,
        egui::CornerRadius::ZERO,
        Stroke::new(ROOT_EDGE, fill),
        egui::StrokeKind::Inside,
    );
}

/// Apply a theme to a whole context.
pub fn apply(ctx: &egui::Context, theme: Theme) {
    let visuals = theme.palette().visuals(theme);
    ctx.set_theme(match theme {
        Theme::Dark => egui::Theme::Dark,
        Theme::Light => egui::Theme::Light,
    });
    // Both slots, not the current one: eframe may restore a theme preference
    // of its own on the next frame, and a window that repainted itself in
    // egui's colours because the desktop said "light" would be the reading
    // problem this palette exists to fix, arriving a frame late.
    ctx.all_styles_mut(|style| style.visuals = visuals.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relative luminance, as WCAG 2 defines it.
    fn luminance(colour: Color32) -> f64 {
        let channel = |v: u8| {
            let v = f64::from(v) / 255.0;
            match v <= 0.04045 {
                true => v / 12.92,
                false => ((v + 0.055) / 1.055).powf(2.4),
            }
        };
        0.2126 * channel(colour.r()) + 0.7152 * channel(colour.g()) + 0.0722 * channel(colour.b())
    }

    /// The WCAG 2 contrast ratio between two opaque colours.
    fn contrast(a: Color32, b: Color32) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// Both palettes, so every claim below is made about each of them.
    fn palettes() -> [(&'static str, Palette); 2] {
        [("dark", DARK), ("light", LIGHT)]
    }

    /// Every ground a palette draws its panels on, named.
    ///
    /// The three moods are three backgrounds for the same vocabulary, so
    /// every claim about a colour on the chrome is three claims. Built from
    /// [`Mood`] by naming each variant, so a fourth mood breaks this build
    /// rather than quietly going unchecked.
    fn grounds(palette: Palette) -> [(&'static str, Color32); 3] {
        [
            ("asking", palette.ground(Mood::Asking)),
            ("running", palette.ground(Mood::Running)),
            ("finished", palette.ground(Mood::Finished)),
        ]
    }

    #[test]
    fn the_command_is_read_at_better_than_seven_to_one_on_its_own_surface() {
        // AAA for body text, and this is the text the whole window exists to
        // have somebody read. egui's own dark theme manages 5.1:1.
        for (name, palette) in palettes() {
            let ratio = contrast(palette.text, palette.surface);
            assert!(ratio >= 7.0, "{name}: body text is {ratio:.2}:1 on a pane");
        }
    }

    #[test]
    fn every_meaning_is_read_at_aa_on_the_surface_it_is_drawn_on() {
        // AA for body text is 4.5:1, and inside a pane that is what
        // everything gets: a pane is a black or a white ground precisely so
        // that a hue has the whole range to be legible in.
        for (name, palette) in palettes() {
            for (role, colour) in [
                ("text", palette.text),
                ("quiet", palette.quiet),
                ("danger", palette.danger),
                ("warn", palette.warn),
                ("command", palette.command),
                ("quoted", palette.quoted),
            ] {
                let ratio = contrast(colour, palette.surface);
                assert!(ratio >= 4.5, "{name}: {role} is {ratio:.2}:1 on a pane");
            }
        }
    }

    #[test]
    fn the_chrome_keeps_aa_for_everything_it_draws_at_body_size() {
        // The window chrome is a mid grey, which is what gives a pane an edge
        // to be a pane against — and a mid grey is the one ground a saturated
        // hue cannot reach 4.5:1 on in either direction. A red that managed
        // it on this grey would be pink.
        //
        // So the split is WCAG's own: `danger` and `warn` are drawn on the
        // chrome only as bold labels at body size or larger — the marked
        // list, the unusual-character line, the countdown, the outcome — and
        // bold at 14 points or more is large text, which AA sets at 3:1.
        // Everything the chrome draws at ordinary weight keeps 4.5:1. Colour
        // is never the only channel for either of them: the marked list says
        // "Marked:" in words and a loud chip carries a background as well.
        //
        // Once per ground, because the window has three of them and the
        // reader is owed the same legibility on each. This is the assertion
        // that keeps the running and finished grounds a change of hue: they
        // hold their luminance because every ratio below is measured against
        // them, several within a tenth of the floor.
        for (name, palette) in palettes() {
            for (mood, ground) in grounds(palette) {
                for (role, colour) in
                    [("text", palette.text), ("quiet", palette.quiet), ("command", palette.command)]
                {
                    let ratio = contrast(colour, ground);
                    assert!(ratio >= 4.5, "{name}/{mood}: {role} is {ratio:.2}:1 on the chrome");
                }
                for (role, colour) in [("danger", palette.danger), ("warn", palette.warn)] {
                    let ratio = contrast(colour, ground);
                    assert!(
                        ratio >= 3.0,
                        "{name}/{mood}: bold {role} is {ratio:.2}:1 on the chrome"
                    );
                }
            }
        }
    }

    #[test]
    fn every_meaning_survives_every_ground() {
        // The rest of the vocabulary, on each of the three grounds. `quoted`
        // is the one the running ground could plausibly collide with — it is
        // the coolest hue in the window and the running ground is a blue —
        // so it is checked against the ground itself and not only against the
        // pane it is usually drawn on.
        for (name, palette) in palettes() {
            for (mood, ground) in grounds(palette) {
                let ratio = contrast(palette.quoted, ground);
                assert!(ratio >= 3.0, "{name}/{mood}: quoted is {ratio:.2}:1 on the chrome");
                // And the ground is a ground, not a meaning: no mood may land
                // on a colour this window already uses to say something.
                for (role, colour) in [
                    ("danger", palette.danger),
                    ("warn", palette.warn),
                    ("quoted", palette.quoted),
                    ("surface", palette.surface),
                    ("gap", palette.gap_bg),
                ] {
                    assert_ne!(ground, colour, "{name}/{mood}: the ground is the {role} colour");
                }
            }
        }
    }

    #[test]
    fn the_root_mark_is_read_out_of_its_fill_and_is_seen_against_every_ground() {
        // The mark is the one place in this window where the colours run the
        // other way round: a block of `danger` with the pane colour reversed
        // out of it, rather than `danger` written on something. So it has two
        // ratios and they are different claims. The word inside gets AA for
        // body text, because it is a word somebody reads. The block itself
        // gets what WCAG 1.4.11 asks of the boundary of a component, on each
        // of the three grounds, because the shape is the half of the mark
        // that survives a reader who cannot see the hue at all.
        for (name, palette) in palettes() {
            let (fill, ink) = palette.root_mark();
            let word = contrast(ink, fill);
            assert!(word >= 4.5, "{name}: ROOT is {word:.2}:1 inside its own block");
            for (mood, ground) in grounds(palette) {
                let block = contrast(fill, ground);
                assert!(
                    block >= 3.0,
                    "{name}/{mood}: the root block is {block:.2}:1 on the window"
                );
            }
            // And it is a reversal, not a second red on a red: the ink is the
            // far end of the palette, which is also what the command is read
            // on.
            assert_eq!(ink, palette.surface, "{name}: the mark's ink is not the pane colour");
            assert_eq!(fill, palette.danger, "{name}: the mark is filled with something new");
        }
    }

    #[test]
    fn the_root_mark_says_the_same_thing_in_every_phase() {
        // Root is not a phase — it is true while the window asks, while the
        // command runs and while the result sits there — so neither half of
        // the mark may move when the ground does. An ink that followed the
        // chrome would be a mark that said something about the phase, and the
        // phase is already the ground's job.
        for (name, palette) in palettes() {
            for (mood, _) in grounds(palette) {
                let worn = palette.in_mood(match mood {
                    "asking" => Mood::Asking,
                    "running" => Mood::Running,
                    _ => Mood::Finished,
                });
                assert_eq!(
                    worn.root_mark(),
                    palette.root_mark(),
                    "{name}/{mood}: the root mark changed with the window's mood"
                );
            }
        }
    }

    #[test]
    fn the_three_grounds_are_told_apart() {
        // A tint nobody notices is a tint that has not been applied. The
        // three are the same lightness on purpose — see the module docs — so
        // the distance that matters is the one contrast cannot see, and this
        // is the crude version of it: how far apart the two colours are in
        // the cube. Twenty is about where a flat field stops reading as the
        // same grey.
        for (name, palette) in palettes() {
            let all = grounds(palette);
            for (i, (first, a)) in all.iter().enumerate() {
                for (second, b) in &all[i + 1..] {
                    let apart = f64::from(i32::from(a.r()) - i32::from(b.r())).powi(2)
                        + f64::from(i32::from(a.g()) - i32::from(b.g())).powi(2)
                        + f64::from(i32::from(a.b()) - i32::from(b.b())).powi(2);
                    assert!(
                        apart.sqrt() >= 20.0,
                        "{name}: {first} and {second} are {:.1} apart in RGB",
                        apart.sqrt()
                    );
                }
            }
        }
    }

    #[test]
    fn quiet_is_a_glyph_a_reader_can_see_rather_than_a_shade_of_the_background() {
        // The structural chips — the ones standing in for a newline or a tab
        // — are drawn in this colour, and an invisible character rendered
        // invisibly is the bug they exist to fix. egui's own weak text is
        // 2.7:1 against its own panel.
        for (name, palette) in palettes() {
            let ratio = contrast(palette.quiet, palette.surface);
            assert!(ratio >= 7.0, "{name}: quiet text is {ratio:.2}:1 on a pane");
        }
    }

    #[test]
    fn a_pane_is_a_surface_of_its_own_and_its_edge_says_so() {
        for (name, palette) in palettes() {
            // On every ground: the panes are still drawn while the command
            // runs, so a mood that swallowed a pane's edge would take the
            // boundary away exactly where the output is arriving.
            for (mood, ground) in grounds(palette) {
                // The fill alone: an anchor for the eye, not a boundary claim.
                let fill = contrast(palette.surface, ground);
                assert!(fill >= 1.5, "{name}/{mood}: a pane is {fill:.2}:1 against the window");
                // The edge, which is the boundary claim, at what WCAG 1.4.11
                // asks of the boundary of a component.
                let edge = contrast(palette.border, ground);
                assert!(edge >= 3.0, "{name}/{mood}: a pane's border is {edge:.2}:1 on it");
            }
            let inner = contrast(palette.border, palette.surface);
            assert!(inner >= 3.0, "{name}: a pane's border is {inner:.2}:1 against the pane");
        }
    }

    #[test]
    fn danger_and_warn_are_told_apart_by_lightness_and_not_only_by_hue() {
        // Red against orange is the collision a colour-blind reader actually
        // has, and this window says "Marked:" in words for the same reason.
        // A fifth of a stop between the two luminances is the floor.
        for (name, palette) in palettes() {
            let ratio = contrast(palette.danger, palette.warn);
            assert!(ratio >= 1.3, "{name}: danger and warn are {ratio:.2}:1 apart");
            // And the direction is the same in both themes, so the relation
            // is something a reader can carry between them.
            assert!(
                luminance(palette.warn) > luminance(palette.danger),
                "{name}: warn is not the lighter of the pair"
            );
        }
    }

    #[test]
    fn a_gap_is_not_the_block_a_separator_sits_on() {
        // Both are faint fills a few steps from the surface, and if they
        // matched, the only thing telling a missing line from a `;` would be
        // the text in one of them.
        for (name, palette) in palettes() {
            assert_ne!(palette.gap_bg, palette.separator_bg, "{name}");
            let from_surface = contrast(palette.gap_bg, palette.surface);
            assert!(from_surface >= 1.2, "{name}: a gap is {from_surface:.2}:1 from the pane");
        }
    }

    #[test]
    fn the_strong_text_a_widget_reaches_for_is_the_command_word_colour() {
        // `RichText::strong` and the command span must not be two different
        // whites, or "the same characters drawn with more contrast" becomes
        // two contrasts.
        for (name, palette) in palettes() {
            let theme = if palette == DARK { Theme::Dark } else { Theme::Light };
            let visuals = palette.visuals(theme);
            assert_eq!(visuals.strong_text_color(), palette.command, "{name}");
            assert_eq!(visuals.text_color(), palette.text, "{name}");
            assert_eq!(visuals.weak_text_color(), palette.quiet, "{name}");
            assert_eq!(visuals.panel_fill, palette.chrome, "{name}");
            // And a mood swaps the ground and nothing else: the whole point
            // of `in_mood` is that a reader learns one vocabulary.
            for (mood, ground) in grounds(palette) {
                let worn = palette.in_mood(match mood {
                    "asking" => Mood::Asking,
                    "running" => Mood::Running,
                    _ => Mood::Finished,
                });
                assert_eq!(worn.visuals(theme).panel_fill, ground, "{name}/{mood}");
                assert_eq!(worn.text, palette.text, "{name}/{mood}: a mood moved a meaning");
                assert_eq!(worn.quiet, palette.quiet, "{name}/{mood}");
                assert_eq!(worn.danger, palette.danger, "{name}/{mood}");
                assert_eq!(worn.warn, palette.warn, "{name}/{mood}");
                assert_eq!(worn.quoted, palette.quoted, "{name}/{mood}");
                assert_eq!(worn.command, palette.command, "{name}/{mood}");
                assert_eq!(worn.surface, palette.surface, "{name}/{mood}");
            }
            assert_eq!(visuals.extreme_bg_color, palette.surface, "{name}");
            assert_eq!(visuals.error_fg_color, palette.danger, "{name}");
            assert_eq!(visuals.warn_fg_color, palette.warn, "{name}");
            assert_eq!(visuals.hyperlink_color, palette.quoted, "{name}");
            // The window's own fill and edge, for the frame a compositor
            // draws around a floating window: the same chrome, so a window
            // that is not maximised does not have a second background.
            assert_eq!(visuals.window_fill, palette.chrome, "{name}");
            assert_eq!(visuals.window_stroke.color, palette.border, "{name}");
            // egui's own faint fill and code background, which is what a
            // widget drawn by egui rather than by this window will pick up.
            assert_eq!(visuals.faint_bg_color, palette.separator_bg, "{name}");
            assert_eq!(visuals.code_bg_color, palette.chip_bg, "{name}");
            assert_eq!(visuals.widgets.noninteractive.bg_stroke.color, palette.border, "{name}");
        }
    }

    #[test]
    fn applying_a_theme_puts_it_on_both_of_a_contexts_styles() {
        // Both slots and not the current one: eframe may restore a theme
        // preference of its own on a later frame, and a window that repainted
        // itself in egui's colours because the desktop said "light" would be
        // the reading problem this palette exists to fix, arriving a frame
        // late.
        let ctx = egui::Context::default();
        apply(&ctx, Theme::Light);

        for slot in [egui::Theme::Dark, egui::Theme::Light] {
            let visuals = &ctx.style_of(slot).visuals;
            assert_eq!(visuals.panel_fill, LIGHT.chrome, "{slot:?} slot kept egui's own colours");
            assert_eq!(visuals.extreme_bg_color, LIGHT.surface, "{slot:?}");
        }
        // And the palette a `Ui` reads back is the one that was applied.
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            assert_eq!(of(ui), LIGHT, "a Ui is drawing with a palette nobody applied");
        });
        out.textures_delta.clear();

        apply(&ctx, Theme::Dark);
        assert_eq!(ctx.style_of(egui::Theme::Light).visuals.panel_fill, DARK.chrome);
    }

    #[test]
    fn a_ui_reads_back_the_ground_it_is_actually_drawing_on() {
        // `of` is how every widget in the window gets its colours, and the
        // chrome it reports has to be the colour behind that widget rather
        // than the one the constant names: a palette that said "asking grey"
        // while the window was running would be a statement about the screen
        // that is not true of it.
        let ctx = egui::Context::default();
        for theme in [Theme::Dark, Theme::Light] {
            apply(&ctx, theme);
            for mood in [Mood::Asking, Mood::Running, Mood::Finished] {
                let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
                    wear(ui, mood);
                    assert_eq!(
                        of(ui).chrome,
                        theme.palette().ground(mood),
                        "{theme:?}/{mood:?}: the palette names a ground nobody is drawing on"
                    );
                    assert_eq!(
                        ui.visuals().panel_fill,
                        theme.palette().ground(mood),
                        "{theme:?}/{mood:?}: the panel behind it is a third colour"
                    );
                    // Everything else is still the theme's own.
                    assert_eq!(of(ui).quiet, theme.palette().quiet, "{theme:?}/{mood:?}");
                    assert_eq!(of(ui).surface, theme.palette().surface, "{theme:?}/{mood:?}");
                });
                out.textures_delta.clear();
            }
        }
    }

    #[test]
    fn a_theme_reads_back_as_the_one_that_was_applied() {
        for theme in [Theme::Dark, Theme::Light] {
            let visuals = theme.palette().visuals(theme);
            assert_eq!(Theme::of(&visuals), theme);
            assert_eq!(Theme::of(&visuals).palette(), theme.palette());
        }
    }

    #[test]
    fn dark_is_what_a_config_that_says_nothing_gets() {
        assert_eq!(Theme::default(), Theme::Dark);
    }

    #[test]
    fn a_theme_is_written_and_read_back_as_the_word_a_reader_would_type() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Holder {
            theme: Theme,
        }
        let text = toml::to_string(&Holder { theme: Theme::Light }).unwrap();
        assert!(text.contains("theme = \"light\""), "{text}");
        assert_eq!(
            toml::from_str::<Holder>("theme = 'dark'\n").unwrap(),
            Holder { theme: Theme::Dark }
        );
    }
}
