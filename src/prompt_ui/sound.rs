//! A noise when a window opens, for a reader who is not looking at the screen.
//!
//! # Why a program and not an audio device
//!
//! Every Rust crate that opens an audio device links C to do it — ALSA on
//! Linux, CoreAudio on macOS — and this is the process that draws
//! agent-chosen bytes. A sound is not worth putting a C library on that path.
//! So hatch spawns something that can already make a noise, names it in the
//! config, and depends on nothing.
//!
//! # It decides nothing
//!
//! A sound that does not play costs the reader the prompt and nothing else.
//! The window is drawn, the deadline runs, and every control works, whether
//! or not anything was heard. Nothing here is on the path of a verdict, which
//! is why it may fail quietly — see [`play`], which is the one thing in this
//! crate that deliberately ignores an error.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use crate::exec::lookup::lookup;

/// Why this machine cannot make a noise, or `None` when it can.
///
/// The same shape and the same reasons as
/// [`crate::exec::interactive::unavailable`], against the same `PATH`, through
/// the same lookup: a control that is dead has to say which of the two things
/// is wrong, because they send the reader to different places.
pub fn unavailable(sound: &[String], env: &BTreeMap<String, String>) -> Option<String> {
    let cause = match sound.first() {
        None => "No sound is configured here".to_string(),
        Some(program) => match lookup(program, env) {
            Some(_) => return None,
            None => format!("{program} is not installed here"),
        },
    };
    Some(format!(
        "{cause}, so nothing can be played. The \"sound\" key in hatch's config file names what to \
         run."
    ))
}

/// Spawn the configured program, and do not wait for it.
///
/// Detached in all three streams. A player that wrote to this process's
/// standard error would put its diagnostics in the daemon's terminal among
/// the window's own, and one that read standard input would be holding a pipe
/// the window needs.
///
/// The child is waited for on a thread of its own, which is the whole of what
/// that thread does. Not waiting at all would leave a zombie for as long as
/// this window is up, and waiting here would stop the window drawing until
/// the sound finished — the frame this is called from is the frame the reader
/// is waiting to see.
///
/// Every failure is ignored, and that is the decision this module exists to
/// make: there is no window state for "the sound did not play", because there
/// is nothing a reader would do about it that they are not already doing by
/// reading the window in front of them.
pub fn play(sound: &[String]) {
    let Some((program, args)) = sound.split_first() else {
        return;
    };
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = spawned {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::exec::env::build_child_env;

    #[test]
    fn nothing_configured_says_so_rather_than_naming_a_program() {
        let env = build_child_env(&Config::default());
        let said = unavailable(&[], &env).expect("nothing is configured");
        assert!(said.contains("No sound is configured"), "{said}");
        assert!(said.contains("config file"), "{said}");
    }

    #[test]
    fn a_player_that_is_not_installed_is_named_as_spelled() {
        let env = build_child_env(&Config::default());
        let sound = ["a-player-nobody-has".to_string(), "bell.oga".to_string()];
        let said = unavailable(&sound, &env).expect("it is not installed");
        // As spelled, because that is the name the reader will look for in
        // their config file.
        assert!(said.contains("a-player-nobody-has"), "{said}");
    }

    #[test]
    fn a_player_that_is_installed_is_no_obstacle() {
        let env = build_child_env(&Config::default());
        assert_eq!(unavailable(&["sh".to_string()], &env), None);
    }

    #[test]
    fn playing_nothing_is_not_an_error_and_starts_no_process() {
        // The empty case is reached whenever a machine has no default, so it
        // has to be a no-op rather than a panic on an empty slice.
        play(&[]);
    }

    #[test]
    fn a_player_that_cannot_be_started_is_ignored() {
        // The claim is that nothing here can take a window down. A program
        // that does not exist is the commonest way to find out.
        play(&["a-player-nobody-has".to_string()]);
    }
}
