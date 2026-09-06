//! The environment an approved command actually runs in.
//!
//! hatch **constructs** the child environment instead of inheriting one, and
//! that is a display decision before it is an execution decision.
//!
//! There is no single obvious environment to inherit. The daemon's own
//! environment came from wherever the daemon happened to be started — a
//! terminal, a desktop session, a systemd unit — and carries whatever that
//! place happened to export. The agent's sandbox has an environment too, and
//! that one is agent-influenced. And for a `root: true` operation `run0`
//! resets the environment anyway, so an inherited value would not survive the
//! trip.
//!
//! Three candidate environments, none of them the one the command runs in.
//! The approval window has to name a value it can stand behind, so hatch
//! builds the environment it will hand the child, from config alone, and
//! renders against exactly that. [`build_child_env`] is the single source of
//! truth: the annotator in [`crate::render::command`] resolves `$HOME`
//! against its result, and the spawner will hand the same map to the child
//! once execution lands — nothing spawns yet, so for now this is the
//! display's source of truth and only that. A
//! window that resolved variables against `std::env` would print a value that
//! looks authoritative and is wrong, which is the worst failure available to
//! a display whose whole job is to be believed — worse than printing nothing,
//! because nothing at least does not invite a reader to skip reading.
//!
//! So this module never reads [`std::env`](mod@std::env), and
//! `child_env_is_constructed_not_inherited` is what holds it to that.

use std::collections::BTreeMap;

use crate::config::Config;

/// The complete environment for an approved command.
///
/// Built from nothing: `PATH` from [`Config::exec_path`], then every pair in
/// [`Config::exec_env`]. Nothing else is added and nothing is inherited, so
/// the result is a total function of the config file — which is what lets the
/// approval window claim a value rather than guess one.
///
/// # `PATH` precedence
///
/// `exec_env` is applied second and therefore wins. That is deliberate:
/// `exec_env` is documented as the complete child environment layered on top
/// of `exec_path`, so a user who spells `PATH` out there means it. The rule
/// matters beyond this function — anything that needs to know where a binary
/// will be looked up must read `PATH` out of this map rather than out of
/// `Config::exec_path`, or it resolves against a path the child will not use.
/// `exec_env_may_override_path` pins the order.
///
/// The environment is agent-visible but not agent-controllable: the agent
/// chooses the command text, the user owns the config file.
pub fn build_child_env(config: &Config) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), config.exec_path.clone());
    for (key, value) in &config.exec_env {
        env.insert(key.clone(), value.clone());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_env_is_constructed_not_inherited() {
        // Reads the process environment and never writes it. An earlier
        // version planted a canary with `set_var` under a comment claiming a
        // single-threaded test; the comment was false -- the default harness
        // runs tests in parallel and other tests reach `dirs::home_dir`,
        // which calls `getenv` concurrently, which is exactly what edition
        // 2024 made `set_var` unsafe for. Reading is sound, and asking about
        // the *whole* real environment is the stronger question anyway: no
        // key this process holds may appear in the child's unless the config
        // put it there.
        let config = Config::default();
        let env = build_child_env(&config);

        let inheritable: Vec<String> = std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| key != "PATH" && !config.exec_env.contains_key(key))
            .collect();
        assert!(!inheritable.is_empty(), "this process must have an environment to inherit");
        for key in inheritable {
            assert!(!env.contains_key(&key), "{key} was inherited from this process");
        }
        assert!(env.contains_key("PATH"), "but the result is not empty either");
    }

    #[test]
    fn path_comes_from_config_not_the_process() {
        let config = Config {
            exec_path: "/only/this".to_string(),
            ..Config::default()
        };
        assert_eq!(build_child_env(&config).get("PATH").map(String::as_str), Some("/only/this"));
    }

    #[test]
    fn every_configured_variable_is_passed_through() {
        let mut config = Config::default();
        config.exec_env.clear();
        config.exec_env.insert("HOME".to_string(), "/home/user".to_string());
        config.exec_env.insert("TERM".to_string(), "dumb".to_string());

        let env = build_child_env(&config);
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/user"));
        assert_eq!(env.get("TERM").map(String::as_str), Some("dumb"));
    }

    #[test]
    fn nothing_is_added_beyond_path_and_the_configured_pairs() {
        // The count is the point: an implementation that helpfully added
        // `USER` or `SHELL` would still pass every test above, and the window
        // would then be resolving against an environment nobody configured.
        let mut config = Config::default();
        config.exec_env.clear();
        config.exec_env.insert("HOME".to_string(), "/home/user".to_string());

        let env = build_child_env(&config);
        assert_eq!(
            env.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["HOME", "PATH"],
            "exactly PATH plus what the config asked for"
        );
    }

    #[test]
    fn an_empty_exec_env_still_yields_a_path() {
        let mut config = Config::default();
        config.exec_env.clear();
        assert_eq!(build_child_env(&config).len(), 1);
    }

    #[test]
    fn exec_env_may_override_path() {
        // Pinned because a later pass has to know which `PATH` the child gets:
        // resolving a binary against `exec_path` while the child runs with a
        // different `PATH` would show the reader the wrong binary.
        let mut config = Config {
            exec_path: "/from/exec_path".to_string(),
            ..Config::default()
        };
        config.exec_env.insert("PATH".to_string(), "/from/exec_env".to_string());
        assert_eq!(
            build_child_env(&config).get("PATH").map(String::as_str),
            Some("/from/exec_env"),
            "exec_env is layered on top of exec_path, so it wins"
        );
    }
}
