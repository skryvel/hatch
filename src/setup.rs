//! `hatch setup`: what a person needs in order to finish an install, printed
//! rather than applied.
//!
//! Two topics. `hatch setup mcp` is the registration a client needs, and
//! `hatch setup polkit` is the drop-in a root command needs. They are the two
//! steps people get wrong, and the failure of each is quiet: a client that
//! never connects, and a root path with one gate where the security argument
//! says there are two. `hatch token` stays what it is — the short path for
//! someone who wants the line and nothing around it; this is the long path,
//! for someone who has not done it before.
//!
//! **It prints and does not write.** Nothing here edits a client's
//! configuration or installs a policy file, and nothing here offers to. A tool
//! whose entire purpose is to put a person in front of a privileged action
//! before it happens has no business quietly rewriting files under that
//! person's home directory, still less under `/etc`. A registration the user
//! pasted is one the user knows about. The cost is a copy and a paste, which
//! is the same cost the rest of hatch charges, for the same reason.
//!
//! **It reports observations, not conclusions.** What is cheap to look at
//! from here is cheap precisely because it is shallow: whether a port accepts
//! a connection, what mode a file is at, whether a file exists and contains a
//! string. None of those answers the question a reader actually has, which is
//! "does this work", and the output says so in as many words rather than
//! letting a tick stand in for it. A port that accepts a connection is a port
//! something is holding, not proof that the something is hatch. A file at the
//! polkit path is a file, not a rule in effect.
//!
//! **It runs nothing privileged.** The only real test of the polkit drop-in
//! is two root commands five seconds apart, and hatch will not run them: the
//! test *is* the password dialog, and a tool that threw one on the user's
//! desktop to answer its own diagnostic would be training them to dismiss the
//! exact prompt that is protecting them.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use crate::config::{self, Config};
use crate::exec::elevate::Run0;
use crate::paths::Paths;

/// How long the port probe waits before giving up.
///
/// Loopback answers or refuses immediately, so this is not a latency budget;
/// it is a ceiling on how long a diagnostic may hang when something strange —
/// a local firewall dropping rather than rejecting — makes a connection
/// neither succeed nor fail. A probe that hung would turn a help command into
/// something the user has to interrupt.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// The mode the config file must be at, and the mode hatch puts it back to on
/// every load. It holds the bearer token.
const PRIVATE_MODE: u32 = 0o600;

/// Where the drop-in goes.
///
/// The number matters as much as the name. polkit reads `rules.d` in lexical
/// order and a later file wins, so a rule in the forties sits ahead of
/// anything a distribution ships in the fifties and behind a local override
/// somebody deliberately numbered higher.
const POLKIT_RULE_PATH: &str = "/etc/polkit-1/rules.d/49-hatch-run0.rules";

/// The topics `hatch setup` knows, one entry each.
///
/// Printed for a bare `hatch setup` and again for a topic that does not
/// exist, because in both cases the reader's next question is the same one.
/// Written a line at a time rather than as one literal with `\` continuations.
/// A continuation eats the leading whitespace of the line after it, which had
/// this list printing its first entry two columns left of its second.
const TOPICS: &str = concat!(
    "  mcp       Register a running hatch with an MCP client: the line to paste,\n",
    "            the same registration as JSON, the tool timeout the client needs,\n",
    "            and what hatch can and cannot check from its own side.\n",
    "\n",
    "  polkit    The drop-in that keeps the polkit password dialog a second gate on\n",
    "            root commands rather than a cached one, and the only test that\n",
    "            shows whether it took effect.",
);

// ---- what a check saw ------------------------------------------------------

/// What was seen at the config file **before** this command loaded it.
///
/// Before, deliberately. Loading the config creates it if it is absent and
/// tightens it to 0600 if it is not, so a check made afterwards could only
/// ever report success, and would be a tick next to something nobody looked
/// at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCheck {
    /// Nothing was there. Loading created it, at 0600.
    Absent,
    /// A file was there, at this mode — the permission bits only.
    Found { mode: u32 },
    /// A file was there and could not be looked at.
    Unreadable { why: String },
}

/// What was seen at the configured port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortCheck {
    /// A connection was accepted. Something holds the port. *Something* is as
    /// far as this goes — see the module docs.
    Accepted,
    /// The connection was refused: nothing is listening there.
    Refused,
    /// Neither, and this is why.
    Unclear { why: String },
}

/// What was seen at the polkit drop-in's path.
///
/// [`RuleCheck::Unreadable`] is not an error case here; on most systems it is
/// the *ordinary* one. `/etc/polkit-1/rules.d` is commonly readable only by
/// root, and reporting "no rule" to a user who has one installed would be
/// worse than reporting nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleCheck {
    /// A file is there and the action id appears in it.
    NamesAction,
    /// A file is there and the action id does not appear in it.
    Silent,
    /// No file is there.
    Absent,
    /// The path could not be read, and this is why.
    Unreadable { why: String },
}

// ---- the topics ------------------------------------------------------------

/// Print the topic list for a bare `hatch setup`.
pub fn list() -> anyhow::Result<()> {
    println!("Usage: hatch setup <topic>\n\n{TOPICS}");
    Ok(())
}

/// Fail a `hatch setup <something else>` by naming the topics that exist.
///
/// An unknown topic is an error and exits non-zero — but the message is the
/// list, not a bare refusal. Someone who guessed the wrong word wants to be
/// told the right one.
pub fn unknown(words: &[String]) -> anyhow::Result<()> {
    let asked = words.first().map(String::as_str).unwrap_or("");
    anyhow::bail!(
        "hatch setup has no topic named `{asked}`.\n\nUsage: hatch setup <topic>\n\n{TOPICS}"
    )
}

/// Print everything needed to register a running hatch with an MCP client.
pub fn mcp() -> anyhow::Result<()> {
    let paths = Paths::from_env()?;
    paths.report();

    let file = paths.config_file();
    // Look before loading: `load_or_create` is what creates the file and what
    // tightens its mode, so this is the last moment the earlier state exists.
    let config_check = check_config(&file);
    let config = Config::load_or_create(&paths)?;
    let port_check = check_port(config.port);

    print!("{}", mcp_page(&config, &file, &config_check, &port_check));
    Ok(())
}

/// Print the polkit drop-in, how to check it, and what it costs.
///
/// Nothing here reads the config or touches the daemon: the drop-in is a
/// property of the machine, not of a hatch instance, and this has to be
/// useful to someone whose daemon will not start.
pub fn polkit() -> anyhow::Result<()> {
    print!("{}", polkit_page(&check_rule(Path::new(POLKIT_RULE_PATH), Run0::POLKIT_ACTION)));
    Ok(())
}

// ---- the checks ------------------------------------------------------------

/// Look at the config file without changing it.
pub fn check_config(path: &Path) -> ConfigCheck {
    match std::fs::metadata(path) {
        // The permission bits alone. `mode()` carries the file type in its
        // high bits, and printing those would hand the reader a number that
        // looks nothing like what `ls -l` or `chmod` talks in.
        Ok(meta) => ConfigCheck::Found { mode: meta.permissions().mode() & 0o777 },
        Err(e) if e.kind() == ErrorKind::NotFound => ConfigCheck::Absent,
        Err(e) => ConfigCheck::Unreadable { why: e.to_string() },
    }
}

/// Ask the configured port whether anything is there, by connecting to it and
/// immediately letting go.
///
/// A connect and a close rather than an MCP handshake. A handshake would
/// answer the better question — is this hatch, and does it hold this token —
/// but it would answer it by making a request, and the cheap honest answer is
/// worth more here than an expensive dishonest one: a probe that spoke MCP at
/// a stranger's port would be handing this machine's bearer token to whatever
/// is holding it.
pub fn check_port(port: u16) -> PortCheck {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        Ok(_) => PortCheck::Accepted,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => PortCheck::Refused,
        Err(e) => PortCheck::Unclear { why: e.to_string() },
    }
}

/// Look for `action` in the file at `path`.
///
/// A substring match on a text file, which is the whole of what it claims. It
/// cannot tell a rule from a comment mentioning one, it cannot parse the
/// JavaScript, and it cannot know whether polkit has read the file since it
/// was written. Every one of those gaps is stated in the output rather than
/// papered over, because the shallow check is worth having and the impression
/// that it is a deep one is not.
pub fn check_rule(path: &Path, action: &str) -> RuleCheck {
    match std::fs::read_to_string(path) {
        Ok(text) if text.contains(action) => RuleCheck::NamesAction,
        Ok(_) => RuleCheck::Silent,
        Err(e) if e.kind() == ErrorKind::NotFound => RuleCheck::Absent,
        Err(e) => RuleCheck::Unreadable { why: e.to_string() },
    }
}

// ---- turning a check into a sentence ---------------------------------------

/// The sentence the port probe earns, and no more than that.
fn port_sentence(port: u16, check: &PortCheck) -> String {
    match check {
        PortCheck::Accepted => format!(
            "Checked just now: something is listening on 127.0.0.1:{port} and accepted a\n   \
             connection. That is all a port check can say. It does not establish that the\n   \
             listener is hatch — any program on this machine can hold that port — and\n   \
             hatch did not send the token to find out."
        ),
        PortCheck::Refused => format!(
            "Checked just now: nothing is listening on 127.0.0.1:{port}. The connection was\n   \
             refused, so nothing a client sends to that address arrives. Start the daemon,\n   \
             or check that the one already running is serving the port this config names."
        ),
        PortCheck::Unclear { why } => format!(
            "Checked just now: 127.0.0.1:{port} neither accepted nor refused a connection.\n   \
             Reason: {why}\n   \
             Nothing follows from that either way."
        ),
    }
}

/// The sentence the config-file check earns.
fn config_sentence(check: &ConfigCheck) -> String {
    match check {
        ConfigCheck::Absent => "Checked just now: no config file was there. Loading it created one, at 0600,\n   \
             and the token below is the one now on disk."
            .to_string(),
        ConfigCheck::Found { mode } if *mode == PRIVATE_MODE => {
            "Checked just now: present, and 0600, so no other local user can read the token\n   \
             out of it."
                .to_string()
        }
        ConfigCheck::Found { mode } => format!(
            "Checked just now: present, but at {mode:04o} rather than 0600 — other users on\n   \
             this machine could read the token out of it, and the token is the whole of\n   \
             what it takes to queue a request. hatch put it back to 0600 as it loaded it.\n   \
             Anyone who read it in the meantime still has it: if that is possible, delete\n   \
             the token line and let the next start write a new one."
        ),
        ConfigCheck::Unreadable { why } => format!(
            "Checked just now: the config file could not be examined.\n   \
             Reason: {why}\n   \
             Its mode is therefore unknown, and so is whether another local user can read\n   \
             the token out of it."
        ),
    }
}

/// The sentence the polkit-path check earns.
fn rule_sentence(check: &RuleCheck) -> String {
    match check {
        RuleCheck::NamesAction => "Checked just now: a file exists at that path and the action id appears in it.\n   \
             That is a substring match on a text file and nothing more — it does not mean\n   \
             the rule is in effect. See below."
            .to_string(),
        RuleCheck::Silent => format!(
            "Checked just now: a file exists at that path, but the action id does not\n   \
             appear anywhere in it:\n   \
             {}\n   \
             Whatever that file is, it is not this rule.",
            Run0::POLKIT_ACTION
        ),
        RuleCheck::Absent => "Checked just now: no file exists at that path. The rule can live in another\n   \
             file in the same directory, so this is not proof that it is missing — but if\n   \
             you have not put one somewhere else, root commands are behind one gate."
            .to_string(),
        RuleCheck::Unreadable { why } => format!(
            "Checked just now: that path could not be read.\n   \
             Reason: {why}\n   \
             On most systems the rules directory is readable only by root, so this is the\n   \
             ordinary result and it says nothing either way."
        ),
    }
}

// ---- the pages -------------------------------------------------------------

/// Indent every non-empty line of `text` by `pad`.
///
/// Empty lines are left empty rather than padded: trailing spaces on a blank
/// line survive a copy and a paste into places that mind about them.
fn indent(text: &str, pad: &str) -> String {
    text.lines()
        .map(|line| if line.is_empty() { String::new() } else { format!("{pad}{line}") })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The polkit drop-in, with the action id taken from the elevation path
/// rather than written out again here.
///
/// [`Run0::POLKIT_ACTION`] is the authority because it is the action `run0`
/// actually authenticates against. A second copy of that string in this file
/// could drift from it, and a drifted action id is a rule that matches
/// nothing, installed by a user who now believes they have two gates.
pub fn polkit_rule() -> String {
    format!(
        "polkit.addRule(function(action, subject) {{\n    \
         if (action.id == \"{}\") {{\n        \
         return polkit.Result.AUTH_ADMIN;\n    \
         }}\n\
         }});",
        Run0::POLKIT_ACTION
    )
}

/// The whole of what `hatch setup mcp` prints, as one string.
///
/// A string rather than a run of `println!`s so that the output is a value a
/// test can read. Every number in it comes from `config`; none is written out
/// here.
pub fn mcp_page(
    config: &Config,
    config_file: &Path,
    config_check: &ConfigCheck,
    port_check: &PortCheck,
) -> String {
    let mut out = String::new();
    let seconds = config.client_timeout_secs();

    out.push_str(
        "Registering hatch with an MCP client\n\
         \n\
         This command prints. It changes nothing, and it will not offer to edit your\n\
         client's configuration for you: a tool that exists to put a person in front of\n\
         a privileged action should not be writing files in that person's home\n\
         directory unasked. You paste these, and so you know they happened.\n\
         \n",
    );

    let _ = write!(
        out,
        "1. The daemon has to be running\n\
         \n   \
         Start it outside the sandbox, as your ordinary user:\n\
         \n       \
         hatch serve\n\
         \n   \
         {}\n\
         \n   \
         Config file: {}\n   \
         {}\n\
         \n",
        port_sentence(config.port, port_check),
        config_file.display(),
        config_sentence(config_check),
    );

    let _ = write!(
        out,
        "2. Register the server with the client\n\
         \n   \
         As a command — this is the line `hatch token` prints:\n\
         \n{}\n\
         \n   \
         As a file, for a client configured through `.mcp.json` or its equivalent.\n   \
         The entry goes under `mcpServers`, and the type is not optional: a client\n   \
         that finds a url with no type beside it reads the entry as a stdio server\n   \
         and skips it, which fails as a server that never appears.\n\
         \n{}\n\
         \n   \
         Both carry the same URL and the same token. Use one of them, not both.\n\
         \n",
        indent(&config::client_line(config), "       "),
        indent(&config::client_json(config), "       "),
    );

    let _ = write!(
        out,
        "3. Raise the client's MCP tool timeout to at least {seconds} seconds\n\
         \n   \
         One call blocks for the approval wait, then for the command's own run, and\n   \
         then, if you chose to read its output before the agent gets it, for that:\n   \
         {}s to decide plus {}s to run plus {}s to review, so {seconds}s in all.\n   \
         Claude Code takes this from MCP_TOOL_TIMEOUT, in milliseconds — {}. Its\n   \
         default for an HTTP server is well under what hatch needs.\n\
         \n   \
         Set it too low and the client gives up first. Three things happen at once:\n   \
         the agent gets an opaque transport failure instead of a clean allowed or\n   \
         denied verdict, so it cannot tell a refusal from a broken connection; the\n   \
         approval window you are part way through reading is orphaned, because\n   \
         nothing is waiting any more for the answer you are about to give; and the\n   \
         request is recorded as a denial, since a dropped connection closes the\n   \
         window the same way a cancellation does.\n\
         \n",
        config.timeout_secs,
        config.exec_timeout_secs,
        config.review_timeout_secs(),
        seconds * 1000,
    );

    out.push_str(
        "What this command did not check\n\
         \n   \
         Whether your MCP client is installed, whether it accepted the registration,\n   \
         and whether a call from it ever reaches this machine. None of that is\n   \
         visible from here, and the port check above is not a stand-in for it. The\n   \
         way to find out is to ask the agent for something harmless and watch for\n   \
         the approval window.\n\
         \n   \
         Root commands need one more thing, which is not on this page and is not\n   \
         optional if you use them: see `hatch setup polkit`.\n",
    );

    out
}

/// The whole of what `hatch setup polkit` prints, as one string.
///
/// The install step is an editor and not a `sudo tee ... <<'RULE'` one-liner,
/// which is the obvious thing to reach for and the wrong one here. A heredoc
/// shown inside an indented block is copied with its terminator indented, and
/// an indented terminator does not terminate: the shell keeps reading. The
/// step where that lands somebody is the one that ends with a half-written
/// policy file, so this page does not carry a heredoc and should not grow one.
pub fn polkit_page(check: &RuleCheck) -> String {
    let mut out = String::new();

    out.push_str(
        "The polkit drop-in, for root commands\n\
         \n\
         This command prints. It installs nothing, and it does not run run0 to find\n\
         out whether the rule works: that check *is* a password dialog, and a tool\n\
         that threw one onto your desktop to answer its own question would be\n\
         teaching you to dismiss the prompt that is protecting you.\n\
         \n",
    );

    let _ = write!(
        out,
        "1. Why it is needed\n\
         \n   \
         hatch's approval window is one gate. The polkit password dialog is meant\n   \
         to be a second, independent one, and it only fires if polkit is asked\n   \
         afresh every time. run0 authenticates against\n   \
         {action}, which systemd ships as\n   \
         auth_admin_keep — polkit caches that authorisation for the session. So a\n   \
         second root command inside the cache window runs with no password prompt\n   \
         at all. hatch's window is then the only gate on root, and nothing on\n   \
         screen says so. A user who skips this gets a tool that looks like it is\n   \
         working.\n\
         \n",
        action = Run0::POLKIT_ACTION,
    );

    let _ = write!(
        out,
        "2. The rule\n\
         \n   \
         File: {path}\n\
         \n{rule}\n\
         \n   \
         Write it as root, with an editor:\n\
         \n       \
         run0 $EDITOR {path}\n\
         \n   \
         Leave the file world readable, 0644. polkit reads it as its own user and\n   \
         skips one it cannot open, which fails as a rule that is there and does\n   \
         nothing.\n\
         \n   \
         (Deliberately not a heredoc. One pasted out of an indented block carries\n   \
         an indented terminator, which does not terminate.)\n\
         \n   \
         {seen}\n\
         \n",
        path = POLKIT_RULE_PATH,
        rule = indent(&polkit_rule(), "       "),
        seen = rule_sentence(check),
    );

    out.push_str(
        "3. The only check that means anything\n\
         \n       \
         run0 true; sleep 5; run0 true\n\
         \n   \
         This must ask for a password twice. Twice means polkit is being asked\n   \
         afresh and the second gate is real. Once means the rule is not in effect\n   \
         and your root operations have one gate instead of two, whatever the file\n   \
         at that path says.\n\
         \n   \
         Run it yourself, at a moment you choose. That is the whole verification.\n\
         \n",
    );

    out.push_str(
        "4. What the rule costs\n\
         \n   \
         That action is the one systemctl uses. With the drop-in in place,\n   \
         systemctl start, stop and restart on system units ask for a password\n   \
         every single time, for every user on this machine, instead of caching for\n   \
         a few minutes. Nothing narrows it to hatch: polkit rules are matched on\n   \
         the action, not on who is asking.\n\
         \n   \
         That is the price of the second factor. It is worth paying knowingly\n   \
         rather than discovering tomorrow.\n\
         \n",
    );

    out.push_str(
        "What this command did not check\n\
         \n   \
         Whether the rule is in effect. A file at that path is not an effective\n   \
         rule: another file in the same directory can override it, since they are\n   \
         read in lexical order and a later one wins; the JavaScript can be\n   \
         malformed, in which case polkit skips it; and polkit may not have reloaded\n   \
         since the file was written. hatch cannot ask polkit whether it would have\n   \
         cached an authorisation, and the two prompts above are the only thing that\n   \
         answers the question.\n",
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A config with a port and a token a test can look for, and the timeouts
    /// a user gets by default.
    fn config() -> Config {
        Config { port: 8787, token: "a-test-token".to_string(), ..Config::default() }
    }

    /// The MCP page for a config, with both checks in their ordinary state.
    fn page_for(config: &Config) -> String {
        mcp_page(
            config,
            Path::new("/config/hatch/config.toml"),
            &ConfigCheck::Found { mode: 0o600 },
            &PortCheck::Accepted,
        )
    }

    /// `text` with every run of whitespace collapsed to a single space.
    ///
    /// The wrapping on these pages is done by hand and is its own test. A test
    /// about what a page *says* should not fail the day a sentence is rewrapped
    /// a word earlier, so prose is searched flat and layout is searched
    /// separately.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The JSON block inside a page: from its first brace to its last.
    ///
    /// The extraction is itself a claim — that the page has no other braces —
    /// and `the_mcp_page_has_no_braces_but_the_json` is what holds that claim
    /// up, so a stray brace in the prose fails there rather than quietly
    /// corrupting every other test.
    fn json_block(page: &str) -> serde_json::Value {
        let start = page.find('{').expect("the page must carry a JSON block");
        let end = page.rfind('}').expect("the page must carry a JSON block");
        serde_json::from_str(&page[start..=end]).expect("the JSON block must parse")
    }

    // ---- the two spellings of the registration ---------------------------

    #[test]
    fn the_json_form_carries_the_same_url_and_token_as_the_command_form() {
        // The whole risk of printing a registration twice is that the two
        // drift and the user pastes the stale one. They are built from one
        // config, and this is what says they stayed that way.
        let config = config();
        let page = page_for(&config);
        let json = json_block(&page);

        let entry = &json["mcpServers"]["hatch"];
        assert_eq!(entry["url"], "http://127.0.0.1:8787/mcp");
        assert_eq!(entry["headers"]["Authorization"], "Bearer a-test-token");

        let line = config::client_line(&config);
        assert!(line.contains("http://127.0.0.1:8787/mcp"), "{line}");
        assert!(line.contains("Authorization: Bearer a-test-token"), "{line}");
    }

    #[test]
    fn the_json_entry_names_its_transport() {
        // A url with no type beside it is read as a stdio server and skipped,
        // so an entry missing this is one that silently never loads.
        let json = json_block(&page_for(&config()));
        assert_eq!(json["mcpServers"]["hatch"]["type"], "http");
    }

    #[test]
    fn the_mcp_page_prints_the_line_hatch_token_prints_and_not_a_second_rendering() {
        // `hatch token` is the short path and this is the long one; a user who
        // ran both and got two different lines would not know which is live.
        let config = config();
        let page = page_for(&config);
        // Indented as a block, and otherwise character for character the line
        // `hatch token` prints.
        assert!(page.contains(&indent(&config::client_line(&config), "       ")), "{page}");
    }

    #[test]
    fn the_mcp_page_has_no_braces_but_the_json() {
        // Holds up `json_block`.
        let page = page_for(&config());
        let json = config::client_json(&config());
        assert_eq!(page.matches('{').count(), json.matches('{').count(), "{page}");
        assert_eq!(page.matches('}').count(), json.matches('}').count(), "{page}");
    }

    #[test]
    fn the_port_in_both_forms_follows_the_config() {
        let config = Config { port: 9191, ..config() };
        let page = page_for(&config);
        assert_eq!(json_block(&page)["mcpServers"]["hatch"]["url"], "http://127.0.0.1:9191/mcp");
        assert!(flat(&page).contains("http://127.0.0.1:9191/mcp"), "{page}");
        assert!(!flat(&page).contains("8787"), "no other port may appear: {page}");
    }

    // ---- the timeout -----------------------------------------------------

    #[test]
    fn the_timeout_is_the_sum_of_the_configured_waits_and_not_a_number_in_the_text() {
        // Raise every term away from its default. A page still carrying 1500
        // after this is a page with the default written into its prose.
        let config = Config { timeout_secs: 1200, exec_timeout_secs: 600, ..config() };
        let page = page_for(&config);

        assert!(flat(&page).contains("at least 3000 seconds"), "{page}");
        assert!(
            flat(&page).contains("1200s to decide plus 600s to run plus 1200s to review"),
            "{page}"
        );
        assert!(flat(&page).contains("so 3000s in all"), "{page}");
        assert!(!flat(&page).contains("1500"), "the default must not survive a raised config: {page}");
    }

    #[test]
    fn the_default_config_asks_for_twenty_five_minutes_in_seconds_and_in_milliseconds() {
        // The number a reader pastes into their client, in the unit the client
        // wants it in. A wrong conversion here is a client that gives up after
        // fifteen hundred milliseconds.
        let page = page_for(&config());
        assert!(flat(&page).contains("at least 1500 seconds"), "{page}");
        assert!(flat(&page).contains("MCP_TOOL_TIMEOUT, in milliseconds — 1500000"), "{page}");
    }

    #[test]
    fn the_mcp_page_says_what_a_client_giving_up_early_costs() {
        let page = page_for(&config());
        assert!(flat(&page).contains("opaque transport failure"), "{page}");
        assert!(flat(&page).contains("orphaned"), "{page}");
        assert!(flat(&page).contains("recorded as a denial"), "{page}");
    }

    // ---- what the checks do and do not claim -----------------------------

    #[test]
    fn a_listening_port_is_reported_as_something_listening_and_not_as_hatch_running() {
        // The one claim this command is most tempted to overstate.
        let sentence = port_sentence(8787, &PortCheck::Accepted);
        assert!(flat(&sentence).contains("something is listening on 127.0.0.1:8787"), "{sentence}");
        assert!(flat(&sentence).contains("does not establish that the listener is hatch"), "{sentence}");
        for overclaim in ["hatch is running", "hatch is listening", "all set"] {
            assert!(!flat(&sentence).contains(overclaim), "must not claim `{overclaim}`: {sentence}");
        }
    }

    #[test]
    fn a_refused_port_says_nothing_is_there_rather_than_that_hatch_is_stopped() {
        let sentence = port_sentence(8787, &PortCheck::Refused);
        assert!(flat(&sentence).contains("nothing is listening on 127.0.0.1:8787"), "{sentence}");
        assert!(flat(&sentence).contains("refused"), "{sentence}");
    }

    #[test]
    fn a_probe_that_neither_connected_nor_was_refused_concludes_nothing() {
        let why = "a firewall ate it";
        let sentence = port_sentence(8787, &PortCheck::Unclear { why: why.to_string() });
        assert!(flat(&sentence).contains(why), "the reason must reach the reader: {sentence}");
        assert!(flat(&sentence).contains("Nothing follows from that"), "{sentence}");
    }

    #[test]
    fn the_mcp_page_names_what_it_could_not_check() {
        let page = page_for(&config());
        assert!(flat(&page).contains("What this command did not check"), "{page}");
        assert!(flat(&page).contains("whether it accepted the registration"), "{page}");
        assert!(flat(&page).contains("hatch setup polkit"), "root's second gate is elsewhere: {page}");
    }

    #[test]
    fn the_mcp_page_says_it_does_not_write_the_clients_configuration() {
        let page = page_for(&config());
        assert!(flat(&page).contains("It changes nothing"), "{page}");
        assert!(flat(&page).contains("will not offer to edit your"), "{page}");
    }

    // ---- the config-file check -------------------------------------------

    #[test]
    fn a_config_at_0600_is_reported_as_readable_by_nobody_else() {
        let sentence = config_sentence(&ConfigCheck::Found { mode: 0o600 });
        assert!(flat(&sentence).contains("present, and 0600"), "{sentence}");
    }

    #[test]
    fn a_lax_config_is_named_with_the_mode_it_was_actually_found_at() {
        // The mode has to be the one on disk, not a description of one: a
        // reader checking by hand needs the two to match.
        let sentence = config_sentence(&ConfigCheck::Found { mode: 0o644 });
        assert!(flat(&sentence).contains("at 0644 rather than 0600"), "{sentence}");
        assert!(flat(&sentence).contains("put it back to 0600"), "{sentence}");
    }

    #[test]
    fn a_config_that_was_not_there_is_reported_as_created_by_this_command() {
        let sentence = config_sentence(&ConfigCheck::Absent);
        assert!(flat(&sentence).contains("no config file was there"), "{sentence}");
        assert!(flat(&sentence).contains("created one, at 0600"), "{sentence}");
        // Not "with a fresh token": on a first-run race another process's token
        // can be the one that reached disk, and the one on disk is the live one.
        assert!(flat(&sentence).contains("the token below is the one now on disk"), "{sentence}");
    }

    #[test]
    fn a_config_that_could_not_be_examined_says_so_rather_than_assuming_0600() {
        let sentence = config_sentence(&ConfigCheck::Unreadable { why: "denied".to_string() });
        assert!(flat(&sentence).contains("denied"), "{sentence}");
        assert!(flat(&sentence).contains("Its mode is therefore unknown"), "{sentence}");
        assert!(!flat(&sentence).contains("present, and 0600"), "{sentence}");
    }

    #[test]
    fn check_config_reads_the_mode_off_the_file_and_absence_off_its_absence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        assert_eq!(check_config(&file), ConfigCheck::Absent);

        std::fs::write(&file, "port = 1\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(check_config(&file), ConfigCheck::Found { mode: 0o644 });

        // The permission bits only: `mode()` carries the file type above them,
        // and a reader given that number could not compare it with `ls -l`.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check_config(&file), ConfigCheck::Found { mode: 0o600 });
    }

    // ---- the port check --------------------------------------------------

    #[test]
    fn check_port_sees_a_held_port_and_then_sees_it_released() {
        // Both directions against one port, in order: a probe that always said
        // `Accepted` would pass the first half on its own.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(check_port(port), PortCheck::Accepted);

        drop(listener);
        assert_eq!(check_port(port), PortCheck::Refused);
    }

    // ---- the polkit rule -------------------------------------------------

    #[test]
    fn the_rule_names_the_action_the_elevation_path_actually_authenticates_against() {
        // The point of the whole drop-in. An action id written out a second
        // time here could drift from the one `run0` meets, and a rule matching
        // nothing is indistinguishable, from the desk, from a rule that works.
        let rule = polkit_rule();
        assert!(rule.contains(Run0::POLKIT_ACTION), "{rule}");
        assert!(polkit_page(&RuleCheck::Absent).contains(Run0::POLKIT_ACTION));
    }

    #[test]
    fn the_rule_is_well_formed_javascript_that_returns_auth_admin() {
        // Not a parse — polkit's JS is not something this crate can evaluate.
        // The shape, then: balanced braces, the callback polkit calls, and the
        // result that restores the prompt rather than one that grants it.
        let rule = polkit_rule();
        assert!(rule.starts_with("polkit.addRule(function(action, subject) {"), "{rule}");
        assert!(rule.contains("return polkit.Result.AUTH_ADMIN;"), "{rule}");
        assert!(rule.ends_with("});"), "{rule}");
        assert_eq!(rule.matches('{').count(), rule.matches('}').count(), "{rule}");
        assert_eq!(rule.matches('(').count(), rule.matches(')').count(), "{rule}");
        assert!(
            !rule.contains("AUTH_ADMIN_KEEP") && !rule.contains("Result.YES"),
            "a caching or granting result would remove the gate it is meant to restore: {rule}"
        );
    }

    #[test]
    fn the_rule_goes_where_polkit_reads_rules_from() {
        assert!(POLKIT_RULE_PATH.starts_with("/etc/polkit-1/rules.d/"), "{POLKIT_RULE_PATH}");
        assert!(POLKIT_RULE_PATH.ends_with(".rules"), "{POLKIT_RULE_PATH}");
        assert!(polkit_page(&RuleCheck::Absent).contains(POLKIT_RULE_PATH));
    }

    #[test]
    fn check_rule_tells_a_matching_file_from_a_silent_one_from_no_file_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("49-hatch-run0.rules");
        assert_eq!(check_rule(&file, Run0::POLKIT_ACTION), RuleCheck::Absent);

        std::fs::write(&file, "polkit.addRule(function() {});\n").unwrap();
        assert_eq!(check_rule(&file, Run0::POLKIT_ACTION), RuleCheck::Silent);

        std::fs::write(&file, polkit_rule()).unwrap();
        assert_eq!(check_rule(&file, Run0::POLKIT_ACTION), RuleCheck::NamesAction);
    }

    #[test]
    fn a_rules_directory_that_cannot_be_read_is_not_reported_as_a_missing_rule() {
        // The ordinary case on a real machine: `/etc/polkit-1/rules.d` is
        // root-only, so a user with the rule correctly installed gets this.
        // Telling them it is missing would be the worst answer available.
        let dir = tempfile::tempdir().unwrap();
        let closed = dir.path().join("rules.d");
        std::fs::create_dir(&closed).unwrap();
        std::fs::write(closed.join("49-hatch-run0.rules"), polkit_rule()).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let check = check_rule(&closed.join("49-hatch-run0.rules"), Run0::POLKIT_ACTION);

        // Root ignores the mode, so on a root test runner this is readable and
        // the case under test cannot be produced. Both outcomes are named
        // rather than the test passing vacuously.
        match check {
            RuleCheck::Unreadable { .. } => {
                let sentence = rule_sentence(&check);
                assert!(flat(&sentence).contains("readable only by root"), "{sentence}");
                assert!(flat(&sentence).contains("says nothing either way"), "{sentence}");
            }
            other => assert_eq!(other, RuleCheck::NamesAction, "running as root, presumably"),
        }

        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_file_that_names_the_action_is_still_not_called_installed_or_working() {
        let sentence = rule_sentence(&RuleCheck::NamesAction);
        assert!(flat(&sentence).contains("substring match"), "{sentence}");
        assert!(flat(&sentence).contains("does not mean"), "{sentence}");
        for overclaim in ["correctly installed", "all set", "is installed"] {
            assert!(!flat(&sentence).contains(overclaim), "must not claim `{overclaim}`: {sentence}");
        }
        // And the one phrase it does contain, it contains under a negation.
        assert!(flat(&sentence).contains("does not mean the rule is in effect"), "{sentence}");
    }

    #[test]
    fn a_missing_file_does_not_claim_the_rule_is_missing_from_the_machine() {
        // A rule numbered differently, or shipped by a distribution, is a rule
        // this check never looks at.
        let sentence = rule_sentence(&RuleCheck::Absent);
        assert!(flat(&sentence).contains("no file exists at that path"), "{sentence}");
        assert!(flat(&sentence).contains("not proof that it is missing"), "{sentence}");
    }

    #[test]
    fn the_polkit_page_carries_the_acceptance_test_and_calls_it_the_verification() {
        let page = polkit_page(&RuleCheck::Absent);
        assert!(flat(&page).contains("run0 true; sleep 5; run0 true"), "{page}");
        assert!(flat(&page).contains("must ask for a password twice"), "{page}");
        assert!(flat(&page).contains("The only check that means anything"), "{page}");
    }

    #[test]
    fn the_polkit_page_says_hatch_will_not_run_the_acceptance_test_itself() {
        let page = polkit_page(&RuleCheck::Absent);
        assert!(flat(&page).contains("it does not run run0"), "{page}");
        assert!(flat(&page).contains("Run it yourself"), "{page}");
    }

    #[test]
    fn the_polkit_page_states_the_cost_to_everything_else_on_the_machine() {
        let page = polkit_page(&RuleCheck::Absent);
        assert!(flat(&page).contains("systemctl"), "{page}");
        assert!(flat(&page).contains("every user on this machine"), "{page}");
        assert!(flat(&page).contains("instead of caching"), "{page}");
    }

    #[test]
    fn the_polkit_page_names_the_three_ways_a_present_file_can_still_do_nothing() {
        let page = polkit_page(&RuleCheck::NamesAction);
        assert!(flat(&page).contains("lexical order"), "override: {page}");
        assert!(flat(&page).contains("malformed"), "unparseable: {page}");
        assert!(flat(&page).contains("not have reloaded"), "not reloaded: {page}");
    }

    #[test]
    fn the_polkit_page_explains_the_cached_authorisation_it_exists_to_prevent() {
        let page = polkit_page(&RuleCheck::Absent);
        assert!(flat(&page).contains("auth_admin_keep"), "{page}");
        assert!(flat(&page).contains("no password prompt"), "{page}");
        assert!(flat(&page).contains("only gate on root"), "{page}");
    }

    // ---- the topic list --------------------------------------------------

    #[test]
    fn an_unknown_topic_fails_by_naming_the_topics_that_exist() {
        let error = unknown(&["mpc".to_string()]).expect_err("an unknown topic is an error");
        let message = format!("{error}");
        assert!(message.contains("no topic named `mpc`"), "{message}");
        assert!(message.contains("mcp"), "the list is the message: {message}");
        assert!(message.contains("polkit"), "the list is the message: {message}");
    }

    #[test]
    fn an_empty_topic_still_gets_the_list_rather_than_a_panic() {
        let error = unknown(&[]).expect_err("an unknown topic is an error");
        assert!(format!("{error}").contains("mcp"));
    }

    #[test]
    fn every_line_of_the_topic_list_is_indented_under_the_same_two_columns() {
        // A `\` continuation in the literal ate the first entry's indent once
        // and printed it two columns left of the second. Nothing but this
        // notices: the text was all there and every `contains` still passed.
        for line in TOPICS.lines().filter(|line| !line.is_empty()) {
            assert!(line.starts_with("  "), "not indented: {line:?}");
            assert_eq!(line, line.trim_end(), "trailing whitespace: {line:?}");
            assert!(line.chars().count() <= 88, "{} chars: {line}", line.chars().count());
        }
        for name in ["mcp", "polkit"] {
            let entry = TOPICS
                .lines()
                .find(|line| line.trim_start().starts_with(name))
                .unwrap_or_else(|| panic!("`{name}` must be listed"));
            let (label, description) = entry.split_at(12);
            assert_eq!(label.trim(), name, "the name sits in the first column: {entry:?}");
            assert!(!description.starts_with(' '), "descriptions must line up: {entry:?}");
        }
    }

    #[test]
    fn the_topic_list_describes_each_topic_rather_than_only_naming_it() {
        assert!(TOPICS.contains("mcp"), "{TOPICS}");
        assert!(TOPICS.contains("MCP client"), "{TOPICS}");
        assert!(TOPICS.contains("polkit"), "{TOPICS}");
        assert!(TOPICS.contains("root"), "{TOPICS}");
    }

    // ---- the shape of both pages -----------------------------------------

    /// Both pages, in every state a check can be in.
    fn every_page() -> Vec<String> {
        let mut pages = Vec::new();
        let config = Config { token: "x".repeat(43), ..config() };
        for config_check in [
            ConfigCheck::Absent,
            ConfigCheck::Found { mode: 0o600 },
            ConfigCheck::Found { mode: 0o644 },
            ConfigCheck::Unreadable { why: "Permission denied (os error 13)".to_string() },
        ] {
            for port_check in [
                PortCheck::Accepted,
                PortCheck::Refused,
                PortCheck::Unclear { why: "Connection timed out (os error 110)".to_string() },
            ] {
                pages.push(mcp_page(
                    &config,
                    Path::new("/home/somebody/.config/hatch/config.toml"),
                    &config_check,
                    &port_check,
                ));
            }
        }
        for rule_check in [
            RuleCheck::NamesAction,
            RuleCheck::Silent,
            RuleCheck::Absent,
            RuleCheck::Unreadable { why: "Permission denied (os error 13)".to_string() },
        ] {
            pages.push(polkit_page(&rule_check));
        }
        pages
    }

    #[test]
    fn every_page_ends_in_exactly_one_newline() {
        // They are printed with `print!`, so a page owns its own last newline
        // and must leave the prompt neither mid-line nor two lines down.
        for page in every_page() {
            assert!(page.ends_with('\n'), "must end a line: {page}");
            assert!(!page.ends_with("\n\n"), "and must not end a blank one: {page}");
        }
    }

    #[test]
    fn no_line_of_any_page_is_wider_than_a_narrow_terminal() {
        // Wrapping is by hand, so nothing but a test keeps it honest. A
        // 43-character token inside an indented line is what sets the ceiling.
        for page in every_page() {
            for line in page.lines() {
                assert!(line.chars().count() <= 88, "{} chars: {line}", line.chars().count());
            }
        }
    }

    #[test]
    fn no_line_of_any_page_carries_trailing_whitespace() {
        for page in every_page() {
            for line in page.lines() {
                assert_eq!(line, line.trim_end(), "trailing whitespace: {line:?}");
            }
        }
    }

    #[test]
    fn the_mcp_page_shows_where_the_config_file_is() {
        let page = mcp_page(
            &config(),
            Path::new("/somewhere/else/config.toml"),
            &ConfigCheck::Absent,
            &PortCheck::Refused,
        );
        assert!(flat(&page).contains("/somewhere/else/config.toml"), "{page}");
    }

    #[test]
    fn indenting_pads_text_and_leaves_blank_lines_blank() {
        assert_eq!(indent("a\n\nb", ".."), "..a\n\n..b");
    }
}
