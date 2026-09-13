//! A unified diff, applied exactly where it says it applies.
//!
//! `swap_file` accepts either the complete new contents of a file or a patch
//! against the contents it has now, and this module is the whole of the second
//! form. What it produces is bytes. By the time anything else in hatch sees
//! the request — the plan, the diff on screen, the hash the write is checked
//! against, the bytes that land — a patch request and the equivalent
//! whole-file request are the same request, and nothing downstream can tell
//! them apart. The audit log is the one exception, and it records the
//! *encoding* rather than treating it as part of the operation, because which
//! form arrived is a fact about the request and the log is where facts about
//! requests live.
//!
//! # Why hatch applies it, here, before anybody is asked
//!
//! The property the whole tool rests on is that **what the person approves is
//! the bytes that land, never an instruction for producing them.** That is
//! what makes the drift check meaningful: hatch hashes the file when it draws
//! the window, hashes it again before it writes, and refuses if it moved,
//! because content composed against a version that no longer exists is not the
//! change the person read.
//!
//! A patch is compatible with that only as a *wire encoding*. Applied here, at
//! render time, against the bytes that are on disk now, it collapses into the
//! same `Vec<u8>` a `content` request would have carried, and every guarantee
//! downstream holds unchanged. Handed to the host instead — `patch -p1`, or
//! anything else that reads the file itself at write time — it would be an
//! instruction, the window would be showing a prediction, and the two reads of
//! the file would be a race nobody could see.
//!
//! # No fuzz, no searching, no partial application
//!
//! A hunk applies at the line its header names or the request is refused. The
//! context is compared byte for byte, at that offset, and hatch never looks
//! one line up or down for a better fit.
//!
//! This is the opposite of what `patch(1)` does by default, and deliberately.
//! Fuzz exists to salvage a patch against a file that has moved on, which is a
//! reasonable thing for a human at a terminal to want and exactly the wrong
//! thing here: a hunk that applied "nearly" has written bytes somewhere the
//! agent did not mean, into a file on the host, under an approval whose whole
//! subject was *where* the change goes. The failure is silent by construction
//! — the diff on screen would show the mis-applied result as if it had been
//! intended.
//!
//! Refusing costs an agent one round trip and a re-read. Hatch's refusals are
//! written to make that cheap: they name the hunk, the line of the file, what
//! the patch expected there and what is actually there.
//!
//! Nothing is ever half-applied. Every refusal returns `Err` and the caller
//! renders nothing, so there is no state to unwind; the "partial" failure mode
//! simply has nowhere to exist.
//!
//! # Why this is written out rather than taken from a crate
//!
//! The tree already has `similar`, which *produces* diffs and does not apply
//! them, so the choice was a new dependency or this file. Two things settled
//! it. The rule above is the entire security argument for the feature, and it
//! is a rule about what an applier must *refuse* to do — a library that fuzzes
//! by default would have to be proven not to, on every upgrade, from the
//! outside, and the proof would be tests indistinguishable from the ones
//! below. And the job is small: a unified diff is a line format with three
//! prefixes and one marker, and what follows is under three hundred lines of
//! code, most of it refusals with sentences attached.
//!
//! # What counts as a line
//!
//! Bytes, split on `\n`, terminators not included. A `\r` therefore belongs to
//! the line it ends, so a patch written against a CRLF file has to carry the
//! `\r` in its context — which is correct, because a swap that quietly
//! rewrote a file's line endings would be a change nobody approved. The file
//! never has to be valid UTF-8 to be patched; the patch itself is a JSON
//! string and so always is.
//!
//! A file whose last line has no terminator is the awkward case every diff
//! format has, and this one handles it the way `diff` does, with
//! `\ No newline at end of file` — required when it is true and refused when
//! it is not, in both directions. Guessing would mean adding or dropping a
//! byte at the end of a file without being told to.

use std::fmt;

use crate::render::unicode::defang;

/// How much of an offending line is quoted back, in characters.
///
/// A line can be as long as the patch, and a refusal that pasted a whole
/// minified file into the agent's context would punish it for a typo. Enough
/// to recognise the line by, and no more.
const QUOTE_CHARS: usize = 120;

/// The marker `diff` writes under a line that ends a file without a newline.
const NO_NEWLINE: &str = "\\ No newline at end of file";

/// Why a patch will not be applied, decided before any prompt is drawn.
///
/// Every variant is a message first and a control-flow value second, on the
/// same terms as [`crate::swap::Refusal`]: the [`fmt::Display`] text is a
/// fragment naming what happened, and the caller wraps it in the sentence that
/// says nothing was rendered, nobody was asked and nothing ran.
///
/// Line numbers come in two flavours and the wording always says which. A
/// *patch line* counts from one through the text the agent sent; a *file line*
/// counts from one through the file on disk. Confusing them is the fastest way
/// to send an agent looking in the wrong place, so no variant carries an
/// unlabelled number.
///
/// Every quoted string has been through [`defang`] and truncated to
/// [`QUOTE_CHARS`]. The patch is agent-written text that reaches an error
/// message and, through it, a log somewhere else; a newline in the wrong place
/// must not be able to forge a line of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// There is no `@@` header anywhere, so there is nothing to apply.
    NoHunks,
    /// Something before the first hunk that is not a diff header.
    NotADiff {
        /// Which line of the patch.
        line: usize,
        /// The line itself.
        text: String,
    },
    /// A line where a hunk header was expected that is not one.
    BadHeader {
        /// Which line of the patch.
        line: usize,
        /// The line itself.
        text: String,
    },
    /// A hunk that carries lines of the file but claims to start at line 0.
    ZeroStart {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the patch its header is on.
        line: usize,
    },
    /// A hunk header's counts and the hunk's body do not describe the same
    /// change.
    ///
    /// Refused rather than reconciled. The body decides the bytes and the
    /// header decides where they go, so a disagreement between them means
    /// hatch cannot tell which of the two the agent meant — and picking one is
    /// the guess this module exists not to make.
    HeaderDisagreesWithBody {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the patch its header is on.
        line: usize,
        /// Lines of the file the header claims.
        declared_old: usize,
        /// Lines of the replacement the header claims.
        declared_new: usize,
        /// Lines of the file the body carries.
        counted_old: usize,
        /// Lines of the replacement the body carries.
        counted_new: usize,
    },
    /// A `\ No newline at end of file` with no line above it to describe.
    StrayMarker {
        /// Which line of the patch.
        line: usize,
    },
    /// A `\ No newline at end of file` on the new side, followed by more of
    /// the new side.
    MarkerNotAtTheEnd {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the patch the marker is on.
        line: usize,
    },
    /// A `\ No newline at end of file` about a line of the file that either is
    /// not the last one or does end with a newline.
    NewlineMarkerIsWrong {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the patch the marker is on.
        line: usize,
        /// Which line of the file it claimed to describe.
        file_line: usize,
        /// How many lines the file has.
        file_lines: usize,
    },
    /// The patch consumed the last line of a file that does not end with a
    /// newline, and never said so.
    MissingNewlineMarker {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the file was consumed without the marker.
        file_line: usize,
    },
    /// A hunk that starts at or before where the hunk in front of it ended.
    OutOfOrder {
        /// Which hunk, counting from one.
        hunk: usize,
        /// The line of the file its header names.
        at: usize,
        /// The line of the file the previous hunk finished at.
        previous_end: usize,
    },
    /// A hunk that starts past the end of the file.
    PastTheEnd {
        /// Which hunk, counting from one.
        hunk: usize,
        /// The line of the file its header names.
        at: usize,
        /// How many lines the file has.
        file_lines: usize,
    },
    /// The context does not match, at the line the hunk says it does. The one
    /// refusal an honest agent will actually meet.
    DoesNotApply {
        /// Which hunk, counting from one.
        hunk: usize,
        /// Which line of the file did not match.
        file_line: usize,
        /// What the patch said is there.
        expected: String,
        /// What is there, or `None` when the file has no such line.
        found: Option<String>,
        /// How many lines the file has, for the `None` case.
        file_lines: usize,
    },
    /// A second file's headers after the first file's hunks.
    SecondFile {
        /// Which line of the patch.
        line: usize,
        /// The line itself.
        text: String,
    },
    /// Something after the last hunk that belongs to no hunk.
    Trailing {
        /// Which line of the patch.
        line: usize,
        /// The line itself.
        text: String,
    },
    /// The file the patch produces is over the cap.
    TooLarge {
        /// The cap, in bytes.
        cap: usize,
    },
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::NoHunks => f.write_str(
                "`patch` carries no `@@` hunk header, so there is nothing in it to apply; a \
                 patch is a unified diff, and to replace a file outright send `content` instead",
            ),
            PatchError::NotADiff { line, text } => write!(
                f,
                "line {line} of `patch`, `{text}`, comes before the first hunk and is not a diff \
                 header: send the diff itself, with no prose around it"
            ),
            PatchError::BadHeader { line, text } => write!(
                f,
                "line {line} of `patch`, `{text}`, is where a hunk header should be and is not \
                 one; a header reads `@@ -first,count +first,count @@`"
            ),
            PatchError::ZeroStart { hunk, line } => write!(
                f,
                "hunk {hunk}, at line {line} of `patch`, carries lines of the file but says it \
                 starts at line 0; a patch counts the lines of a file from one"
            ),
            PatchError::HeaderDisagreesWithBody {
                hunk,
                line,
                declared_old,
                declared_new,
                counted_old,
                counted_new,
            } => write!(
                f,
                "hunk {hunk}, at line {line} of `patch`, declares {declared_old} lines of the \
                 file and {declared_new} of the replacement, but carries {counted_old} and \
                 {counted_new}: hatch will not guess which of the two you meant. Count the ` ` \
                 and `-` lines for the first number and the ` ` and `+` lines for the second"
            ),
            PatchError::StrayMarker { line } => write!(
                f,
                "line {line} of `patch` is a `{NO_NEWLINE}` marker with no line above it for it \
                 to describe"
            ),
            PatchError::MarkerNotAtTheEnd { hunk, line } => write!(
                f,
                "hunk {hunk} puts a `{NO_NEWLINE}` marker at line {line} of `patch` and then \
                 carries more of the new file; the marker says a line is the last one, so \
                 nothing may follow it"
            ),
            PatchError::NewlineMarkerIsWrong { hunk, line, file_line, file_lines } => write!(
                f,
                "hunk {hunk} puts a `{NO_NEWLINE}` marker at line {line} of `patch`, about line \
                 {file_line} of a file that has {file_lines} lines and ends with a newline; the \
                 marker may only describe a last line that has none"
            ),
            PatchError::MissingNewlineMarker { hunk, file_line } => write!(
                f,
                "hunk {hunk} covers line {file_line} of the file, which is the last line and \
                 ends without a newline, and does not say so; write `{NO_NEWLINE}` under it, or \
                 the patch is asking for a byte the file does not have"
            ),
            PatchError::OutOfOrder { hunk, at, previous_end } => write!(
                f,
                "hunk {hunk} starts at line {at} of the file, which the hunk before it has \
                 already used — that one ended at line {previous_end}. Hunks must be in order \
                 and must not overlap"
            ),
            PatchError::PastTheEnd { hunk, at, file_lines } => write!(
                f,
                "hunk {hunk} starts at line {at} of a file that has {file_lines} lines: the \
                 patch was written against a different version of this file, so read it again \
                 and rewrite the hunks against what is there now"
            ),
            PatchError::DoesNotApply { hunk, file_line, expected, found, file_lines } => {
                match found {
                    Some(found) => write!(
                        f,
                        "hunk {hunk} does not apply: it expects line {file_line} of the file to \
                         be `{expected}`, and that line is `{found}`. hatch applies a hunk at \
                         the line its header names and never searches nearby for a better fit, \
                         so read the file again and rewrite the hunk against what is there now"
                    ),
                    None => write!(
                        f,
                        "hunk {hunk} does not apply: it expects line {file_line} of the file to \
                         be `{expected}`, and the file has only {file_lines} lines. Read it \
                         again and rewrite the hunk against what is there now"
                    ),
                }
            }
            PatchError::SecondFile { line, text } => write!(
                f,
                "line {line} of `patch`, `{text}`, starts a second file; a write changes the \
                 one file its `path` names, so send each file's hunks as a write of its own"
            ),
            PatchError::Trailing { line, text } => write!(
                f,
                "line {line} of `patch`, `{text}`, follows the last hunk and belongs to no hunk"
            ),
            PatchError::TooLarge { cap } => write!(
                f,
                "the file this patch produces is over the {cap}-byte limit a swap may write. \
                 That limit is the same one `content` has: how the request was encoded does not \
                 change how much a person can be asked to read"
            ),
        }
    }
}

impl std::error::Error for PatchError {}

/// What one body line of a hunk does, which is what decides which side of the
/// change it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// ` `: on both sides, and must match the file.
    Context,
    /// `-`: on the old side only, and must match the file.
    Remove,
    /// `+`: on the new side only.
    Add,
}

/// One body line of a hunk, with the marker that may follow it folded in.
///
/// The marker is a property of the line above it rather than a line of its
/// own — it counts towards neither side's total and describes whichever sides
/// the line above belongs to — so it is stored that way instead of being kept
/// as a separate token everything downstream would have to look behind it for.
#[derive(Debug, Clone, Copy)]
struct Body<'a> {
    op: Op,
    text: &'a str,
    /// Which line of the patch the `\ No newline at end of file` under this
    /// one is on, when there is one.
    marker: Option<usize>,
}

/// The file being built, and the two limits it is built under.
///
/// A struct rather than a closure because pushing a line has to consult and
/// update three things at once, and because both limits are conditions on the
/// *output* — the cap the caller sets, and the rule that nothing may follow a
/// line the patch called the last one. Both are cheapest to enforce exactly
/// where a line is added.
struct Built {
    bytes: Vec<u8>,
    /// Which hunk ended the file, and where it said so, once a
    /// `\ No newline at end of file` has been applied to the new side. Any
    /// line pushed after that would make the marker a lie, and the refusal
    /// names the marker rather than the line that followed it, because the
    /// marker is the part that was wrong.
    bare: Option<(usize, usize)>,
    cap: usize,
}

impl Built {
    fn new(cap: usize) -> Built {
        Built { bytes: Vec::new(), bare: None, cap }
    }

    /// Add one line, with the terminator that [`Built::end_bare`] takes off
    /// again if the patch says the file ends without one.
    fn push(&mut self, line: &[u8]) -> Result<(), PatchError> {
        if let Some((hunk, line)) = self.bare {
            return Err(PatchError::MarkerNotAtTheEnd { hunk, line });
        }
        // Checked before the bytes are appended rather than after, so the
        // allocation never exceeds the cap by more than one line however large
        // the patch is.
        if self.bytes.len() + line.len() + 1 > self.cap {
            return Err(PatchError::TooLarge { cap: self.cap });
        }
        self.bytes.extend_from_slice(line);
        self.bytes.push(b'\n');
        Ok(())
    }

    /// Take the terminator off the last line, because the file being copied
    /// did not have one either.
    fn drop_terminator(&mut self) {
        if self.bytes.last() == Some(&b'\n') {
            self.bytes.pop();
        }
    }

    /// The same, because the patch *said* the file ends without one — which
    /// additionally means no further line may be pushed.
    fn end_bare(&mut self, hunk: usize, marker_line: usize) {
        self.drop_terminator();
        self.bare = Some((hunk, marker_line));
    }
}

/// Apply `patch` to `before`, or refuse it.
///
/// `cap` bounds the *result*, which is a different limit from the one on the
/// patch itself and is needed for a reason the input cap does not cover: a few
/// hundred bytes of `+` lines inside a loop of hunks can name a great deal of
/// output, and the person at the window is the one who would have to read it.
/// It is a parameter and there is deliberately no default compiled in here,
/// for the reason [`crate::render::diff::diff_files`] takes one: the caller
/// passes the same number a `content` request is measured against, and a
/// second number here could drift from it without anybody noticing.
///
/// A refusal means nothing happened. There is no partially applied state to
/// unwind, because the result is built beside the file rather than in it and
/// is dropped whole.
pub fn apply(before: &[u8], patch: &str, cap: usize) -> Result<Vec<u8>, PatchError> {
    let lines = split_lines(patch);
    let (source, source_ends_with_newline) = decompose(before);

    let mut built = Built::new(cap);
    let mut cursor = 0usize;
    let mut hunks = 0usize;

    // Everything before the first hunk is allowed to be a file header and
    // nothing else. Ignoring it would be harmless for the bytes — the file
    // written is the one `path` names, never a name inside the patch — but a
    // patch with a sentence at the top of it is an agent that has misunderstood
    // the field, and telling it so costs one round trip where guessing costs a
    // window.
    let mut i = 0usize;
    while i < lines.len() && !is_hunk_header(lines[i]) {
        if !lines[i].is_empty() && !is_file_header(lines[i]) {
            return Err(PatchError::NotADiff { line: i + 1, text: quote(lines[i]) });
        }
        i += 1;
    }
    if i == lines.len() {
        return Err(PatchError::NoHunks);
    }

    while i < lines.len() {
        let header_line = i + 1;
        // A blank line between hunks or after the last one is noise and not a
        // line of anything: a hunk's own blank lines are taken by its counts
        // long before this is reached, so nothing that arrives here can be one.
        if lines[i].is_empty() {
            i += 1;
            continue;
        }
        if !is_hunk_header(lines[i]) {
            return Err(if is_file_header(lines[i]) {
                PatchError::SecondFile { line: header_line, text: quote(lines[i]) }
            } else {
                PatchError::Trailing { line: header_line, text: quote(lines[i]) }
            });
        }
        let Some(header) = parse_header(lines[i]) else {
            return Err(PatchError::BadHeader { line: header_line, text: quote(lines[i]) });
        };
        hunks += 1;
        i += 1;

        let body = read_body(&lines, &mut i, &header, hunks, header_line)?;

        // Where the hunk lands. A hunk with no lines of the file is an
        // insertion *after* the line its header names — that is what
        // `@@ -0,0` means for an empty file and what `diff -U0` writes for an
        // insertion anywhere else — and a hunk with lines of the file starts
        // *at* the line it names. The two readings differ by one, which is
        // why the counts have to agree with the body before this is read.
        let at = if header.old_count == 0 {
            header.old_start
        } else {
            if header.old_start == 0 {
                return Err(PatchError::ZeroStart { hunk: hunks, line: header_line });
            }
            header.old_start - 1
        };
        if at < cursor {
            return Err(PatchError::OutOfOrder {
                hunk: hunks,
                at: header.old_start,
                previous_end: cursor,
            });
        }
        if at > source.len() {
            return Err(PatchError::PastTheEnd {
                hunk: hunks,
                at: header.old_start,
                file_lines: source.len(),
            });
        }

        // Everything between the last hunk and this one is carried over
        // untouched.
        while cursor < at {
            built.push(source[cursor])?;
            cursor += 1;
        }

        for line in &body {
            match line.op {
                Op::Context | Op::Remove => {
                    let Some(found) = source.get(cursor) else {
                        return Err(PatchError::DoesNotApply {
                            hunk: hunks,
                            file_line: cursor + 1,
                            expected: quote(line.text),
                            found: None,
                            file_lines: source.len(),
                        });
                    };
                    if *found != line.text.as_bytes() {
                        return Err(PatchError::DoesNotApply {
                            hunk: hunks,
                            file_line: cursor + 1,
                            expected: quote(line.text),
                            found: Some(quote_bytes(found)),
                            file_lines: source.len(),
                        });
                    }
                    let last = cursor + 1 == source.len();
                    // Both directions. A marker on a line that is not the
                    // file's unterminated last line is a claim about the file
                    // that is false; no marker on that line is a claim that
                    // the file ends with a byte it does not have. Either way
                    // the difference is one byte at the end of a file nobody
                    // asked to change.
                    match line.marker {
                        Some(marker) if !(last && !source_ends_with_newline) => {
                            return Err(PatchError::NewlineMarkerIsWrong {
                                hunk: hunks,
                                line: marker,
                                file_line: cursor + 1,
                                file_lines: source.len(),
                            });
                        }
                        None if last && !source_ends_with_newline => {
                            return Err(PatchError::MissingNewlineMarker {
                                hunk: hunks,
                                file_line: cursor + 1,
                            });
                        }
                        _ => {}
                    }
                    cursor += 1;
                    if line.op == Op::Context {
                        built.push(line.text.as_bytes())?;
                    }
                }
                Op::Add => built.push(line.text.as_bytes())?,
            }
            // A marker under a removed line describes the old side alone: the
            // line it belongs to is not in the new file at all, so it says
            // nothing about how the new file ends.
            if let Some(marker) = line.marker
                && line.op != Op::Remove
            {
                built.end_bare(hunks, marker);
            }
        }
    }

    // The tail of the file, after the last hunk, carried over untouched. It
    // also settles the question of the final newline, because the last line of
    // the file is in it: the file keeps the ending it already had, and any
    // marker the patch carried was about a line further up. A file whose last
    // line a hunk *did* reach never gets here, and had its ending settled by
    // the rule above instead.
    let tail = cursor < source.len();
    while cursor < source.len() {
        built.push(source[cursor])?;
        cursor += 1;
    }
    if tail && !source_ends_with_newline {
        built.drop_terminator();
    }

    Ok(built.bytes)
}

/// A hunk header's four numbers.
struct Header {
    old_start: usize,
    old_count: usize,
    new_count: usize,
}

/// Whether a line is where a hunk begins.
///
/// The `-` is part of the test because it is what keeps the check unambiguous
/// against a body line: every line inside a hunk carries a one-character
/// prefix, so a line starting `@@ -` at a position where a body line could also
/// be is still a header — a context line spelling one would read ` @@ -`.
fn is_hunk_header(line: &str) -> bool {
    line.starts_with("@@ -")
}

/// The header lines a patch may carry around its hunks.
///
/// The list is what `diff -u`, `git diff` and `git format-patch` put there.
/// None of it is read: hatch writes the file `path` names and a name inside
/// the patch never changes that. It is recognised only so that the lines which
/// are *not* one of these can be refused.
fn is_file_header(line: &str) -> bool {
    const HEADERS: &[&str] = &[
        "--- ",
        "+++ ",
        "diff ",
        "index ",
        "old mode ",
        "new mode ",
        "new file mode ",
        "deleted file mode ",
        "similarity index ",
        "dissimilarity index ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "Index: ",
        "===",
    ];
    HEADERS.iter().any(|prefix| line.starts_with(prefix))
}

/// Read `@@ -first,count +first,count @@`, with either count defaulting to one
/// when it is left off, and anything after the second `@@` ignored.
///
/// Hand-parsed rather than matched with a regular expression: it is four
/// numbers in a fixed frame, and a pattern would be longer to read than the
/// code and would still need the same four `parse` calls behind it.
fn parse_header(line: &str) -> Option<Header> {
    let rest = line.strip_prefix("@@ -")?;
    let (old, rest) = rest.split_once(" +")?;
    let (new, _section) = rest.split_once(" @@")?;
    let (old_start, old_count) = parse_range(old)?;
    let (_new_start, new_count) = parse_range(new)?;
    Some(Header { old_start, old_count, new_count })
}

/// One side of a hunk header: `12,3`, or `12` for a single line.
fn parse_range(text: &str) -> Option<(usize, usize)> {
    match text.split_once(',') {
        Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
        None => Some((text.parse().ok()?, 1)),
    }
}

/// Take one hunk's body off `lines`, advancing `i` past it, and refuse it if
/// it is not the body its header described.
///
/// Body lines are taken until both of the header's counts are satisfied, which
/// is what resolves the format's one real ambiguity: `--- a/file` starting the
/// next file and `-`-prefixed removal of a line reading `-- a/file` are the
/// same eleven characters, and only the counts say which one is meant. A
/// header that under-counts would therefore swallow the next file's headers
/// silently, so what follows a satisfied hunk is checked as well.
fn read_body<'a>(
    lines: &[&'a str],
    i: &mut usize,
    header: &Header,
    hunk: usize,
    header_line: usize,
) -> Result<Vec<Body<'a>>, PatchError> {
    let mut body: Vec<Body<'a>> = Vec::new();
    let mut old = 0usize;
    let mut new = 0usize;

    while old < header.old_count || new < header.new_count {
        let Some(line) = lines.get(*i) else {
            return Err(disagrees(header, hunk, header_line, old, new));
        };
        if attach_marker(line, *i + 1, &mut body)? {
            *i += 1;
            continue;
        }
        let Some((op, text)) = as_body(line) else {
            return Err(disagrees(header, hunk, header_line, old, new));
        };
        match op {
            Op::Context => {
                old += 1;
                new += 1;
            }
            Op::Remove => old += 1,
            Op::Add => new += 1,
        }
        body.push(Body { op, text, marker: None });
        *i += 1;
    }

    // The marker under the hunk's last line, which counts towards neither
    // total and so is never reached by the loop above.
    if let Some(line) = lines.get(*i)
        && attach_marker(line, *i + 1, &mut body)?
    {
        *i += 1;
    }

    // A hunk that carries more than it declared. Counted rather than reported
    // as "one too many", because an agent that miscounted by four wants to be
    // told four. A blank line stops the count instead of joining it: after the
    // declared body, a blank line is far more often the end of the patch text
    // than a context line somebody forgot to count, and it is the one extra
    // line that cannot change where a later hunk lands.
    let mut extra_old = 0usize;
    let mut extra_new = 0usize;
    let mut j = *i;
    while let Some(line) = lines.get(j) {
        if line.is_empty() || is_hunk_header(line) || is_file_header(line) {
            break;
        }
        match as_body(line) {
            Some((Op::Context, _)) => {
                extra_old += 1;
                extra_new += 1;
            }
            Some((Op::Remove, _)) => extra_old += 1,
            Some((Op::Add, _)) => extra_new += 1,
            None => break,
        }
        j += 1;
    }
    if extra_old > 0 || extra_new > 0 {
        return Err(disagrees(header, hunk, header_line, old + extra_old, new + extra_new));
    }

    Ok(body)
}

/// The refusal for a hunk whose body is not the one its header described.
fn disagrees(
    header: &Header,
    hunk: usize,
    header_line: usize,
    counted_old: usize,
    counted_new: usize,
) -> PatchError {
    PatchError::HeaderDisagreesWithBody {
        hunk,
        line: header_line,
        declared_old: header.old_count,
        declared_new: header.new_count,
        counted_old,
        counted_new,
    }
}

/// Fold a `\ No newline at end of file` into the body line above it, and say
/// whether that is what this line was.
///
/// A marker with nothing above it, or a second marker over the same line, is
/// refused here rather than ignored: both mean the patch is describing an
/// ending that does not exist, and this module never decides what an agent
/// probably meant.
fn attach_marker(line: &str, number: usize, body: &mut [Body<'_>]) -> Result<bool, PatchError> {
    if !line.starts_with('\\') {
        return Ok(false);
    }
    match body.last_mut() {
        Some(above) if above.marker.is_none() => {
            above.marker = Some(number);
            Ok(true)
        }
        _ => Err(PatchError::StrayMarker { line: number }),
    }
}

/// Split a body line into what it does and the text it carries.
///
/// An entirely empty line is an empty context line. `diff` writes a space
/// there and so does everything that generates one properly, but trailing
/// whitespace does not survive every pipe a patch travels down, and refusing
/// the result would be refusing an honest patch for something no agent did.
/// It is not fuzz: the line still has to match an empty line in the file,
/// exactly where the hunk says it does.
fn as_body(line: &str) -> Option<(Op, &str)> {
    match line.as_bytes().first() {
        None => Some((Op::Context, "")),
        Some(b' ') => Some((Op::Context, &line[1..])),
        Some(b'-') => Some((Op::Remove, &line[1..])),
        Some(b'+') => Some((Op::Add, &line[1..])),
        Some(_) => None,
    }
}

/// The patch's lines, without the terminator that ends the last one.
///
/// `str::lines` cannot be used: it strips a `\r` before a `\n`, and a patch
/// against a CRLF file carries `\r` as part of the text its context has to
/// match. So the split is on `\n` alone, and the empty piece a trailing
/// newline leaves behind is dropped — that piece is the terminator, not a
/// line.
fn split_lines(patch: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = patch.split('\n').collect();
    if patch.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// The file's lines, and whether it ends with a newline.
///
/// An empty file has no lines at all rather than one empty line, which is what
/// makes `@@ -0,0 +1,3 @@` against it mean "insert at the start". It is
/// reported as ending with a newline because nothing else is true of it: there
/// is no last line for a marker to describe, and saying otherwise would demand
/// one.
fn decompose(before: &[u8]) -> (Vec<&[u8]>, bool) {
    if before.is_empty() {
        return (Vec::new(), true);
    }
    let mut lines: Vec<&[u8]> = before.split(|b| *b == b'\n').collect();
    let ends_with_newline = before.last() == Some(&b'\n');
    if ends_with_newline {
        lines.pop();
    }
    (lines, ends_with_newline)
}

/// One line of agent-written text, safe to put in a message.
///
/// Defanged on the same terms as `title`: every character that is not plain
/// ASCII becomes the label that names it, so a newline in a patch cannot forge
/// a line of anything this message is later written into, and an invisible
/// character — which is a likely reason a context line did not match in the
/// first place — is shown rather than hidden. Truncation is marked with a
/// character defanging would have replaced, so the mark cannot be forged
/// either.
fn quote(text: &str) -> String {
    let mut out: String = defang(&text.chars().take(QUOTE_CHARS).collect::<String>());
    if text.chars().nth(QUOTE_CHARS).is_some() {
        out.push('…');
    }
    out
}

/// The same, for a line of the file, which need not be valid UTF-8.
fn quote_bytes(text: &[u8]) -> String {
    quote(&String::from_utf8_lossy(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Big enough that no test here meets it except the one about the cap.
    const CAP: usize = 64 * 1024;

    fn applied(before: &str, patch: &str) -> String {
        String::from_utf8(apply(before.as_bytes(), patch, CAP).expect("the patch applies"))
            .expect("the result is text")
    }

    fn refused(before: &str, patch: &str) -> PatchError {
        apply(before.as_bytes(), patch, CAP).expect_err("the patch is refused")
    }

    #[test]
    fn a_hunk_replaces_the_lines_it_names_and_carries_the_rest_over() {
        let before = "one\ntwo\nthree\nfour\nfive\n";
        let patch = "--- a/f\n+++ b/f\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n";
        assert_eq!(applied(before, patch), "one\ntwo\nTHREE\nfour\nfive\n");
    }

    #[test]
    fn several_hunks_apply_in_order_against_the_same_original_line_numbers() {
        // Every hunk's header counts lines of the file as it is now, not of
        // the file as earlier hunks have left it, so a first hunk that adds
        // two lines must not shift where the second one lands.
        let before = "a\nb\nc\nd\ne\nf\ng\n";
        let patch = "@@ -1,2 +1,4 @@\n a\n+a1\n+a2\n b\n@@ -6,2 +8,3 @@\n f\n+f1\n g\n";
        assert_eq!(applied(before, patch), "a\na1\na2\nb\nc\nd\ne\nf\nf1\ng\n");
    }

    #[test]
    fn a_hunk_header_may_leave_out_a_count_of_one() {
        let before = "only\n";
        assert_eq!(applied(before, "@@ -1 +1 @@\n-only\n+lonely\n"), "lonely\n");
    }

    #[test]
    fn a_section_heading_after_the_second_at_signs_is_ignored() {
        let before = "a\nb\n";
        assert_eq!(applied(before, "@@ -1,1 +1,1 @@ fn main() {\n-a\n+A\n"), "A\nb\n");
    }

    #[test]
    fn an_empty_line_stands_in_for_an_empty_context_line() {
        let before = "a\n\nb\n";
        assert_eq!(applied(before, "@@ -1,3 +1,3 @@\n a\n\n-b\n+B\n"), "a\n\nB\n");
    }

    #[test]
    fn a_context_line_keeps_the_carriage_return_a_crlf_file_ends_its_lines_with() {
        let before = "a\r\nb\r\n";
        assert_eq!(applied(before, "@@ -1,2 +1,2 @@\n a\r\n-b\r\n+B\r\n"), "a\r\nB\r\n");
        // And a patch that dropped it does not apply to that file at all,
        // rather than quietly rewriting the line endings of every line it
        // touches.
        assert!(matches!(
            refused(before, "@@ -1,2 +1,2 @@\n a\n-b\n+B\n"),
            PatchError::DoesNotApply { file_line: 1, .. }
        ));
    }

    #[test]
    fn an_insertion_with_no_lines_of_the_file_goes_after_the_line_it_names() {
        let before = "a\nb\nc\n";
        assert_eq!(applied(before, "@@ -2,0 +3 @@\n+inserted\n"), "a\nb\ninserted\nc\n");
        assert_eq!(applied(before, "@@ -0,0 +1 @@\n+first\n"), "first\na\nb\nc\n");
    }

    #[test]
    fn a_patch_against_no_file_at_all_is_the_whole_of_the_new_file() {
        assert_eq!(applied("", "@@ -0,0 +1,2 @@\n+one\n+two\n"), "one\ntwo\n");
    }

    #[test]
    fn a_hunk_that_removes_every_line_leaves_an_empty_file() {
        assert_eq!(applied("a\nb\n", "@@ -1,2 +0,0 @@\n-a\n-b\n"), "");
    }

    // --- the ending of a file that has no newline at the end of it ----------

    #[test]
    fn the_last_line_of_a_file_without_a_newline_must_be_marked_as_such() {
        let before = "a\nb";
        assert_eq!(applied(before, "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+B\n"), "a\nB\n");
        assert!(matches!(
            refused(before, "@@ -2 +2 @@\n-b\n+B\n"),
            PatchError::MissingNewlineMarker { hunk: 1, file_line: 2 }
        ));
    }

    #[test]
    fn a_marker_about_a_file_that_does_end_with_a_newline_is_refused() {
        assert!(matches!(
            refused("a\nb\n", "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+B\n"),
            PatchError::NewlineMarkerIsWrong { hunk: 1, file_line: 2, .. }
        ));
    }

    #[test]
    fn a_marker_about_a_line_that_is_not_the_last_one_is_refused() {
        assert!(matches!(
            refused("a\nb", "@@ -1,2 +1,2 @@\n-a\n\\ No newline at end of file\n+A\n b"),
            PatchError::NewlineMarkerIsWrong { hunk: 1, file_line: 1, .. }
        ));
    }

    #[test]
    fn a_patch_can_take_the_last_newline_off_a_file_and_put_one_back() {
        assert_eq!(
            applied("a\nb\n", "@@ -2 +2 @@\n-b\n+b\n\\ No newline at end of file\n"),
            "a\nb"
        );
        assert_eq!(
            applied("a\nb", "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+b\n"),
            "a\nb\n"
        );
    }

    #[test]
    fn a_context_line_marked_bare_describes_both_sides_at_once() {
        // The line is the last of both files and neither ends with a newline,
        // which is the one case where a single marker answers for both sides.
        let before = "a\nb";
        assert_eq!(applied(before, "@@ -1,2 +1,2 @@\n-a\n+A\n b\n\\ No newline at end of file\n"), "A\nb");
    }

    #[test]
    fn a_file_without_a_final_newline_keeps_it_that_way_when_no_hunk_reaches_the_end() {
        assert_eq!(applied("a\nb\nc", "@@ -1 +1 @@\n-a\n+A\n"), "A\nb\nc");
    }

    #[test]
    fn nothing_may_follow_the_line_a_marker_called_the_last_one() {
        assert!(matches!(
            refused("a\nb\n", "@@ -1,2 +1,2 @@\n-a\n+A\n\\ No newline at end of file\n b\n"),
            PatchError::MarkerNotAtTheEnd { hunk: 1, .. }
        ));
    }

    #[test]
    fn a_marker_with_no_line_above_it_is_refused() {
        assert!(matches!(
            refused("a\n", "@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+A\n"),
            PatchError::StrayMarker { line: 2 }
        ));
    }

    // --- where a hunk may land ----------------------------------------------

    #[test]
    fn a_hunk_applies_where_its_header_says_and_nowhere_else() {
        // The context is in the file, one line above where the hunk claims it
        // is. A fuzzing applier finds it; this one refuses, because a hunk
        // that slid by a line has written bytes somewhere nobody approved.
        let before = "target\nother\nother\n";
        let error = refused(before, "@@ -2 +2 @@\n-target\n+TARGET\n");
        assert!(matches!(error, PatchError::DoesNotApply { hunk: 1, file_line: 2, .. }));
        let message = error.to_string();
        assert!(message.contains("`target`"), "the message says what was expected: {message}");
        assert!(message.contains("`other`"), "and what is actually there: {message}");
        assert!(message.contains("never searches"), "and that it will not hunt for it: {message}");
    }

    #[test]
    fn a_hunk_past_the_end_of_the_file_names_the_length_the_file_has() {
        let error = refused("a\nb\n", "@@ -9,1 +9,1 @@\n-x\n+y\n");
        assert!(matches!(error, PatchError::PastTheEnd { hunk: 1, at: 9, file_lines: 2 }));
        assert!(error.to_string().contains("has 2 lines"), "{error}");
    }

    #[test]
    fn a_hunk_that_runs_off_the_end_of_the_file_says_so_rather_than_stopping_short() {
        let error = refused("a\nb\n", "@@ -2,3 +2,1 @@\n b\n-c\n-d\n");
        assert!(matches!(
            error,
            PatchError::DoesNotApply { hunk: 1, file_line: 3, found: None, file_lines: 2, .. }
        ));
        assert!(error.to_string().contains("only 2 lines"), "{error}");
    }

    #[test]
    fn hunks_that_go_backwards_or_overlap_are_refused() {
        let before = "a\nb\nc\nd\n";
        assert!(matches!(
            refused(before, "@@ -3 +3 @@\n-c\n+C\n@@ -1 +1 @@\n-a\n+A\n"),
            PatchError::OutOfOrder { hunk: 2, at: 1, previous_end: 3 }
        ));
        assert!(matches!(
            refused(before, "@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n"),
            PatchError::OutOfOrder { hunk: 2, at: 2, previous_end: 2 }
        ));
    }

    #[test]
    fn a_hunk_that_carries_lines_of_the_file_cannot_start_at_line_zero() {
        assert!(matches!(
            refused("a\n", "@@ -0,1 +0,1 @@\n-a\n+A\n"),
            PatchError::ZeroStart { hunk: 1, line: 1 }
        ));
    }

    // --- the shape of the patch itself --------------------------------------

    #[test]
    fn a_patch_with_no_hunk_in_it_is_refused() {
        assert_eq!(refused("a\n", "--- a/f\n+++ b/f\n"), PatchError::NoHunks);
        assert_eq!(refused("a\n", ""), PatchError::NoHunks);
    }

    #[test]
    fn prose_around_the_diff_is_refused_rather_than_skipped_over() {
        let error = refused("a\n", "Here is the patch:\n@@ -1 +1 @@\n-a\n+A\n");
        assert!(matches!(error, PatchError::NotADiff { line: 1, .. }));
        assert!(error.to_string().contains("Here is the patch:"), "{error}");
    }

    #[test]
    fn a_second_file_in_one_patch_is_refused_by_name() {
        let patch = "@@ -1 +1 @@\n-a\n+A\n--- a/other\n+++ b/other\n@@ -1 +1 @@\n-x\n+X\n";
        assert!(matches!(refused("a\n", patch), PatchError::SecondFile { line: 4, .. }));
    }

    #[test]
    fn a_removal_of_a_line_that_looks_like_a_file_header_is_still_a_removal() {
        // `--- a/f` as the text of a removed line and `--- a/f` as the header
        // of the next file are the same characters; the hunk's counts are
        // what tell them apart, which is why the counts are enforced.
        let before = "--- a/f\nb\n";
        assert_eq!(applied(before, "@@ -1,2 +1,1 @@\n---- a/f\n b\n"), "b\n");
    }

    #[test]
    fn a_hunk_header_that_is_not_one_is_refused_where_it_stands() {
        let error = refused("a\n", "@@ -one +two @@\n-a\n+A\n");
        assert!(matches!(error, PatchError::BadHeader { line: 1, .. }));
        assert!(error.to_string().contains("@@ -first,count"), "{error}");
    }

    #[test]
    fn a_hunk_whose_counts_do_not_match_its_body_is_refused_rather_than_reconciled() {
        let before = "a\nb\nc\n";
        let error = refused(before, "@@ -1,3 +1,3 @@\n a\n-b\n+B\n");
        assert!(matches!(
            error,
            PatchError::HeaderDisagreesWithBody {
                hunk: 1,
                declared_old: 3,
                declared_new: 3,
                counted_old: 2,
                counted_new: 2,
                ..
            }
        ));
        assert!(error.to_string().contains("carries 2 and 2"), "{error}");

        // And the same in the other direction: more body than the header
        // declared, counted out in full rather than reported as one too many.
        assert!(matches!(
            refused(before, "@@ -1,1 +1,1 @@\n a\n b\n c\n"),
            PatchError::HeaderDisagreesWithBody { counted_old: 3, counted_new: 3, .. }
        ));
    }

    #[test]
    fn a_body_line_with_no_prefix_ends_the_hunk_and_is_reported() {
        let error = refused("a\nb\n", "@@ -1,2 +1,2 @@\n a\n-b\n+B\nwhat is this\n");
        assert!(matches!(error, PatchError::Trailing { line: 5, .. }));
        assert!(error.to_string().contains("what is this"), "{error}");
    }

    #[test]
    fn a_truncated_hunk_is_refused_with_what_it_did_carry() {
        assert!(matches!(
            refused("a\nb\nc\n", "@@ -1,3 +1,3 @@\n a\n-b\n"),
            PatchError::HeaderDisagreesWithBody { counted_old: 2, counted_new: 1, .. }
        ));
    }

    // --- what reaches a message ---------------------------------------------

    #[test]
    fn a_newline_in_a_quoted_line_cannot_forge_a_line_of_the_message() {
        // The patch is agent-written text and a refusal quotes it back. The
        // characters that a reader's terminal or log would obey are named
        // rather than obeyed, exactly as a title is.
        let error = refused("a\n", "\u{7}oh\u{202e}no\n@@ -1 +1 @@\n-a\n+A\n");
        let message = error.to_string();
        assert!(!message.contains('\u{7}'), "a control character survived: {message}");
        assert!(!message.contains('\u{202e}'), "a bidi override survived: {message}");
        assert!(message.contains("[BEL]") || message.contains("[U+0007]"), "{message}");
    }

    #[test]
    fn a_very_long_line_is_quoted_only_as_far_as_it_is_worth_reading() {
        let long = "x".repeat(10_000);
        let error = refused("a\n", &format!("{long}\n@@ -1 +1 @@\n-a\n+A\n"));
        let message = error.to_string();
        assert!(message.len() < 1_000, "the whole line was pasted back: {} bytes", message.len());
        assert!(message.contains('…'), "the truncation is marked: {message}");
    }

    // --- the cap ------------------------------------------------------------

    #[test]
    fn a_patch_that_expands_past_the_cap_is_refused_on_what_it_would_produce() {
        // Small patch, large result: the input cap cannot see this coming,
        // which is why the output has one of its own.
        let before = "a\n".repeat(1000);
        let patch = "@@ -1 +1,3 @@\n a\n+".to_string() + &"y".repeat(200) + "\n+z\n";
        let error = apply(before.as_bytes(), &patch, 300).expect_err("over the cap");
        assert_eq!(error, PatchError::TooLarge { cap: 300 });
        assert!(error.to_string().contains("300-byte"), "{error}");
    }

    #[test]
    fn a_result_of_exactly_the_cap_is_within_it() {
        // The cap is a maximum size and not a size that is already too big,
        // on the same terms as `render_content`'s.
        let produced = apply(b"a\n", "@@ -1 +1 @@\n-a\n+bb\n", 3).expect("three bytes fit in three");
        assert_eq!(produced, b"bb\n");
    }
}
