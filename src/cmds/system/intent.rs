//! Surgical lexical extraction for `read --intent`.
//!
//! When a `contextcrawler read` invocation is given an `--intent "<terms>"` flag
//! AND the input is large enough that the symmetric head/tail cap can't fit
//! it efficiently, this module scores heading-anchored sections of the file
//! by lexical match against the intent terms and returns only the top-scoring
//! ones plus head/tail bookends so the file shape stays readable.
//!
//! Designed to be **opt-in and non-async**: regex / split-only, no LLM, no
//! external service. Returns `None` when the file is too small or the
//! extractor can't find enough sections to make extraction worthwhile —
//! caller (`read::run`) falls back to the normal render path in that case.
//!
//! Section splitters covered in v1:
//!   - Markdown (`.md`, `.markdown`)            — split on `^#+\s` headings
//!   - Rust (Language::Rust)                    — split on top-level items
//!   - TOML / Cargo.lock (`.toml`, `.lock`)     — split on `^[` headers
//!   - Anything else                            — split on blank-line runs
//!
//! New extension or language support is additive: add a branch to
//! [`split_into_sections`] plus a fixture-backed test. No schema changes.

use crate::core::filter::Language;

/// Minimum input size at which intent extraction kicks in. Below this, the
/// existing head/tail cap is already small enough that surgical extraction
/// would just add overhead.
const INTENT_MIN_BYTES: usize = 5 * 1024;

/// Lines of head + tail to keep verbatim around the extracted sections.
/// Preserves the file's "shape" (imports, license header, last line) so the
/// reader can orient without reading the whole thing.
const BOOKEND_LINES: usize = 20;

/// Hard byte cap per bookend, in case the file has only a few very long
/// lines (e.g. minified JSON, single-line CSV). Without this, a 20-line
/// bookend can swallow the whole file.
const BOOKEND_MAX_BYTES: usize = 1024;

/// Skip bookends entirely on files with fewer total lines than this — the
/// bookends would just duplicate the kept sections.
const BOOKEND_MIN_TOTAL_LINES: usize = 60;

/// Stop extracting once the kept content reaches this fraction of original
/// size — prevents the extractor from over-keeping on a file where many
/// sections match weakly.
const KEEP_TARGET_RATIO: usize = 30; // 30%

/// Headings have higher weight in scoring than body matches: a match in the
/// heading is a strong navigational signal (the section's *about* the term).
const HEADING_WEIGHT: usize = 5;

/// Common English stopwords. Intentionally short — we'd rather over-tokenise
/// (and match too much) than under-tokenise on a short intent string.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "as", "at", "by", "for", "in", "is", "of", "on", "or",
    "the", "to", "with", "from", "into",
];

/// Run intent-driven extraction over `content`.
///
/// Returns `Some(extracted_output)` if extraction applies AND finds at least
/// one matching section. Returns `None` when the caller should fall back to
/// the regular render path:
///
///   - input is smaller than [`INTENT_MIN_BYTES`]
///   - intent string has no usable terms (all stopwords or punctuation)
///   - file doesn't split into at least 3 sections
///   - no section scored above zero
pub fn extract_for_intent(
    content: &str,
    ext: Option<&str>,
    lang: Language,
    intent: &str,
    display_path: &str,
) -> Option<String> {
    if content.len() < INTENT_MIN_BYTES {
        return None;
    }
    let terms = tokenize_intent(intent);
    if terms.is_empty() {
        return None;
    }
    let sections = split_into_sections(content, ext, lang);
    if sections.len() < 3 {
        return None;
    }

    // Score every section against the intent terms.
    let mut scored: Vec<(usize, usize)> = sections
        .iter()
        .enumerate()
        .map(|(idx, s)| (idx, score_section(s, &terms)))
        .collect();

    // If literally nothing matched, intent extraction can't help. Caller
    // falls through to the head/tail cap so the user still gets readable
    // output.
    if scored.iter().all(|(_, score)| *score == 0) {
        return None;
    }

    // Keep top scorers until kept content is approximately KEEP_TARGET_RATIO%
    // of the original. Sort kept indices in original document order so the
    // assembled output reads chronologically, not by score.
    //
    // Tie handling (peer-review #163, Codex Q6): once the target is reached,
    // KEEP adding any further sections whose score equals the last-included
    // score before stopping. Without this, a single chunky section can push
    // past the target and the loop would silently drop equally-relevant
    // siblings that should have appeared together.
    scored.sort_by(|a, b| b.1.cmp(&a.1));
    let target_bytes = content.len() * KEEP_TARGET_RATIO / 100;
    let mut kept: Vec<usize> = Vec::new();
    let mut kept_bytes = 0usize;
    let mut last_kept_score: Option<usize> = None;
    for (idx, score) in &scored {
        if *score == 0 {
            break;
        }
        if kept_bytes >= target_bytes {
            // Past target — only keep going if this section ties the last
            // included one. The moment we hit a strictly lower score, stop.
            if last_kept_score != Some(*score) {
                break;
            }
        }
        kept.push(*idx);
        kept_bytes += sections[*idx].body.len();
        last_kept_score = Some(*score);
    }
    kept.sort();

    Some(assemble_output(
        content,
        intent,
        display_path,
        &sections,
        &kept,
    ))
}

/// A logical "section" of the file — heading + body. Heading is empty for
/// formats that don't have natural headings (paragraph-split fallback).
#[derive(Debug)]
struct Section {
    heading: String,
    body: String,
}

/// Lower-case, split on non-alphanumeric, drop stopwords. Keeps the design
/// simple — no stemming, no synonyms. A user typing `--intent "auth tokens"`
/// gets matches on the literal tokens "auth" and "tokens".
fn tokenize_intent(intent: &str) -> Vec<String> {
    intent
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .filter(|s| !STOPWORDS.contains(&s.as_str()))
        .collect()
}

/// Per-section score: count of intent-term occurrences in body, plus
/// heading hits weighted by [`HEADING_WEIGHT`]. Case-insensitive.
fn score_section(section: &Section, terms: &[String]) -> usize {
    let body_lc = section.body.to_lowercase();
    let heading_lc = section.heading.to_lowercase();
    terms
        .iter()
        .map(|t| body_lc.matches(t.as_str()).count() + heading_lc.matches(t.as_str()).count() * HEADING_WEIGHT)
        .sum()
}

/// Dispatch to the right section splitter based on file extension first,
/// then language. Extension wins because Cargo.lock (`.lock`) and `.md` both
/// map to `Language::Data`, but they want different splitters.
fn split_into_sections(content: &str, ext: Option<&str>, lang: Language) -> Vec<Section> {
    if let Some(e) = ext.map(|s| s.to_ascii_lowercase()) {
        match e.as_str() {
            "md" | "markdown" => return split_by_markdown_headings(content),
            "toml" | "lock" => return split_by_toml_headers(content),
            _ => {}
        }
    }
    if matches!(lang, Language::Rust) {
        return split_by_rust_items(content);
    }
    split_by_blank_lines(content)
}

/// Markdown: a new section starts at any line matching `^#+\s+`. Code blocks
/// (fenced ``` ... ```) are NOT split even if they contain `#` lines — that
/// would be a comment in a shell script, not a heading.
fn split_by_markdown_headings(content: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut current_heading = String::new();
    let mut current_body = String::new();
    let mut in_fence = false;

    for line in content.lines() {
        let fence = line.trim_start().starts_with("```");
        if fence {
            in_fence = !in_fence;
        }
        let is_heading = !in_fence
            && line.starts_with('#')
            && line
                .chars()
                .take_while(|c| *c == '#')
                .count()
                <= 6
            && line
                .chars()
                .find(|c| *c != '#')
                .is_some_and(|c| c == ' ');

        if is_heading {
            if !current_body.is_empty() || !current_heading.is_empty() {
                sections.push(Section {
                    heading: std::mem::take(&mut current_heading),
                    body: std::mem::take(&mut current_body),
                });
            }
            current_heading = line.trim_start_matches('#').trim().to_string();
        } else {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }
    if !current_body.is_empty() || !current_heading.is_empty() {
        sections.push(Section {
            heading: current_heading,
            body: current_body,
        });
    }
    sections
}

/// Rust: split on top-level item starts — `fn`, `impl`, `struct`, `enum`,
/// `trait`, `mod`, `type`, `const`, `static`, optionally prefixed with `pub`
/// / `async` / `unsafe` / `pub(crate)`. Only zero-indented lines count, so
/// inner-impl items don't split.
fn split_by_rust_items(content: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut current_heading = String::new();
    let mut current_body = String::new();

    for line in content.lines() {
        let stripped = line.trim_start();
        let indented = line.len() != stripped.len();
        let is_item = !indented && is_rust_item_start(stripped);
        if is_item {
            if !current_body.is_empty() || !current_heading.is_empty() {
                sections.push(Section {
                    heading: std::mem::take(&mut current_heading),
                    body: std::mem::take(&mut current_body),
                });
            }
            // Heading = first line of the item, truncated for stability in
            // snapshot tests.
            current_heading = line.chars().take(80).collect();
        }
        current_body.push_str(line);
        current_body.push('\n');
    }
    if !current_body.is_empty() || !current_heading.is_empty() {
        sections.push(Section {
            heading: current_heading,
            body: current_body,
        });
    }
    sections
}

fn is_rust_item_start(line: &str) -> bool {
    let after_vis = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let after_async = after_vis
        .strip_prefix("async ")
        .unwrap_or(after_vis);
    let after_unsafe = after_async
        .strip_prefix("unsafe ")
        .unwrap_or(after_async);
    [
        "fn ", "impl ", "struct ", "enum ", "trait ", "mod ", "type ",
        "const ", "static ",
    ]
    .iter()
    .any(|kw| after_unsafe.starts_with(kw))
}

/// TOML / Cargo.lock: split on `^[` lines, which are either table headers
/// `[section]` or array-of-tables headers `[[package]]`. The header line
/// itself becomes the section heading.
fn split_by_toml_headers(content: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut current_heading = String::new();
    let mut current_body = String::new();

    for line in content.lines() {
        if line.starts_with('[') {
            if !current_body.is_empty() || !current_heading.is_empty() {
                sections.push(Section {
                    heading: std::mem::take(&mut current_heading),
                    body: std::mem::take(&mut current_body),
                });
            }
            current_heading = line.to_string();
        }
        current_body.push_str(line);
        current_body.push('\n');
    }
    if !current_body.is_empty() || !current_heading.is_empty() {
        sections.push(Section {
            heading: current_heading,
            body: current_body,
        });
    }
    sections
}

/// Fallback for unknown formats: split on runs of blank lines. Each
/// paragraph becomes a section with empty heading.
fn split_by_blank_lines(content: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut current_body = String::new();
    let mut prev_blank = false;

    for line in content.lines() {
        let blank = line.trim().is_empty();
        if blank && prev_blank && !current_body.is_empty() {
            sections.push(Section {
                heading: String::new(),
                body: std::mem::take(&mut current_body),
            });
        }
        current_body.push_str(line);
        current_body.push('\n');
        prev_blank = blank;
    }
    if !current_body.is_empty() {
        sections.push(Section {
            heading: String::new(),
            body: current_body,
        });
    }
    sections
}

fn assemble_output(
    content: &str,
    intent: &str,
    display_path: &str,
    sections: &[Section],
    kept: &[usize],
) -> String {
    let total_lines = content.lines().count();
    let show_bookends = total_lines >= BOOKEND_MIN_TOTAL_LINES;

    let mut out = String::new();
    out.push_str(&format!(
        "// [contextcrawler] intent extraction on {} ({} bytes, kept {} of {} sections)\n",
        display_path,
        content.len(),
        kept.len(),
        sections.len()
    ));
    out.push_str(&format!("// intent: {}\n", intent));

    if show_bookends {
        let head = take_capped(content.lines().take(BOOKEND_LINES), BOOKEND_MAX_BYTES);
        out.push_str("// head bookend:\n");
        out.push_str(&head);
        out.push_str("\n\n// ...\n\n");
    }

    for &idx in kept {
        let heading = if sections[idx].heading.is_empty() {
            format!("section {}", idx)
        } else {
            sections[idx].heading.clone()
        };
        out.push_str(&format!("// match: {}\n", heading));
        out.push_str(&sections[idx].body);
        if !sections[idx].body.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "// ... {} sections omitted ...\n",
        sections.len() - kept.len()
    ));

    if show_bookends {
        let tail_start = total_lines.saturating_sub(BOOKEND_LINES);
        let tail = take_capped(content.lines().skip(tail_start), BOOKEND_MAX_BYTES);
        out.push_str("\n// tail bookend:\n");
        out.push_str(&tail);
        out.push('\n');
    }
    out
}

/// Take lines from the iterator until the byte cap is reached. Joining with
/// '\n' so a 1-line-megabyte file emits at most ~1 line worth of bookend.
///
/// When the first line itself exceeds the cap, truncates to the largest
/// UTF-8-valid byte prefix that fits below the cap and appends a marker.
/// Byte-boundary safe — never slices mid-codepoint, so multibyte UTF-8
/// inputs (CJK, emoji, accented Latin) can't panic. Peer-review #151 (Codex).
fn take_capped<'a, I: Iterator<Item = &'a str>>(iter: I, max_bytes: usize) -> String {
    const TRUNCATION_MARKER: &str = " …[truncated]";
    let mut out = String::new();
    for line in iter {
        // Peer-review #163 Q4a: only charge the separator newline when
        // there's already content; without this, an exactly-fitting first
        // line was falsely treated as overflow.
        let separator_cost = if out.is_empty() { 0 } else { 1 };
        if out.len() + line.len() + separator_cost > max_bytes {
            // Peer-review #163 Q4b: if the cap is smaller than the marker
            // itself, emitting "marker alone" exceeds the nominal cap.
            // Honour the cap strictly — return empty rather than over-emit.
            if out.is_empty() && max_bytes >= TRUNCATION_MARKER.len() {
                // First line already exceeds cap. Keep the largest valid-
                // UTF-8 prefix that fits below (cap - marker.len()) bytes.
                let cap = max_bytes.saturating_sub(TRUNCATION_MARKER.len());
                let end = line
                    .char_indices()
                    .map(|(i, c)| i + c.len_utf8())
                    .take_while(|&i| i <= cap)
                    .last()
                    .unwrap_or(0);
                out.push_str(&line[..end]);
                out.push_str(TRUNCATION_MARKER);
            }
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_tokens(s: &str) -> usize {
        s.split_whitespace().count()
    }

    // ─── Tokeniser ─────────────────────────────────────────────────────────

    #[test]
    fn tokenize_drops_stopwords_and_lowercases() {
        let terms = tokenize_intent("Auth and Tokens in the API");
        assert_eq!(terms, vec!["auth", "tokens", "api"]);
    }

    #[test]
    fn tokenize_handles_punctuation() {
        let terms = tokenize_intent("User-struct + impls");
        assert!(terms.contains(&"user".to_string()));
        assert!(terms.contains(&"struct".to_string()));
        assert!(terms.contains(&"impls".to_string()));
    }

    #[test]
    fn tokenize_only_stopwords_yields_empty() {
        assert!(tokenize_intent("the and of").is_empty());
    }

    // ─── Markdown splitter ─────────────────────────────────────────────────

    #[test]
    fn markdown_splitter_finds_sections() {
        let md = "# Intro\n\nbody one\n\n## Sub\n\nbody two\n\n# Final\n\nbody three\n";
        let sections = split_by_markdown_headings(md);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].heading, "Intro");
        assert_eq!(sections[1].heading, "Sub");
        assert_eq!(sections[2].heading, "Final");
    }

    #[test]
    fn markdown_splitter_ignores_headings_in_fenced_code() {
        let md = "# Outer\n\nbefore\n\n```bash\n# this is a comment, not a heading\nls -la\n```\n\nafter\n\n# Next\n\nbody\n";
        let sections = split_by_markdown_headings(md);
        assert_eq!(sections.len(), 2, "fenced `# comment` must not split: {:?}", sections);
        assert_eq!(sections[0].heading, "Outer");
        assert_eq!(sections[1].heading, "Next");
    }

    // ─── Rust splitter ─────────────────────────────────────────────────────

    #[test]
    fn rust_splitter_handles_visibility_and_qualifiers() {
        let rs = "use foo;\n\npub fn alpha() {}\n\npub(crate) struct Beta;\n\nasync fn gamma() {}\n\nunsafe fn delta() {}\n";
        let sections = split_by_rust_items(rs);
        assert!(
            sections.len() >= 4,
            "expected ≥4 sections (alpha, Beta, gamma, delta), got {}: {:?}",
            sections.len(),
            sections
        );
    }

    #[test]
    fn rust_splitter_does_not_split_inner_fns() {
        let rs = "impl Foo {\n    fn inner() {}\n    fn other() {}\n}\n";
        let sections = split_by_rust_items(rs);
        assert_eq!(sections.len(), 1, "inner impl items must not split: {sections:?}");
    }

    // ─── TOML splitter ─────────────────────────────────────────────────────

    #[test]
    fn toml_splitter_array_of_tables() {
        let lock = "[[package]]\nname = \"a\"\nversion = \"1\"\n\n[[package]]\nname = \"b\"\nversion = \"2\"\n";
        let sections = split_by_toml_headers(lock);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].heading, "[[package]]");
    }

    // ─── extract_for_intent integration ────────────────────────────────────

    fn make_big_markdown() -> String {
        // Build a realistic >5KB markdown fixture: 5 sections each with
        // many short body lines (mirrors actual docs / READMEs, not the
        // unrealistic "5 megalines" case). Each body has ~50 lines × ~50
        // chars = ~2.5 KB per section, so 5 sections ≈ 12.5 KB total —
        // well above INTENT_MIN_BYTES and large enough to exercise the
        // bookend logic too.
        let make_body = |topic: &str, line: &str| -> String {
            let mut s = String::new();
            for _ in 0..50 {
                s.push_str(&format!("{}: {}\n", topic, line));
            }
            s
        };
        let mut s = String::new();
        s.push_str("# Authentication\n\n");
        s.push_str(&make_body("Auth", "this line is about auth and tokens"));
        s.push_str("\n# Database\n\n");
        s.push_str(&make_body("DB", "this line is about SQL queries"));
        s.push_str("\n# Networking\n\n");
        s.push_str(&make_body("Net", "this line is about HTTP"));
        s.push_str("\n# Logging\n\n");
        s.push_str(&make_body("Log", "this line is about log output"));
        s.push_str("\n# Errors\n\n");
        s.push_str(&make_body("Err", "this line covers error handling"));
        s
    }

    #[test]
    fn extract_returns_none_for_small_input() {
        let small = "# tiny\n\nshort\n";
        assert!(
            extract_for_intent(small, Some("md"), Language::Data, "auth tokens", "x.md").is_none()
        );
    }

    #[test]
    fn extract_returns_none_when_no_section_matches() {
        let md = make_big_markdown();
        assert!(
            extract_for_intent(&md, Some("md"), Language::Data, "quantum holography", "x.md")
                .is_none(),
            "no matching terms should yield None so caller falls back"
        );
    }

    #[test]
    fn extract_keeps_matching_section_and_drops_others() {
        let md = make_big_markdown();
        let out = extract_for_intent(&md, Some("md"), Language::Data, "auth tokens", "x.md")
            .expect("should extract — Authentication section matches");
        // The matching section's heading must appear in output.
        assert!(
            out.contains("Authentication"),
            "matching section heading must be present: {out}"
        );
        // At least one non-matching heading must NOT appear in a `// match:` line.
        assert!(
            !out.contains("// match: Database"),
            "non-matching section must not be kept: {out}"
        );
    }

    #[test]
    fn extract_achieves_meaningful_reduction() {
        let md = make_big_markdown();
        let out = extract_for_intent(&md, Some("md"), Language::Data, "auth tokens", "x.md")
            .expect("extraction applies");
        let savings_pct =
            100.0 - (count_tokens(&out) as f64 / count_tokens(&md) as f64 * 100.0);
        assert!(
            savings_pct >= 50.0,
            "intent extraction must achieve ≥50% token reduction on a 5-section fixture, got {savings_pct:.1}%"
        );
    }

    #[test]
    fn extract_preserves_head_and_tail_bookends() {
        let md = make_big_markdown();
        let out = extract_for_intent(&md, Some("md"), Language::Data, "auth tokens", "x.md")
            .expect("extraction applies");
        assert!(out.contains("// head bookend:"));
        assert!(out.contains("// tail bookend:"));
    }

    // ─── Real-fixture grounding (peer-review #151 Codex finding #6) ────────

    #[test]
    fn extract_on_pinned_cargo_lock_meets_savings_target() {
        // Peer-review #163 Q8: pin a static Cargo.lock-shaped fixture
        // instead of the live repo Cargo.lock. The previous test was
        // brittle — adding/removing a single dep on develop could shift
        // baseline byte count and the matched section set, causing spurious
        // failures unrelated to the filter logic. Snapshot lives in
        // tests/fixtures/cargo_lock_sample.txt and is treated as a fixed
        // input the test owns.
        let lock = include_str!("../../../tests/fixtures/cargo_lock_sample.txt");
        let out = extract_for_intent(
            lock,
            Some("lock"),
            Language::Data,
            "rusqlite chrono",
            "cargo_lock_sample.txt",
        )
        .expect("pinned fixture is large enough to extract from");
        let savings_pct =
            100.0 - (count_tokens(&out) as f64 / count_tokens(lock) as f64 * 100.0);
        assert!(
            savings_pct >= 80.0,
            "Cargo.lock-shaped extraction must achieve ≥80% token reduction, got {savings_pct:.1}%"
        );
        // Sanity: the requested terms must actually appear in the output —
        // a "high savings" result that filtered out the matches would be a
        // regression worse than the baseline filter.
        assert!(
            out.contains("rusqlite"),
            "rusqlite must appear in the kept sections"
        );
        assert!(
            out.contains("chrono"),
            "chrono must appear in the kept sections"
        );
    }

    // ─── KEEP_TARGET_RATIO tie handling (peer-review #163 Q6 CONCERN) ──────

    #[test]
    fn extract_keeps_tied_scoring_sections_past_target() {
        // Construct a fixture where two sections both contain the same
        // intent terms with the same density. The first kept section
        // already pushes past target_bytes — without the tie-handling
        // fix, the second equally-relevant section would be silently
        // dropped.
        let make_body = |topic: &str, line: &str, n: usize| -> String {
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(&format!("{}: {}\n", topic, line));
            }
            s
        };
        // Two large sections that both match "alpha beta" with identical
        // term frequency (each line contains both terms once). Each ~100
        // lines × 30 bytes = ~3 KB. Combined with the third (smaller,
        // non-matching) section, total is ~6.5 KB — large enough to
        // trigger extraction.
        let mut md = String::new();
        md.push_str("# Alpha\n\n");
        md.push_str(&make_body("Alpha", "this line covers alpha and beta", 100));
        md.push_str("\n# Beta\n\n");
        md.push_str(&make_body("Beta", "this line covers alpha and beta", 100));
        md.push_str("\n# Gamma\n\n");
        md.push_str(&make_body("Gamma", "irrelevant content here", 20));

        let out = extract_for_intent(&md, Some("md"), Language::Data, "alpha beta", "tied.md")
            .expect("extraction applies");
        // Both equally-scoring sections must appear, despite the first
        // alone exceeding target_bytes. This is the Q6 regression guard.
        assert!(
            out.contains("// match: Alpha"),
            "first tied section must be kept: {out}"
        );
        assert!(
            out.contains("// match: Beta"),
            "tied-scoring sibling must also be kept (Q6 tie-handling): {out}"
        );
        // The strictly-lower-scoring section MUST NOT be kept.
        assert!(
            !out.contains("// match: Gamma"),
            "non-matching section must remain excluded: {out}"
        );
    }

    // ─── take_capped UTF-8 safety (peer-review #151 Codex finding #4) ──────

    #[test]
    fn take_capped_does_not_panic_on_multibyte_overflow() {
        // A single line of 4-byte emoji exceeding the cap must truncate at
        // a valid UTF-8 boundary, not panic mid-codepoint. Each "🎉" is 4
        // bytes; with cap=50 we expect at most 9 emoji (36 bytes) before
        // the marker.
        let huge = "🎉".repeat(100);
        let lines = std::iter::once(huge.as_str());
        let out = take_capped(lines, 50);
        assert!(out.ends_with("…[truncated]"), "marker must be present: {out:?}");
        // Output is valid UTF-8 by construction (String guarantees this) —
        // the real test is that the function didn't panic.
    }

    #[test]
    fn take_capped_emits_nothing_when_cap_is_tiny() {
        // Peer-review #163 Q4b: when the cap is smaller than the truncation
        // marker itself, emitting "marker alone" would exceed the nominal
        // cap. The function must honour the cap strictly and return empty
        // rather than over-emit. Pre-fix behaviour returned the bare marker
        // which violated the cap contract.
        let out = take_capped(std::iter::once("anything"), 3);
        assert_eq!(
            out, "",
            "cap < TRUNCATION_MARKER.len() must yield empty output, not the bare marker"
        );
    }
}
