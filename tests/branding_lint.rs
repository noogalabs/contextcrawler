//! Branding lint — prevents the downstream-rebrand regressions that
//! repeatedly bit us in this fork (issues #19, #20, #22, #23).
//!
//! Scans every `.rs` file under `src/` and asserts that none of the
//! forbidden upstream-branded literals appear in production source —
//! `[rtk]`, `[rtk:`, `RTK.md`, `@RTK.md`. Each occurrence either
//! - needs to be replaced with the equivalent CONTEXTCRAWLER form, or
//! - if it's an intentional legacy reference (regression-history
//!   comments, the `LEGACY_RTK_MD_FILES` registry, migration code
//!   that detects the old names, tests that verify legacy cleanup),
//!   needs the marker comment `// branding-lint: allow legacy` on the
//!   same line OR be in a function/test name whose role makes legacy
//!   reference obvious (matched via the allowed-callsite rules below).
//!
//! Future renames just update the `FORBIDDEN_TOKENS` table here — any
//! source line that drifts from the rebrand will fail this test with a
//! clear pointer back to this file.

use std::fs;
use walkdir::WalkDir;

/// Tokens that should never appear in production source unless explicitly
/// allowlisted. Each entry: (needle, human-readable explanation shown on
/// failure).
const FORBIDDEN_TOKENS: &[(&str, &str)] = &[
    ("[rtk]", "warning/error prefix — use \"[contextcrawler]\" (issue #23)"),
    ("[rtk:", "diagnostic prefix variants — use \"[contextcrawler:\" (issue #23)"),
    ("RTK.md", "slim instructions filename — use CONTEXTCRAWLER.md or the RTK_MD constant (issue #19/#20)"),
    ("@RTK.md", "slim instructions @-reference — use @CONTEXTCRAWLER.md or RTK_MD_REF constant (issue #19/#20)"),
];

/// Per-line allowlist marker. A line ending with this comment is exempt.
const ALLOW_MARKER: &str = "// branding-lint: allow legacy";

/// Substrings that, if present on the line being scanned, exempt that line.
/// Use for short structural references (variable names, history comments)
/// that don't justify a per-line marker.
const STRUCTURAL_ALLOW_NEEDLES: &[&str] = &[
    "LEGACY_RTK_MD_FILES",       // the registry itself
    "issue #19",                 // regression-history comments
    "see issue #19",
    "see #19",
    "bcddd06",                   // the offending commit hash mentioned in history comments
];

/// Function-name prefixes whose entire body is exempt from the lint. Use
/// for tests/helpers that deliberately operate on the legacy filename and
/// would be tedious to mark line-by-line. The lint detects function
/// boundaries by tracking brace depth starting from the `fn` declaration.
const ALLOWED_FUNCTION_PREFIXES: &[&str] = &[
    "fn test_cleanup_legacy_codex_files_",
    "fn test_uninstall_codex_at_removes_legacy_rtk_md_file_and_ref",
    "fn test_patch_claude_md_migrates_legacy_at_ref_in_place",
    "fn test_strip_at_reference_line_collapses_surrounding_blanks",
    "fn test_rtk_md_constant_pinned_to_contextcrawler_filename",
];

/// Top-level entries (file path prefixes) that are skipped entirely. Keep
/// this list tiny — preferring per-line markers over bulk exemptions.
const SKIPPED_PATHS: &[&str] = &[
    // The branding-lint test itself reads forbidden tokens as data.
    "tests/branding_lint.rs",
];

#[test]
fn branding_lint_no_forbidden_upstream_literals_in_src() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = repo_root.join("src");

    let mut failures: Vec<String> = Vec::new();

    for entry in WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|s| s == "rs")
                .unwrap_or(false)
        })
    {
        let rel = entry
            .path()
            .strip_prefix(&repo_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();

        if SKIPPED_PATHS.iter().any(|s| rel == *s) {
            continue;
        }

        let content = fs::read_to_string(entry.path())
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", rel, e));

        // Track which lines fall inside an allowed-function body. Simple
        // brace-depth tracking starting from the `fn` declaration: enter
        // when we see one of ALLOWED_FUNCTION_PREFIXES on the line; exit
        // when net brace count returns to 0.
        let mut in_allowed_fn = false;
        let mut allowed_fn_depth: i64 = 0;

        for (lineno, line) in content.lines().enumerate() {
            let lineno = lineno + 1;

            // Update brace-depth state BEFORE evaluating the line so that
            // the `fn` declaration line itself is treated as "inside".
            if !in_allowed_fn
                && ALLOWED_FUNCTION_PREFIXES.iter().any(|p| line.contains(p))
            {
                in_allowed_fn = true;
                allowed_fn_depth = 0;
            }
            if in_allowed_fn {
                let opens = line.chars().filter(|c| *c == '{').count() as i64;
                let closes = line.chars().filter(|c| *c == '}').count() as i64;
                allowed_fn_depth += opens - closes;
                // We exit on the line whose closes bring depth back to 0,
                // but the closing-brace line itself stays exempt.
                let exit_this_line = allowed_fn_depth <= 0 && (opens + closes) > 0;
                let was_in = in_allowed_fn;
                if exit_this_line {
                    in_allowed_fn = false;
                    allowed_fn_depth = 0;
                }
                if was_in {
                    continue;
                }
            }

            if line.contains(ALLOW_MARKER) {
                continue;
            }
            if STRUCTURAL_ALLOW_NEEDLES.iter().any(|n| line.contains(n)) {
                continue;
            }

            for (needle, why) in FORBIDDEN_TOKENS {
                if line.contains(needle) {
                    failures.push(format!(
                        "  {}:{}  found `{}`  ({})\n      {}",
                        rel,
                        lineno,
                        needle,
                        why,
                        line.trim()
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "\n\n--- branding-lint failures ---\n\
             {} forbidden upstream literal(s) found in production source:\n\n{}\n\n\
             FIX: replace each occurrence with the CONTEXTCRAWLER equivalent\n\
             (constants RTK_MD, RTK_MD_REF in src/hooks/init.rs), or — if the\n\
             reference is intentionally legacy (regression history, cleanup\n\
             code, migration tests) — add `{}` to the end of the line.\n\n\
             This test exists to prevent the rebrand-regression family\n\
             (issues #19, #20, #22, #23) from re-introducing itself silently\n\
             during future upstream rebases.\n",
            failures.len(),
            failures.join("\n\n"),
            ALLOW_MARKER,
        );
    }
}

#[test]
fn branding_lint_canonical_name_present_in_init() {
    // Sanity that the canonical name actually appears where it should, to
    // catch the inverse mistake: someone rips out all "CONTEXTCRAWLER.md"
    // references without re-adding them via the constant. This isn't a
    // perfect check but it costs nothing.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/hooks/init.rs");
    let content = fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("CONTEXTCRAWLER.md"),
        "src/hooks/init.rs no longer mentions CONTEXTCRAWLER.md anywhere — \
         did the rebrand get inverted again?"
    );
    assert!(
        content.contains("@CONTEXTCRAWLER.md"),
        "src/hooks/init.rs no longer mentions @CONTEXTCRAWLER.md — \
         same regression family as #19."
    );
}

#[test]
fn branding_lint_config_files_pin_canonical_package_name() {
    // Config files outside src/ — Cargo.toml's [package].name field and
    // release-please-config.json's "package-name" — also need to read
    // "contextcrawler", not "rtk". The upstream rebase silently set
    // release-please-config.json's package-name back to "rtk", which would
    // have produced rtk-vX.Y.Z tags + release-PR titles. The src/-scoped
    // lint above doesn't cover the build/release-engineering surface, so
    // this extra check pins those two fields explicitly.

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Cargo.toml [package].name — extract via simple line scan to avoid
    // pulling in a TOML parser dependency just for one assertion.
    let cargo = fs::read_to_string(repo_root.join("Cargo.toml"))
        .expect("Cargo.toml readable");
    let mut in_package = false;
    let mut found_name: Option<String> = None;
    for line in cargo.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package && t.starts_with("name") {
            if let Some(eq) = t.find('=') {
                let value = t[eq + 1..].trim().trim_matches('"').to_string();
                found_name = Some(value);
                break;
            }
        }
    }
    assert_eq!(
        found_name.as_deref(),
        Some("contextcrawler"),
        "Cargo.toml [package].name must be \"contextcrawler\" — \
         see issue #19 family."
    );

    // release-please-config.json package-name field. serde_json is already
    // a workspace dep so no new dependency cost.
    let rp = fs::read_to_string(repo_root.join("release-please-config.json"))
        .expect("release-please-config.json readable");
    let parsed: serde_json::Value =
        serde_json::from_str(&rp).expect("release-please-config.json is valid JSON");
    let pkg_name = parsed
        .pointer("/packages/./package-name")
        .and_then(|v| v.as_str());
    assert_eq!(
        pkg_name,
        Some("contextcrawler"),
        "release-please-config.json packages[\".\"].package-name must be \
         \"contextcrawler\" — caught silently set to \"rtk\" by the \
         upstream rebase. Same regression family as #19/#20/#22."
    );
}
