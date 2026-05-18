//! Tier 1 of the bench harness (issue #29) — standalone binary microbench.
//!
//! Per-invocation isolation: each case runs the built contextcrawler binary
//! with `RTK_DB_PATH` pointed at a tempfile so the user's real tracking DB
//! (`~/Library/Application Support/rtk/history.db`) is never touched.
//!
//! At the end of the run, a single aggregate report is written to
//! `bench/results-<git-sha>.{json,md}` (under the repo's bench/ dir, which
//! is gitignored so accumulating runs don't pollute the tree). The .md
//! file is intended for human review and PR diff inclusion; the .json is
//! for machine pre/post comparison.
//!
//! This test never fails the suite on a regression by itself — it produces
//! the numbers. Hard regression gates live in `bench/baseline.json` (when
//! present) and assertions below; the default behaviour is "produce the
//! report and surface the deltas, let the reader decide".

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn binary_path() -> PathBuf {
    // Use Cargo's CARGO_BIN_EXE_<name> env var — set automatically for
    // integration tests, picks up CARGO_TARGET_DIR / release builds /
    // workspace layouts correctly. Avoids the stale-binary trap of
    // hardcoding `target/debug/contextcrawler`. See codex review on #29.
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn fixtures_dir() -> PathBuf {
    manifest_dir().join("tests/fixtures/bench")
}

fn bench_dir() -> PathBuf {
    manifest_dir().join("bench")
}

/// Mirror of the production token estimator at `src/core/tracking.rs`'s
/// `estimate_tokens()` — ~4 chars per token, ceiling. Kept in lock-step so
/// the harness numbers are directly comparable to `contextcrawler gain` and
/// the SQLite history DB. If `estimate_tokens` ever changes formula, this
/// function MUST track it (or the bench numbers stop being comparable to
/// production metrics — see codex review on #29).
fn count_tokens(s: &str) -> usize {
    (s.len() as f64 / 4.0).ceil() as usize
}

fn git_short_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(manifest_dir())
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CaseResult {
    /// Human-readable case name.
    case: String,
    /// The contextcrawler args this case invokes (after the binary path).
    args: Vec<String>,
    /// Path to the input fixture, if any (relative to repo root). `None`
    /// for cases that don't read from a fixed file (e.g. `gain`).
    fixture: Option<String>,
    input_tokens: usize,
    output_tokens: usize,
    saved_tokens: i64,
    savings_pct: f64,
    exec_ms: u128,
    exit_code: i32,
}

#[derive(Debug, Serialize)]
struct Report {
    git_sha: String,
    binary_path: String,
    case_count: usize,
    total_input_tokens: usize,
    total_output_tokens: usize,
    total_saved_tokens: i64,
    weighted_savings_pct: f64,
    cases: Vec<CaseResult>,
}

/// Run one harness case. Reads the fixture (if any), invokes the binary
/// with the given args + isolated DB path, returns a CaseResult.
fn run_case(
    case: &str,
    args: &[&str],
    fixture: Option<&Path>,
    db_path: &Path,
) -> CaseResult {
    let bin = binary_path();
    assert!(
        bin.exists(),
        "binary not built — run `cargo build --bin contextcrawler` first ({})",
        bin.display()
    );

    let (input_tokens, fixture_rel) = match fixture {
        Some(p) => {
            let content = fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", p.display(), e));
            let rel = p
                .strip_prefix(manifest_dir())
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned();
            (count_tokens(&content), Some(rel))
        }
        None => (0, None),
    };

    let start = Instant::now();
    let output = Command::new(&bin)
        .env("RTK_DB_PATH", db_path)
        // Real opt-out env var checked in src/core/telemetry.rs — codex
        // review on #29 caught that the previous draft used a non-existent
        // `RTK_NO_TELEMETRY`, which silently did nothing.
        .env("RTK_TELEMETRY_DISABLED", "1")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("binary invocation failed");
    let elapsed = start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let output_tokens = count_tokens(&stdout);

    let saved = input_tokens as i64 - output_tokens as i64;
    let savings_pct = if input_tokens > 0 {
        100.0 * (saved as f64) / (input_tokens as f64)
    } else {
        0.0
    };

    CaseResult {
        case: case.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        fixture: fixture_rel,
        input_tokens,
        output_tokens,
        saved_tokens: saved,
        savings_pct,
        exec_ms: elapsed.as_millis(),
        exit_code: output.status.code().unwrap_or(-1),
    }
}

fn render_md(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Standalone bench harness — {}\n\n",
        report.git_sha
    ));
    out.push_str(&format!(
        "Binary: `{}`  \nCases: {}  \n**Aggregate**: {} input → {} output, {} saved ({:.1}% weighted)\n\n",
        report.binary_path,
        report.case_count,
        report.total_input_tokens,
        report.total_output_tokens,
        report.total_saved_tokens,
        report.weighted_savings_pct,
    ));
    out.push_str("| Case | Fixture | In | Out | Saved | % | ms | exit |\n");
    out.push_str("|---|---|---:|---:|---:|---:|---:|---:|\n");
    for c in &report.cases {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.1} | {} | {} |\n",
            c.case,
            c.fixture.as_deref().unwrap_or("—"),
            c.input_tokens,
            c.output_tokens,
            c.saved_tokens,
            c.savings_pct,
            c.exec_ms,
            c.exit_code,
        ));
    }
    out
}

#[test]
fn bench_harness_tier1_standalone() {
    // Isolated DB per run — does NOT touch the user's real tracking DB.
    let db_path =
        std::env::temp_dir().join(format!("cc-bench-{}.db", std::process::id()));
    let _ = fs::remove_file(&db_path); // clean slate

    let fx = fixtures_dir();
    assert!(
        fx.exists(),
        "fixtures dir missing: {}",
        fx.display()
    );

    let short = fx.join("short.txt");
    let large = fx.join("large.unknownext");
    let xcstrings = fx.join("sample.xcstrings");
    let code_rs = fx.join("code.rs");

    let large_str = large.to_string_lossy().into_owned();
    let xcstrings_str = xcstrings.to_string_lossy().into_owned();
    let code_str = code_rs.to_string_lossy().into_owned();
    let short_str = short.to_string_lossy().into_owned();

    let cases: Vec<CaseResult> = vec![
        run_case(
            "read_short_passthrough",
            &["read", &short_str],
            Some(&short),
            &db_path,
        ),
        run_case(
            "read_large_unknownext_cap_fires",
            &["read", &large_str],
            Some(&large),
            &db_path,
        ),
        run_case(
            "read_xcstrings_json_route",
            &["read", &xcstrings_str],
            Some(&xcstrings),
            &db_path,
        ),
        run_case(
            "read_rust_minimal_filter",
            &["read", &code_str],
            Some(&code_rs),
            &db_path,
        ),
    ];

    // Aggregate
    let total_in: usize = cases.iter().map(|c| c.input_tokens).sum();
    let total_out: usize = cases.iter().map(|c| c.output_tokens).sum();
    let total_saved = total_in as i64 - total_out as i64;
    let weighted_pct = if total_in > 0 {
        100.0 * (total_saved as f64) / (total_in as f64)
    } else {
        0.0
    };

    let report = Report {
        git_sha: git_short_sha(),
        binary_path: binary_path().to_string_lossy().into_owned(),
        case_count: cases.len(),
        total_input_tokens: total_in,
        total_output_tokens: total_out,
        total_saved_tokens: total_saved,
        weighted_savings_pct: weighted_pct,
        cases,
    };

    // Write report (best-effort; bench/ is gitignored so accumulating
    // runs are fine).
    let bench = bench_dir();
    let _ = fs::create_dir_all(&bench);
    let json_path = bench.join(format!("results-{}.json", report.git_sha));
    let md_path = bench.join(format!("results-{}.md", report.git_sha));
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        let _ = fs::write(&json_path, json);
    }
    let _ = fs::write(&md_path, render_md(&report));

    // Also stream the human-readable report to test stdout so
    // `cargo test --test harness_standalone -- --nocapture` shows it.
    eprintln!("\n{}", render_md(&report));
    eprintln!("Reports written:");
    eprintln!("  json: {}", json_path.display());
    eprintln!("  md:   {}", md_path.display());

    // Sanity assertions — these are FLOORS, not regression gates. They
    // catch "the binary is doing nothing" or "every filter is a no-op",
    // not subtle drifts. Tighter gates belong in a follow-up that diffs
    // against bench/baseline.json.
    for c in &report.cases {
        assert!(
            c.exit_code == 0,
            "case {} exited non-zero (code {}): args={:?}",
            c.case,
            c.exit_code,
            c.args
        );
    }

    // The cap-firing case should save at least 50% of its input.
    let cap_case = report
        .cases
        .iter()
        .find(|c| c.case == "read_large_unknownext_cap_fires")
        .expect("cap case present");
    assert!(
        cap_case.savings_pct >= 50.0,
        "cap case savings dropped below 50% ({:.1}%) — read_filter regression? \
         see bench report for details",
        cap_case.savings_pct
    );

    // The xcstrings case should also save tokens (JSON compaction).
    let xc_case = report
        .cases
        .iter()
        .find(|c| c.case == "read_xcstrings_json_route")
        .expect("xcstrings case present");
    assert!(
        xc_case.savings_pct > 0.0,
        ".xcstrings should be JSON-compacted (got {:.1}% savings)",
        xc_case.savings_pct
    );

    // Cleanup the isolated DB so the temp dir doesn't accumulate.
    let _ = fs::remove_file(&db_path);
}
