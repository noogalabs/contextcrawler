//! Tier 2 of the bench harness (issue #29) — Claude Code end-to-end hook bench.
//!
//! Where Tier 1 (`tests/harness_standalone.rs`) drives the contextcrawler
//! binary directly against fixture files, Tier 2 exercises the full
//! **Claude Code PreToolUse hook pipeline** the way a user actually hits it:
//!
//!   1. Stand up an isolated `~/.claude` lookalike in a tempdir, wiring
//!      `contextcrawler hook claude` as the PreToolUse handler in a
//!      synthetic `settings.json`. (This proves we're invoking the same
//!      shape Claude Code would; we don't actually launch Claude Code.)
//!   2. For each fixture command, build a synthetic Claude Code tool_use
//!      envelope (`{"tool_name":"Bash","tool_input":{"command":"..."}}`),
//!      pipe it through `contextcrawler hook claude` and parse the
//!      rewritten command out of `hookSpecificOutput.updatedInput.command`.
//!   3. Execute BOTH the raw command and the rewritten command against
//!      the repo working tree, count output tokens for each, and record
//!      the realised end-to-end savings the hook delivered. This is the
//!      number a Claude Code user would have seen in their context window.
//!   4. Aggregate into the same JSON+MD report shape Tier 1 produces,
//!      written to `bench/claude-code-<git-sha>.{json,md}`.
//!
//! Isolation:
//!   - `RTK_DB_PATH` points the tracking DB at a tempfile, so the user's
//!     real `history.db` (`~/Library/Application Support/rtk/history.db`)
//!     stays untouched. Same trick Tier 1 uses.
//!   - `RTK_TELEMETRY_DISABLED=1` mirrors Tier 1, in case the hook ever
//!     starts pinging telemetry.
//!   - The synthetic `~/.claude` lives in a tempdir and is cleaned up on
//!     test exit. We do NOT touch the real `~/.claude`.
//!
//! Skip conditions (graceful, no test failure):
//!   - Binary not built. `CARGO_BIN_EXE_contextcrawler` is set by cargo
//!     for integration tests, so this is rare — but if the build was
//!     skipped (e.g. running from a stale workspace) we bail with a
//!     warning instead of panicking.
//!
//! Idempotency: re-running the test produces the same JSON report modulo
//! wall-clock fields (`exec_ms`). Token counts, savings %, exit codes,
//! and rewritten commands are deterministic.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn binary_path() -> PathBuf {
    // Same pattern as harness_standalone.rs — CARGO_BIN_EXE_<name> is set
    // by cargo for integration tests and picks up release/CARGO_TARGET_DIR
    // layouts correctly. Hardcoding `target/debug/...` is the stale-binary
    // trap codex review on #29 caught.
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn bench_dir() -> PathBuf {
    manifest_dir().join("bench")
}

fn fixtures_path() -> PathBuf {
    manifest_dir().join("tests/fixtures/bench_commands.txt")
}

/// Mirror of `src/core/tracking.rs::estimate_tokens()` — ~4 chars per
/// token, ceiling. Tracked in lock-step with Tier 1 so both reports use
/// the same units. If estimate_tokens ever changes, this MUST track it.
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
    /// The raw command as it would arrive from Claude Code.
    raw_command: String,
    /// What the hook rewrote it to (or the raw command, if no rewrite).
    rewritten_command: String,
    /// True if the hook actually emitted a rewrite (vs no-op passthrough).
    hook_rewrote: bool,
    /// Token count of stdout when running the raw command.
    raw_output_tokens: usize,
    /// Token count of stdout when running the rewritten command.
    rewritten_output_tokens: usize,
    /// raw - rewritten. Positive = the hook saved tokens for the LLM.
    saved_tokens: i64,
    savings_pct: f64,
    /// Wall-clock for the hook invocation itself (envelope -> verdict).
    hook_ms: u128,
    /// Wall-clock for raw command execution.
    raw_exec_ms: u128,
    /// Wall-clock for rewritten command execution.
    rewritten_exec_ms: u128,
    raw_exit_code: i32,
    rewritten_exit_code: i32,
    /// True if either execution failed (e.g. binary missing on this host).
    /// Used to skip a case from aggregate savings rather than poison it.
    skipped: bool,
    skip_reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    tier: &'static str,
    git_sha: String,
    binary_path: String,
    fake_claude_home: String,
    case_count: usize,
    cases_executed: usize,
    cases_skipped: usize,
    cases_rewritten: usize,
    total_raw_output_tokens: usize,
    total_rewritten_output_tokens: usize,
    total_saved_tokens: i64,
    weighted_savings_pct: f64,
    cases: Vec<CaseResult>,
}

/// Build a synthetic `~/.claude` directory tree that points the
/// PreToolUse hook at the contextcrawler binary under test. We don't
/// actually launch Claude Code — this is just proof that the wiring the
/// hook expects (a settings.json with the right hook command) is intact.
/// The real assertion is that `contextcrawler hook claude` produces a
/// usable rewrite given a synthetic envelope.
fn write_fake_claude_home(root: &Path, bin: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    let bin_str = bin.to_string_lossy();
    // Match the same hook shape `contextcrawler init` would write. Kept
    // minimal — Claude Code only needs `command` and `hooks.PreToolUse`
    // to dispatch. If the production init schema ever drifts, the hook
    // invocation below (which is what actually gets benched) keeps
    // working because it calls the binary directly.
    let settings = format!(
        r#"{{
  "hooks": {{
    "PreToolUse": [
      {{
        "matcher": "Bash",
        "hooks": [
          {{
            "type": "command",
            "command": "{bin_str} hook claude"
          }}
        ]
      }}
    ]
  }}
}}
"#
    );
    fs::write(root.join("settings.json"), settings)?;
    Ok(())
}

/// Invoke `contextcrawler hook claude` with a synthetic Claude Code
/// PreToolUse envelope. Returns the rewritten command (if any) along
/// with hook wall-clock time.
fn run_hook(bin: &Path, db_path: &Path, raw_cmd: &str) -> (Option<String>, u128) {
    let envelope = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": raw_cmd }
    })
    .to_string();

    let start = Instant::now();
    let mut child = Command::new(bin)
        .arg("hook")
        .arg("claude")
        .env("RTK_DB_PATH", db_path)
        .env("RTK_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn contextcrawler hook claude");

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(envelope.as_bytes());
    }
    let output = child.wait_with_output().expect("hook process wait failed");
    let elapsed = start.elapsed().as_millis();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        // Hook passes through silently (no rewrite). This is the
        // documented no-op shape — see process_claude_payload's Skip arm.
        return (None, elapsed);
    }

    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return (None, elapsed),
    };

    let rewritten = v
        .pointer("/hookSpecificOutput/updatedInput/command")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());

    (rewritten, elapsed)
}

/// Execute a shell command line and return (stdout, exit_code, ms).
/// Uses `sh -c` so the harness handles pipes, redirects, env prefixes
/// etc. exactly the way Claude Code would dispatch them.
fn run_shell(cmd_line: &str) -> (String, i32, u128) {
    let start = Instant::now();
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd_line)
        .current_dir(manifest_dir())
        .env("RTK_TELEMETRY_DISABLED", "1")
        // Suppress pager/interactive prompts that would hang the harness.
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let elapsed = start.elapsed().as_millis();

    match output {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            o.status.code().unwrap_or(-1),
            elapsed,
        ),
        Err(_) => (String::new(), -1, elapsed),
    }
}

/// Substitute `rtk` -> the test binary path so the rewritten command
/// actually exercises the contextcrawler binary under test, not whatever
/// global `rtk`/`contextcrawler` happens to be on PATH. Matches the
/// pattern Claude Code users see (the hook emits `rtk <cmd>`, and the
/// global shim resolves to the installed binary).
fn resolve_rtk_prefix(rewritten: &str, bin: &Path) -> String {
    let bin_str = bin.to_string_lossy().into_owned();
    // Post-rebrand the hook emits `contextcrawler …`; pre-rebrand it emitted
    // `rtk …`. Handle both so this harness exercises the test binary
    // (target/debug/contextcrawler) rather than whatever stale global binary
    // happens to be on PATH (which would also pollute the production DB
    // because it predates the issue #91 fix).
    if let Some(rest) = rewritten.strip_prefix("contextcrawler ") {
        format!("{bin_str} {rest}")
    } else if rewritten == "contextcrawler" {
        bin_str
    } else if let Some(rest) = rewritten.strip_prefix("rtk ") {
        format!("{bin_str} {rest}")
    } else if rewritten == "rtk" {
        bin_str
    } else {
        // Compound commands like `cd "/tmp" && rtk git status`: replace
        // every " rtk " / " contextcrawler " token boundary too. Keep this
        // conservative — literal-substring replacement only.
        rewritten
            .replace(" contextcrawler ", &format!(" {bin_str} "))
            .replace(" rtk ", &format!(" {bin_str} "))
    }
}

fn parse_fixtures(path: &Path) -> Vec<String> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn run_case(bin: &Path, db_path: &Path, raw_cmd: &str) -> CaseResult {
    let (rewritten_opt, hook_ms) = run_hook(bin, db_path, raw_cmd);

    let hook_rewrote = rewritten_opt.is_some();
    let rewritten_command = rewritten_opt
        .clone()
        .unwrap_or_else(|| raw_cmd.to_string());

    // Always execute the raw command so we have the baseline token count.
    let (raw_stdout, raw_exit, raw_ms) = run_shell(raw_cmd);
    let raw_output_tokens = count_tokens(&raw_stdout);

    let (rewritten_stdout, rewritten_exit, rewritten_ms) = if hook_rewrote {
        let resolved = resolve_rtk_prefix(&rewritten_command, bin);
        run_shell(&resolved)
    } else {
        // No rewrite — both numbers are identical by definition.
        (raw_stdout.clone(), raw_exit, raw_ms)
    };
    let rewritten_output_tokens = count_tokens(&rewritten_stdout);

    // Skip cases where the raw command isn't even available on this
    // host (exit 127 = command not found). Without this, a missing
    // `htop` poisons the aggregate with a phantom 100% savings.
    let (skipped, skip_reason) = if raw_exit == 127 {
        (
            true,
            Some("raw command not available on this host (exit 127)".to_string()),
        )
    } else {
        (false, None)
    };

    let saved = raw_output_tokens as i64 - rewritten_output_tokens as i64;
    let savings_pct = if raw_output_tokens > 0 {
        100.0 * (saved as f64) / (raw_output_tokens as f64)
    } else {
        0.0
    };

    CaseResult {
        raw_command: raw_cmd.to_string(),
        rewritten_command,
        hook_rewrote,
        raw_output_tokens,
        rewritten_output_tokens,
        saved_tokens: saved,
        savings_pct,
        hook_ms,
        raw_exec_ms: raw_ms,
        rewritten_exec_ms: rewritten_ms,
        raw_exit_code: raw_exit,
        rewritten_exit_code: rewritten_exit,
        skipped,
        skip_reason,
    }
}

fn render_md(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Claude Code hook bench (Tier 2) — {}\n\n",
        report.git_sha
    ));
    out.push_str(&format!(
        "Binary: `{}`  \nFake `~/.claude`: `{}`  \nCases: {} ({} executed, {} skipped, {} rewritten)  \n**Aggregate**: {} raw out → {} rewritten out, {} saved ({:.1}% weighted)\n\n",
        report.binary_path,
        report.fake_claude_home,
        report.case_count,
        report.cases_executed,
        report.cases_skipped,
        report.cases_rewritten,
        report.total_raw_output_tokens,
        report.total_rewritten_output_tokens,
        report.total_saved_tokens,
        report.weighted_savings_pct,
    ));
    out.push_str("| Raw command | Rewritten | Hook ms | Raw out | Rewritten out | Saved | % | Skipped |\n");
    out.push_str("|---|---|---:|---:|---:|---:|---:|---|\n");
    for c in &report.cases {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {:.1} | {} |\n",
            c.raw_command,
            c.rewritten_command,
            c.hook_ms,
            c.raw_output_tokens,
            c.rewritten_output_tokens,
            c.saved_tokens,
            c.savings_pct,
            if c.skipped { c.skip_reason.as_deref().unwrap_or("yes") } else { "no" },
        ));
    }
    out
}

#[test]
fn bench_harness_tier2_claude_code() {
    let bin = binary_path();
    if !bin.exists() {
        // Graceful skip — see Tier 1 for the same pattern. In normal
        // `cargo test` invocations cargo guarantees this exists, but
        // running the .rs file directly from a stale workspace would
        // otherwise crash.
        eprintln!(
            "SKIP: contextcrawler binary not built at {} — \
             run `cargo build --bin contextcrawler` first",
            bin.display()
        );
        return;
    }

    // Isolated tracking DB — never touch the user's real history.db.
    let db_path = std::env::temp_dir()
        .join(format!("cc-bench-tier2-{}.db", std::process::id()));
    let _ = fs::remove_file(&db_path);

    // Synthetic ~/.claude tempdir. We hold the TempDir for the duration
    // of the test so its Drop cleans up; we never touch the real ~/.claude.
    let claude_home = tempfile::tempdir().expect("failed to create temp ~/.claude");
    write_fake_claude_home(claude_home.path(), &bin)
        .expect("failed to write fake ~/.claude/settings.json");

    // Sanity: the settings.json we just wrote should at least parse.
    let settings_raw = fs::read_to_string(claude_home.path().join("settings.json"))
        .expect("fake settings.json missing after write");
    let _settings_json: serde_json::Value = serde_json::from_str(&settings_raw)
        .expect("fake settings.json must be valid JSON");

    let fixtures = parse_fixtures(&fixtures_path());
    assert!(
        !fixtures.is_empty(),
        "no fixtures parsed from {} — check the file is committed",
        fixtures_path().display()
    );

    let cases: Vec<CaseResult> = fixtures
        .iter()
        .map(|cmd| run_case(&bin, &db_path, cmd))
        .collect();

    // Aggregate only over executed (non-skipped) cases. Skipped cases
    // (e.g. `htop` not installed on this host) would otherwise produce
    // phantom 0/0 savings and dilute the headline number.
    let executed: Vec<&CaseResult> = cases.iter().filter(|c| !c.skipped).collect();
    let total_raw: usize = executed.iter().map(|c| c.raw_output_tokens).sum();
    let total_rewritten: usize = executed.iter().map(|c| c.rewritten_output_tokens).sum();
    let total_saved = total_raw as i64 - total_rewritten as i64;
    let weighted_pct = if total_raw > 0 {
        100.0 * (total_saved as f64) / (total_raw as f64)
    } else {
        0.0
    };
    let cases_executed = executed.len();
    let cases_skipped = cases.len() - cases_executed;
    let cases_rewritten = cases.iter().filter(|c| c.hook_rewrote).count();

    let report = Report {
        tier: "claude-code",
        git_sha: git_short_sha(),
        binary_path: bin.to_string_lossy().into_owned(),
        fake_claude_home: claude_home.path().to_string_lossy().into_owned(),
        case_count: cases.len(),
        cases_executed,
        cases_skipped,
        cases_rewritten,
        total_raw_output_tokens: total_raw,
        total_rewritten_output_tokens: total_rewritten,
        total_saved_tokens: total_saved,
        weighted_savings_pct: weighted_pct,
        cases,
    };

    let bench = bench_dir();
    let _ = fs::create_dir_all(&bench);
    let json_path = bench.join(format!("claude-code-{}.json", report.git_sha));
    let md_path = bench.join(format!("claude-code-{}.md", report.git_sha));
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        let _ = fs::write(&json_path, json);
    }
    let _ = fs::write(&md_path, render_md(&report));

    eprintln!("\n{}", render_md(&report));
    eprintln!("Reports written:");
    eprintln!("  json: {}", json_path.display());
    eprintln!("  md:   {}", md_path.display());

    // Sanity floors — these catch "the hook is dead" or "the hook
    // matched nothing", not subtle drifts. Tighter regression gates
    // belong in a follow-up that diffs bench/baseline-tier2.json.

    // The hook MUST rewrite at least one fixture. If every fixture
    // falls through to passthrough something is broken in the
    // discover/registry layer (or the fixtures file got nuked).
    assert!(
        report.cases_rewritten > 0,
        "hook rewrote 0/{} fixtures — discover registry broken?",
        report.case_count
    );

    // Aggregate savings should be non-negative — the hook should never
    // make things worse on average. (Per-case regressions are noted but
    // not failed; the report carries the detail.)
    assert!(
        report.weighted_savings_pct >= 0.0,
        "Aggregate savings went negative ({:.1}%) — the hook is now \
         producing MORE tokens than the raw command. See report for the \
         offending case(s).",
        report.weighted_savings_pct
    );

    // Cleanup the isolated DB; the TempDir Drop handles claude_home.
    let _ = fs::remove_file(&db_path);
}
