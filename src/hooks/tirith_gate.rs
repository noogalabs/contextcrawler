// SPDX-License-Identifier: MIT
// Part of the ContextCrawler downstream of rtk-ai/rtk.
// Copyright (c) 2026 ContextCrawler contributors.
//
//! Tirith pre-execution gate.
//!
//! Subprocess-calls `tirith check --format json` and parses the verdict.
//! Used by both the legacy `rtk rewrite` path (`hooks::rewrite_cmd`) and
//! the modern `rtk hook claude` path (`hooks::hook_cmd`) so the gate is
//! consistent regardless of which integration the user runs.
//!
//! Subprocess-only invocation; no statically-linked AGPL code.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// Hard cap on how long we wait for `tirith check` before treating it as
/// unavailable. A hung tirith would otherwise block the agent's PreToolUse
/// hook indefinitely (until the host agent itself times out — multi-second
/// freeze of the agent UI).
const TIRITH_TIMEOUT: Duration = Duration::from_secs(8);

/// Hard cap on tirith stdout size. A trusted tirith returns a small JSON
/// verdict; a compromised one could emit gigabytes and OOM us.
const TIRITH_STDOUT_MAX: u64 = 4 * 1024 * 1024;

pub enum Verdict {
    Allow,
    Block { tirith_json: String },
    /// Tirith missing, errored, or returned an unrecognized verdict.
    /// Caller decides fail-open (proceed) vs fail-closed (downgrade).
    Unavailable,
}

pub fn check(cmd: &str) -> Verdict {
    // Soft opt-out for debugging.
    if std::env::var("CONTEXTCRAWLER_TIRITH_DISABLED").as_deref() == Ok("1") {
        return Verdict::Unavailable;
    }

    // Try `tirith` from $PATH; fall back to ~/.cargo/bin/tirith.
    let bin = if which::which("tirith").is_ok() {
        "tirith".to_string()
    } else {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return Verdict::Unavailable,
        };
        let cargo_bin = home.join(".cargo/bin/tirith");
        if !cargo_bin.exists() {
            return Verdict::Unavailable;
        }
        cargo_bin.to_string_lossy().to_string()
    };

    // Tirith puts the verdict in stdout JSON; exit code is 0 even on block.
    // Spawn explicitly (not output()) so we can apply a wall-clock timeout
    // and a stdout size cap. F-01 / F-02 from the 2026-05-15 module audit.
    let mut child = match Command::new(&bin)
        .args([
            "check",
            "--format",
            "json",
            "--non-interactive",
            "--no-daemon",
            "--",
        ])
        .arg(cmd)
        // Don't inherit stdin from the host agent's hook pipe (F-05).
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // stderr to /dev/null, not piped. A noisy tirith would otherwise
        // fill the ~64 KiB kernel pipe buffer and block on write until
        // our 8s wait_timeout fires — turning a successful check into an
        // 8-second stall. We don't surface tirith stderr anywhere, so
        // discarding directly is safe. (Codex review follow-up.)
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Verdict::Unavailable,
    };

    let exit_status = match child.wait_timeout(TIRITH_TIMEOUT) {
        Ok(Some(s)) => s,
        Ok(None) => {
            // Timed out. Kill the child so it doesn't linger; fall through
            // to Unavailable (caller decides fail-open vs fail-closed).
            let _ = child.kill();
            let _ = child.wait();
            return Verdict::Unavailable;
        }
        Err(_) => return Verdict::Unavailable,
    };

    let _ = exit_status; // tirith returns 0 on both allow and block; rely on JSON content.

    // Read piped stdout with a hard size cap.
    let mut stdout_buf = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s
            .by_ref()
            .take(TIRITH_STDOUT_MAX)
            .read_to_end(&mut stdout_buf);
    }
    let stdout = String::from_utf8_lossy(&stdout_buf).to_string();

    // Parse structurally — substring matching on JSON is fragile (pretty-
    // printed output, descriptions containing the word "block", etc.).
    let parsed: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => return Verdict::Unavailable,
    };
    match parsed.get("action").and_then(|x| x.as_str()) {
        Some("block") => Verdict::Block { tirith_json: stdout },
        Some("allow") => Verdict::Allow,
        _ => Verdict::Unavailable,
    }
}

pub fn require_tirith() -> bool {
    std::env::var("CONTEXTCRAWLER_TIRITH_REQUIRED").as_deref() == Ok("1")
}

/// Decide whether an upstream `Allow` verdict should be downgraded.
/// Returns Some((reason, optional_tirith_json)) to downgrade; None to proceed.
pub fn should_downgrade(verdict: &Verdict) -> Option<(&'static str, Option<&str>)> {
    match verdict {
        Verdict::Block { tirith_json } => Some(("tirith_block", Some(tirith_json.as_str()))),
        Verdict::Unavailable if require_tirith() => Some(("tirith_required_unavailable", None)),
        _ => None,
    }
}

/// Append a downgrade event to the ContextCrawler local log.
/// Path: $XDG_DATA_HOME/contextcrawler/downgrades.jsonl
/// (or platform equivalent via dirs::data_local_dir).
/// Best-effort: any I/O error is silently dropped.
pub fn log_downgrade(cmd: &str, reason: &'static str, tirith_json: Option<&str>) {
    let dir = match dirs::data_local_dir() {
        Some(d) => d.join("contextcrawler"),
        None => return,
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("downgrades.jsonl");

    let timestamp = chrono::Utc::now().to_rfc3339();
    let record = match tirith_json {
        Some(json) => format!(
            r#"{{"ts":"{}","reason":"{}","cmd":{},"tirith":{}}}"#,
            timestamp,
            reason,
            json_escape(cmd),
            json.trim(),
        ),
        None => format!(
            r#"{{"ts":"{}","reason":"{}","cmd":{}}}"#,
            timestamp,
            reason,
            json_escape(cmd),
        ),
    };

    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", record);
    }
}

/// Minimal JSON string escape for our log lines.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
