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

use std::process::Command;

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
    let output = Command::new(&bin)
        .args([
            "check",
            "--format",
            "json",
            "--non-interactive",
            "--no-daemon",
            "--",
        ])
        .arg(cmd)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Verdict::Unavailable,
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Cheap parse: avoid pulling serde_json into the hot path.
    if stdout.contains("\"action\":\"block\"") {
        Verdict::Block { tirith_json: stdout }
    } else if stdout.contains("\"action\":\"allow\"") {
        Verdict::Allow
    } else {
        Verdict::Unavailable
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
