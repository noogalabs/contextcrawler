//! Integration tests for the Claude Code PreToolUse hook fail-CLOSED paths
//! (#100 G2 Codex 2nd pass).
//!
//! These spawn the real `contextcrawler hook claude` binary and assert that
//! the hook emits the Claude `permissionDecision: deny` JSON the harness
//! blocks on, rather than passing a command through unchecked.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Pipe `stdin` into `contextcrawler hook claude`, return its stdout.
fn run_hook_claude(stdin: &[u8]) -> String {
    let mut child = Command::new(binary_path())
        .arg("hook")
        .arg("claude")
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .env("RTK_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn contextcrawler hook claude");
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(stdin);
    }
    let out = child.wait_with_output().expect("hook wait failed");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn assert_deny_json(stdout: &str, ctx: &str) {
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "{ctx}: hook emitted nothing — it must fail CLOSED with a deny verdict"
    );
    let v: serde_json::Value =
        serde_json::from_str(trimmed).unwrap_or_else(|e| panic!("{ctx}: stdout not JSON: {e}\n{trimmed}"));
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "{ctx}: expected permissionDecision=deny, got:\n{trimmed}"
    );
}

/// Malformed JSON payload → the hook must emit deny JSON (direct assertion,
/// not merely "no rewrite").
#[test]
fn malformed_json_emits_deny() {
    let stdout = run_hook_claude(b"{not valid json at all");
    assert_deny_json(&stdout, "malformed JSON");
}

/// A `command` field that is not a string is a payload-shape error → deny.
#[test]
fn non_string_command_emits_deny() {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": 42 }
    })
    .to_string();
    let stdout = run_hook_claude(payload.as_bytes());
    assert_deny_json(&stdout, "non-string command");
}

/// Oversized stdin (> 1 MiB cap) → the hook cannot reason about the payload,
/// so it must fail CLOSED with a deny verdict.
#[test]
fn oversized_stdin_emits_deny() {
    // 1 MiB cap + slack. Wrap a real-looking envelope so the failure is the
    // size cap, not a JSON shape error.
    let filler = "A".repeat(1_200_000);
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {filler}"}}}}"#
    );
    let stdout = run_hook_claude(payload.as_bytes());
    assert_deny_json(&stdout, "oversized stdin");
}
