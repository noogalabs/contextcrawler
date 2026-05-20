//! Integration tests for issue #53 — proxy bypass nudge.
//!
//! These tests spawn the real `contextcrawler` binary and assert that the
//! nudge fires on stderr when expected and stays silent when suppressed.
//! Unit tests in `src/main.rs` only cover `proxy_wrapped_equivalent()` in
//! isolation; this suite proves the end-to-end env→nudge→suppression path.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Run the binary with stderr piped, returning the captured stderr text.
/// We don't care about stdout for the nudge tests. `extra_env` is a list of
/// `(key, value)` pairs added to the child env on top of `clean_env` defaults.
fn run_capture_stderr(args: &[&str], extra_env: &[(&str, &str)]) -> String {
    let _guard = common::env_lock();
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    // Issue #91 — sentinel for release-built spawned binary.
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
    // Start from a known-clean env baseline so test results don't depend on
    // whatever the host shell happens to export. Then layer extras on top.
    cmd.env_remove("CONTEXTCRAWLER_NO_PROXY_NUDGE");
    cmd.env_remove("CI");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn contextcrawler");
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn proxy_nudge_suppressed_by_env_var() {
    // `CONTEXTCRAWLER_NO_PROXY_NUDGE=1` must silence the nudge regardless of
    // whether the proxied tool would otherwise trigger one. Use `whoami` —
    // it exists on every unix and has no wrapper, but the path the test
    // exercises is the env-var check (which short-circuits before the
    // wrapper lookup).
    let stderr = run_capture_stderr(
        &["proxy", "whoami"],
        &[("CONTEXTCRAWLER_NO_PROXY_NUDGE", "1")],
    );
    assert!(
        !stderr.contains("bypasses the wrapped filter"),
        "nudge fired despite CONTEXTCRAWLER_NO_PROXY_NUDGE=1; stderr was:\n{}",
        stderr
    );
}

#[test]
fn proxy_nudge_suppressed_by_ci_env() {
    // `CI=*` must silence the nudge so pipeline logs stay clean.
    let stderr = run_capture_stderr(&["proxy", "whoami"], &[("CI", "true")]);
    assert!(
        !stderr.contains("bypasses the wrapped filter"),
        "nudge fired despite CI=true; stderr was:\n{}",
        stderr
    );
}

/// Run the binary, returning `(stdout, stderr, exit_code)`.
fn run_proxy(args: &[&str]) -> (String, String, i32) {
    let _guard = common::env_lock();
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
    cmd.env("CONTEXTCRAWLER_NO_PROXY_NUDGE", "1");
    cmd.env_remove("CI");
    let out = cmd.output().expect("spawn contextcrawler");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

/// #100 G2 Codex 2nd pass — CRITICAL 2: a proxy `argv[0]` containing a path
/// separator must be REJECTED, not executed. Otherwise
/// `proxy ../../evil/npm` runs the attacker's binary while any
/// basename-normalised hardening was computed for the bare `npm`.
#[test]
fn proxy_rejects_path_separator_argv0() {
    for bad in ["../../evil/npm", "/usr/bin/whoami", "./local-tool", "sub/dir/cmd"] {
        let (_stdout, stderr, code) = run_proxy(&["proxy", bad, "--version"]);
        assert_ne!(
            code, 0,
            "proxy must reject path-bearing argv[0] `{bad}`, exit was 0"
        );
        assert!(
            stderr.contains("path-bearing"),
            "expected path-bearing rejection for `{bad}`, stderr was:\n{stderr}"
        );
    }
}

/// A bare tool name (no separator) is still accepted by the proxy path.
#[test]
fn proxy_accepts_bare_tool_name() {
    let (_stdout, _stderr, code) = run_proxy(&["proxy", "whoami"]);
    assert_eq!(code, 0, "proxy of a bare tool name must succeed");
}

/// #100 G2 Codex 2nd pass — PARTIAL 3: the proxy flag is `--via-shell`, so a
/// proxied child whose OWN argument is literally `--shell` is passed through
/// to the child intact rather than stolen by clap.
#[test]
fn proxy_passes_literal_shell_arg_to_child() {
    // `echo --shell` should print `--shell` on stdout. `--shell` is no longer
    // a contextcrawler flag, so clap leaves it in the child argv.
    let (stdout, _stderr, code) = run_proxy(&["proxy", "echo", "--shell"]);
    assert_eq!(code, 0, "proxy echo --shell must succeed");
    assert!(
        stdout.contains("--shell"),
        "child must receive literal `--shell` arg; stdout was:\n{stdout}"
    );
}

/// The renamed `--via-shell` flag still works as the explicit shell opt-in.
#[test]
fn proxy_via_shell_flag_still_functions() {
    let (stdout, _stderr, code) = run_proxy(&["proxy", "--via-shell", "echo hello"]);
    assert_eq!(code, 0, "proxy --via-shell must succeed");
    assert!(
        stdout.contains("hello"),
        "--via-shell should word-split and run the command; stdout was:\n{stdout}"
    );
}

#[test]
fn proxy_nudge_suppressed_when_stderr_not_tty() {
    // When the test harness captures stderr (which it always does), stderr is
    // a pipe, not a tty. The nudge MUST stay silent in that case so it doesn't
    // pollute test output or script consumers.
    //
    // This is the test-harness-friendly version of the tty check: even with
    // both env-var suppressions explicitly removed, the nudge should NOT fire
    // because our pipe-capture isn't a terminal.
    let _guard = common::env_lock();
    let mut cmd = Command::new(binary_path());
    cmd.args(["proxy", "sed", "--version"]);
    // Issue #91 — sentinel for release-built spawned binary.
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
    cmd.env_remove("CONTEXTCRAWLER_NO_PROXY_NUDGE");
    cmd.env_remove("CI");
    let out = cmd.output().expect("spawn contextcrawler");
    drop(_guard);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("bypasses the wrapped filter"),
        "nudge fired despite stderr not being a tty; stderr was:\n{}",
        stderr
    );
}
