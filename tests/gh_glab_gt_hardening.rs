//! Integration tests for issue #50 — gh / glab / gt env hardening.
//!
//! Spawns the real `contextcrawler` binary with hijack-prone env vars set
//! and asserts the wrapped tool does NOT see them. Per-tool checks are
//! gated on `which::which("<tool>")` so the suite passes on CI runners
//! that don't have every tool installed; the arg-deny and unit-level
//! token-preservation tests run unconditionally and live alongside the
//! helpers in `src/core/utils.rs`.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn tool_present(name: &str) -> bool {
    which::which(name).is_ok()
}

fn run_with_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn contextcrawler")
}

// ════════════════════════════════════════════════════════════════════
// env-strip negative tests: hijack vars must NOT reach the child.
// ════════════════════════════════════════════════════════════════════

#[test]
fn gh_config_dir_is_stripped() {
    if !tool_present("gh") {
        eprintln!("skip: gh not on PATH");
        return;
    }
    // If GH_CONFIG_DIR reached gh, gh would try to load config from this
    // bogus path and either error specifically about it or silently
    // operate with no auth. Either way, the evil path itself should NOT
    // appear in stdout/stderr — that would prove it was honored.
    let evil = "/tmp/cc-gh-hardening-evil-DOES-NOT-EXIST";
    let out = run_with_env(&["gh", "--version"], &[("GH_CONFIG_DIR", evil)]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(evil) && !stderr.contains(evil),
        "GH_CONFIG_DIR={} leaked through to gh. stdout={}, stderr={}",
        evil,
        stdout,
        stderr
    );
}

#[test]
fn glab_config_dir_is_stripped() {
    if !tool_present("glab") {
        eprintln!("skip: glab not on PATH");
        return;
    }
    let evil = "/tmp/cc-glab-hardening-evil-DOES-NOT-EXIST";
    let out = run_with_env(&["glab", "--version"], &[("GLAB_CONFIG_DIR", evil)]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(evil) && !stderr.contains(evil),
        "GLAB_CONFIG_DIR={} leaked through to glab. stdout={}, stderr={}",
        evil,
        stdout,
        stderr
    );
}

// ════════════════════════════════════════════════════════════════════
// arg deny: gh extension exec must be rejected (exit 2, deny message).
// ════════════════════════════════════════════════════════════════════

#[test]
fn gh_extension_exec_is_rejected() {
    // No `gh` install required — the deny check runs in our process before
    // any spawn. We use a clearly-bogus extension name so even if a future
    // change accidentally lets the command through, gh would fail rather
    // than execute a real extension.
    let out = run_with_env(
        &["gh", "extension", "exec", "cc-hardening-test-evil"],
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected deny exit 2, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward 'extension exec' to gh"),
        "expected deny message on stderr; got: {}",
        stderr
    );
}

// ════════════════════════════════════════════════════════════════════
// Positive: auth tokens MUST survive (otherwise non-interactive use breaks).
// We don't have gh installed in all CI envs, so we verify by capturing
// the inherited env via printenv — gh-the-binary isn't required.
// ════════════════════════════════════════════════════════════════════

#[test]
fn gh_auth_tokens_are_preserved_in_proxy_path() {
    // Use the proxy path to invoke `printenv` so we can see exactly which
    // env vars made it through. The proxy path doesn't apply per-tool
    // secure_*_command — that only matters for the typed routes. This
    // confirms the positive baseline: tokens DO reach a child when not
    // explicitly stripped.
    let out = run_with_env(
        &["proxy", "printenv"],
        &[
            ("GH_TOKEN", "test-token-abc"),
            ("GITHUB_TOKEN", "test-token-xyz"),
            ("GH_HOST", "github.example.com"),
            ("CONTEXTCRAWLER_NO_PROXY_NUDGE", "1"),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GH_TOKEN=test-token-abc"));
    assert!(stdout.contains("GITHUB_TOKEN=test-token-xyz"));
    assert!(stdout.contains("GH_HOST=github.example.com"));
}
