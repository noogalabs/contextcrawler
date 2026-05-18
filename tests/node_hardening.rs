//! Integration tests for the Node.js toolchain hardening — issue #37.
//!
//! These tests spawn the built `contextcrawler` binary with hostile env
//! vars / args and confirm that:
//!
//!   1. `NODE_OPTIONS=--require <path>` does NOT cause the path to be
//!      `require()`d by a Node child the binary spawns (proves the env
//!      strip in `secure_node_command` actually reaches every Node
//!      subprocess).
//!   2. `NPM_CONFIG_USERCONFIG=<path>` does NOT make npm read the
//!      attacker-controlled .npmrc (proves the dynamic `NPM_CONFIG_*`
//!      sweep works end-to-end).
//!   3. `--reporter <abs-path>` on `vitest` is rejected at the arg-gate
//!      with a clear error mentioning issue #37 and the proxy escape
//!      hatch.
//!   4. Positive: harmless `npm --version` still works (no false
//!      positives from the hardening).
//!
//! Pattern mirrors the rg/grep hardening tests added in #32.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Whether `node` is on PATH. Used to skip the NODE_OPTIONS preload
/// test in CI environments that don't ship Node. npm requires Node so
/// in practice it's always there on dev machines, but we keep the
/// guard so the suite stays green on minimal containers.
fn have_node() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether `npm` is on PATH.
fn have_npm() -> bool {
    Command::new("npm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Tempdir cleanup helper — wraps a closure that gets a unique
/// tempdir, and removes it at the end (best-effort).
fn with_tempdir<F: FnOnce(&std::path::Path)>(label: &str, f: F) {
    let mut dir = std::env::temp_dir();
    let nonce = format!(
        "ctxc-node-harden-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    dir.push(nonce);
    fs::create_dir_all(&dir).expect("create tempdir");
    f(&dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn node_options_require_does_not_execute_evil_js_via_tsc() {
    // ---------------------------------------------------------------
    // The kill shot: set NODE_OPTIONS=--require /tmp/evil.js, run a
    // contextcrawler command that spawns a Node tool (`tsc --version`),
    // and confirm evil.js was NEVER loaded. evil.js's job is to touch
    // a sentinel file; if the sentinel exists after the run, the env
    // strip leaked.
    //
    // We use `tsc --version` because (a) tsc falls back to `npx tsc`
    // which is always available where npm is, and (b) `--version`
    // exits immediately so we don't pay test-suite latency for a real
    // typecheck.
    // ---------------------------------------------------------------

    if !have_node() {
        eprintln!("[skip] node not on PATH; cannot exercise NODE_OPTIONS preload");
        return;
    }

    with_tempdir("node-options", |dir| {
        let evil_js = dir.join("evil.js");
        let marker = dir.join("marker-tsc");

        // evil.js: if Node loads us via --require, touch the marker.
        // The marker path is hardcoded into the JS so the only way it
        // exists after the run is if Node actually required this file.
        fs::write(
            &evil_js,
            format!(
                "require('fs').writeFileSync({:?}, '');\n",
                marker.to_string_lossy()
            ),
        )
        .expect("write evil.js");

        // Sanity: marker should NOT exist before the run.
        assert!(!marker.exists(), "marker pre-existed before test ran");

        let node_options = format!("--require {}", evil_js.to_string_lossy());

        // Spawn contextcrawler with the hostile env var. We exercise
        // the `tsc` route — it's wired through secure_node_command.
        // `--version` will fail fast if tsc isn't installed, but the
        // critical assertion is on the marker, not the exit code.
        let _ = Command::new(binary_path())
            .args(["tsc", "--version"])
            .env("NODE_OPTIONS", &node_options)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        assert!(
            !marker.exists(),
            "SECURITY: NODE_OPTIONS=--require evil.js was honored by a Node \
             child of contextcrawler — env strip did NOT reach the subprocess. \
             Marker file appeared at {:?}",
            marker
        );
    });
}

#[test]
fn npm_config_userconfig_is_ignored() {
    // ---------------------------------------------------------------
    // `NPM_CONFIG_USERCONFIG=<path>` tells npm to read that .npmrc as
    // the user config. An attacker .npmrc can set `registry=` to an
    // exfil endpoint (and other dangerous knobs like ignore-scripts /
    // script-shell on older npms). We confirm contextcrawler strips
    // the env var so npm falls back to the default registry.
    // ---------------------------------------------------------------

    if !have_npm() {
        eprintln!("[skip] npm not on PATH; cannot exercise NPM_CONFIG_USERCONFIG");
        return;
    }

    with_tempdir("npm-config", |dir| {
        let evil_npmrc = dir.join("evil-npmrc");
        fs::write(
            &evil_npmrc,
            "registry=https://attacker.example.com/evil-registry/\n",
        )
        .expect("write evil .npmrc");

        let out = Command::new(binary_path())
            .args(["npm", "config", "get", "registry"])
            .env("NPM_CONFIG_USERCONFIG", &evil_npmrc)
            // Be defensive: also wipe any pre-existing per-user
            // overrides from the parent env that could shadow the
            // assertion. We're testing strip behavior, not config
            // precedence.
            .env_remove("npm_config_userconfig")
            .stderr(Stdio::null())
            .output()
            .expect("spawn contextcrawler npm config get registry");

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("attacker.example.com"),
            "SECURITY: attacker-controlled registry URL leaked into \
             npm config output — NPM_CONFIG_USERCONFIG was honored. \
             stdout was: {}",
            stdout
        );
    });
}

#[test]
fn vitest_rejects_reporter_path() {
    // Arg-gate test: a path-shape value for --reporter must be
    // refused with the issue-#37 error and proxy hatch hint, BEFORE
    // vitest is spawned. No vitest install needed — the gate fires
    // before exec.

    let out = Command::new(binary_path())
        .args(["vitest", "--reporter", "/tmp/evil-reporter.js"])
        .output()
        .expect("spawn contextcrawler vitest");

    assert!(
        !out.status.success(),
        "expected non-zero exit when path-shape --reporter is passed"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    assert!(
        combined.contains("#37"),
        "expected error message to cite issue #37, got: {}",
        combined
    );
    assert!(
        combined.contains("contextcrawler proxy"),
        "expected error message to mention the proxy escape hatch, got: {}",
        combined
    );
    assert!(
        combined.contains("--reporter"),
        "expected error message to name the offending flag, got: {}",
        combined
    );
}

#[test]
fn npm_version_still_works() {
    // Positive control: the hardening must NOT break harmless commands.
    if !have_npm() {
        eprintln!("[skip] npm not on PATH; cannot run positive control");
        return;
    }

    let out = Command::new(binary_path())
        .args(["npm", "--version"])
        .output()
        .expect("spawn contextcrawler npm --version");

    assert!(
        out.status.success(),
        "`contextcrawler npm --version` should succeed; stderr was: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // npm --version emits a semver line like `10.8.2`. Just verify
    // we got SOME digit-dot output, not an error.
    assert!(
        stdout.chars().any(|c| c.is_ascii_digit()),
        "expected npm version output to contain digits, got: {}",
        stdout
    );
}
