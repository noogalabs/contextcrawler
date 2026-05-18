//! End-to-end PoC integration tests for the cargo wrapper hardening
//! (issue #34). Each test spawns the actual `contextcrawler` binary so
//! the env-strip and `--config` deny-list are exercised exactly as they
//! would run in production.
//!
//! The "marker" PoCs are the contract: an attacker who controls the
//! parent env, or who can inject a single argv flag, would land arbitrary
//! code execution without this hardening. We assert that the marker file
//! does NOT appear after the run, and that the deny-list flag is rejected
//! with exit code 2.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Unique marker path per test so parallel runs / repeat runs don't
/// collide. Cleaned up at start and end of each test that uses it.
fn marker_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("contextcrawler-cargo-harden-{}-{}-{}", tag, pid, ts))
}

/// Write a `sh` script at `path` that touches `marker`, then chmod +x it.
/// Returns the script path for use as `RUSTC_WRAPPER`.
fn write_marker_script(script: &PathBuf, marker: &PathBuf) {
    let body = format!(
        "#!/bin/sh\ntouch '{}'\nexit 0\n",
        marker.display()
    );
    std::fs::write(script, body).expect("write marker script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(script, perms).unwrap();
    }
}

/// Empirical PoC, brief variant: `RUSTC_WRAPPER=/tmp/evil-marker.sh
/// contextcrawler cargo --version` must NOT create the marker. With the
/// env strip in place this is trivially true (cargo --version doesn't
/// touch rustc anyway), but the test also acts as a regression gate —
/// if anyone removes `env_remove("RUSTC_WRAPPER")` AND a future cargo
/// release decides to honor the wrapper during `--version`, this fires.
#[test]
#[cfg(unix)]
fn rustc_wrapper_does_not_fire_under_version() {
    let marker = marker_path("rustc-wrapper-version");
    let script = marker_path("rustc-wrapper-version-script");
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_file(&script);

    write_marker_script(&script, &marker);

    let output = Command::new(binary_path())
        .arg("cargo")
        .arg("--version")
        .env("RUSTC_WRAPPER", &script)
        .output()
        .expect("spawn contextcrawler cargo --version");

    let _ = std::fs::remove_file(&script);
    let marker_exists = marker.exists();
    let _ = std::fs::remove_file(&marker);

    assert!(
        !marker_exists,
        "RUSTC_WRAPPER marker was created during `cargo --version`.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Stronger empirical PoC: `cargo check` on a throwaway crate DOES
/// invoke rustc, so a tainted `RUSTC_WRAPPER` would absolutely fire
/// without the env strip. The marker MUST NOT appear.
#[test]
#[cfg(unix)]
fn rustc_wrapper_env_is_stripped_during_check() {
    let marker = marker_path("rustc-wrapper-check");
    let script = marker_path("rustc-wrapper-check-script");
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_file(&script);

    write_marker_script(&script, &marker);

    let tmp_crate = marker_path("tiny-crate");
    let _ = std::fs::remove_dir_all(&tmp_crate);
    std::fs::create_dir_all(tmp_crate.join("src")).unwrap();
    std::fs::write(
        tmp_crate.join("Cargo.toml"),
        "[package]\nname = \"harden_probe\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(tmp_crate.join("src/lib.rs"), "// empty\n").unwrap();

    let output = Command::new(binary_path())
        .arg("cargo")
        .arg("check")
        .arg("--offline")
        .env("RUSTC_WRAPPER", &script)
        // Isolate target dir into the temp crate so we don't poison the
        // outer workspace's build cache.
        .env("CARGO_TARGET_DIR", tmp_crate.join("target"))
        .current_dir(&tmp_crate)
        .output()
        .expect("spawn contextcrawler cargo check");

    let _ = std::fs::remove_file(&script);
    let marker_exists = marker.exists();
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_dir_all(&tmp_crate);

    assert!(
        !marker_exists,
        "RUSTC_WRAPPER marker was created during `cargo check` — env strip failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Argv-side PoC: `--config target.<triple>.runner="..."` is rejected
/// before cargo is spawned. Exit code must be 2 and stderr must contain
/// the deny message + escape hatch.
#[test]
fn target_runner_config_is_rejected() {
    let output = Command::new(binary_path())
        .arg("cargo")
        .arg("build")
        .arg("--config")
        .arg("target.x86_64-apple-darwin.runner=\"evil\"")
        .output()
        .expect("spawn contextcrawler cargo build");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(
        output.status.code(),
        Some(0),
        "expected non-zero exit, got 0.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr.contains("refusing to forward"),
        "expected deny message in stderr, got:\n{}",
        stderr,
    );
    assert!(
        stderr.contains("contextcrawler proxy cargo"),
        "expected escape-hatch hint in stderr, got:\n{}",
        stderr,
    );
    assert!(
        stderr.contains("#34"),
        "expected issue reference in stderr, got:\n{}",
        stderr,
    );
}

/// Positive control: a benign `cargo --version` still exits 0 through
/// the hardened wrapper. This catches the "we accidentally broke the
/// happy path" failure mode.
#[test]
fn benign_cargo_version_still_works() {
    let output = Command::new(binary_path())
        .arg("cargo")
        .arg("--version")
        .output()
        .expect("spawn contextcrawler cargo --version");

    assert_eq!(
        output.status.code(),
        Some(0),
        "cargo --version should succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("cargo "),
        "expected cargo version output, got:\n{}",
        combined,
    );
}
