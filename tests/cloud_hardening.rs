//! Integration tests for the cloud CLI hardening (issue #38).
//!
//! Verifies that:
//! - kubectl / docker / aws / psql spawned via contextcrawler do NOT honour
//!   the hijack-prone env vars they inherit from the caller (KUBECONFIG,
//!   DOCKER_CONFIG, AWS_CONFIG_FILE, PSQLRC).
//! - The per-tool arg deny-lists reject the dangerous flags.
//! - Positive sanity: legitimate invocations still succeed.
//!
//! Tests that require the underlying tool to be installed are auto-skipped
//! via `#[ignore]` semantics — we check `which::which(tool)` at the top of
//! each test and early-return success when absent, so CI without these
//! tools doesn't go red on a flake.
//!
//! Negative env-var assertions check that the binary did NOT load the
//! tainted file — typically the tainted file contains syntactically-invalid
//! content that would produce a specific parse error if loaded. Absence of
//! that error proves the env strip worked.

use std::path::PathBuf;
use std::process::{Command, Stdio};

mod common;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn tool_installed(name: &str) -> bool {
    which::which(name).is_ok()
}

/// Write a tainted config file containing nonsense that would produce a
/// distinctive error if the tool actually parsed it. Returns the temp
/// directory (keep it alive for the test scope) and the file path.
fn write_evil_config(filename: &str, content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join(filename);
    std::fs::write(&path, content).expect("write evil config");
    (dir, path)
}

fn run_cc(env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    // Serialize env-mutating spawns via the shared lock (issue #48).
    let _guard = common::env_lock();
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    // Issue #91 — mark spawned binary as test context so it short-circuits
    // production-DB writes even in release builds (cfg!(test) is false in
    // a release-compiled child binary).
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
    // Per-invocation isolated DB. A shared `cc-hardening-<pid>.sqlite` made
    // every test in this binary race on one file (order-dependence risk);
    // a fresh tempdir per call removes the shared state entirely. The
    // TempDir handle is held until after `cmd.output()` returns, then
    // dropped — the spawned child only touches the DB during its run.
    let db_dir = tempfile::tempdir().expect("create per-test DB tempdir");
    cmd.env("RTK_DB_PATH", db_dir.path().join("tracking.sqlite"));
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.output().expect("spawn contextcrawler")
}

// ==================== kubectl ====================

#[test]
fn kubectl_strips_kubeconfig_env() {
    if !tool_installed("kubectl") {
        eprintln!("SKIP: kubectl not installed");
        return;
    }
    let (_dir, evil) = write_evil_config(
        "evil.yaml",
        "this is not valid kubeconfig yaml @@@ contextcrawler hardening probe",
    );

    let out = run_cc(
        &[("KUBECONFIG", evil.to_str().unwrap())],
        &["kubectl", "version", "--client"],
    );

    // `kubectl version --client` does NOT need a kubeconfig at all. If the
    // env strip works, it succeeds. If it doesn't, kubectl will either
    // succeed silently (still fine — version --client ignores config) OR
    // print a yaml-parse error mentioning the evil path. The strong signal
    // is: stderr must NOT mention the evil path.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.contains("evil.yaml") && !stdout.contains("evil.yaml"),
        "kubectl saw KUBECONFIG=evil.yaml — env strip failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn kubectl_rejects_exec_subcommand() {
    let out = run_cc(&[], &["kubectl", "exec", "somepod", "--", "sh"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("kubectl"),
        "kubectl exec should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn kubectl_rejects_kubeconfig_flag() {
    let out = run_cc(
        &[],
        &["kubectl", "--kubeconfig", "/tmp/x.yaml", "get", "pods"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--kubeconfig"),
        "--kubeconfig should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn kubectl_version_client_works() {
    if !tool_installed("kubectl") {
        eprintln!("SKIP: kubectl not installed");
        return;
    }
    let out = run_cc(&[], &["kubectl", "version", "--client"]);
    // version --client should not need a cluster. Allow exit 0; permit
    // non-zero only if stderr is empty of cluster-connection errors.
    assert!(
        out.status.success() || !String::from_utf8_lossy(&out.stderr).contains("Unable to connect"),
        "kubectl version --client failed unexpectedly: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ==================== docker ====================

#[test]
fn docker_strips_docker_config_env() {
    if !tool_installed("docker") {
        eprintln!("SKIP: docker not installed");
        return;
    }
    let (_dir, evil_dir) = write_evil_config(
        "marker.txt",
        "contextcrawler-evil-docker-config-marker",
    );
    let evil_dir_path = evil_dir.parent().unwrap();

    let out = run_cc(
        &[("DOCKER_CONFIG", evil_dir_path.to_str().unwrap())],
        &["docker", "version"],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Docker should not reference the evil DOCKER_CONFIG dir at all.
    let evil_str = evil_dir_path.to_str().unwrap();
    assert!(
        !stderr.contains(evil_str) && !stdout.contains(evil_str),
        "docker saw DOCKER_CONFIG={} — env strip failed.\nstdout: {}\nstderr: {}",
        evil_str,
        stdout,
        stderr
    );
}

#[test]
fn docker_rejects_config_flag() {
    let out = run_cc(&[], &["docker", "--config", "/tmp/x", "version"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--config"),
        "docker --config should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn docker_version_works() {
    if !tool_installed("docker") {
        eprintln!("SKIP: docker not installed");
        return;
    }
    let out = run_cc(&[], &["docker", "--version"]);
    // `docker --version` is metadata-only — works even without a running daemon.
    assert!(
        out.status.success(),
        "docker --version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ==================== aws ====================

#[test]
fn aws_strips_aws_config_file_env() {
    if !tool_installed("aws") {
        eprintln!("SKIP: aws not installed");
        return;
    }
    let (_dir, evil) = write_evil_config(
        "evil.ini",
        "[[[ not valid aws config — contextcrawler probe",
    );

    let out = run_cc(
        &[("AWS_CONFIG_FILE", evil.to_str().unwrap())],
        &["aws", "--version"],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `aws --version` doesn't need config; if env strip works, no mention of evil.ini.
    assert!(
        !stderr.contains("evil.ini") && !stdout.contains("evil.ini"),
        "aws saw AWS_CONFIG_FILE=evil.ini — env strip failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn aws_rejects_ca_bundle_flag() {
    let out = run_cc(&[], &["aws", "--ca-bundle", "/tmp/evil.pem", "s3", "ls"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--ca-bundle"),
        "aws --ca-bundle should be rejected; stderr: {}",
        stderr
    );
}

// ==================== psql ====================

#[test]
fn psql_strips_psqlrc_env() {
    if !tool_installed("psql") {
        eprintln!("SKIP: psql not installed");
        return;
    }
    let (_dir, evil) = write_evil_config(
        "evil.psqlrc",
        "\\echo CONTEXTCRAWLER_PSQLRC_LOADED_MARKER\n",
    );

    let out = run_cc(
        &[("PSQLRC", evil.to_str().unwrap())],
        &["psql", "--version"],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // If PSQLRC stripping works, the marker the rc file would echo never appears.
    assert!(
        !stdout.contains("CONTEXTCRAWLER_PSQLRC_LOADED_MARKER")
            && !stderr.contains("CONTEXTCRAWLER_PSQLRC_LOADED_MARKER"),
        "psql loaded PSQLRC — env strip failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

// ==================== curl ====================

#[test]
fn curl_rejects_config_flag() {
    let out = run_cc(&[], &["curl", "--config", "/tmp/x.curlrc"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--config"),
        "curl --config should be rejected; stderr: {}",
        stderr
    );
}

// G4/#100: the deny-list must catch the attached-value form (`-K=file`,
// `--config=file`) — curl accepts these and they are equivalent to the
// space-separated form a naive token compare missed.
#[test]
fn curl_rejects_short_config_attached_value() {
    let out = run_cc(&[], &["curl", "-K=/tmp/evil.curlrc", "https://example.com"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "curl -K=file should be rejected (attached-value flag injection); stderr: {}",
        stderr
    );
}

#[test]
fn curl_rejects_long_config_attached_value() {
    let out = run_cc(
        &[],
        &["curl", "--config=/tmp/evil.curlrc", "https://example.com"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "curl --config=file should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn curl_rejects_short_config_space_form() {
    let out = run_cc(&[], &["curl", "-K", "/tmp/evil.curlrc"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "curl -K file should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn curl_rejects_output_to_bashrc() {
    let out = run_cc(
        &[],
        &["curl", "https://example.com", "--output", "/home/user/.bashrc"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "curl --output ~/.bashrc should be rejected; stderr: {}",
        stderr
    );
}

// ==================== wget ====================

#[test]
fn wget_rejects_execute_flag() {
    let out = run_cc(
        &[],
        &["wget", "https://example.com", "--execute=robots=off"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--execute"),
        "wget --execute should be rejected; stderr: {}",
        stderr
    );
}

#[test]
fn wget_rejects_use_askpass() {
    let out = run_cc(
        &[],
        &["wget", "https://example.com", "--use-askpass=/tmp/evil.sh"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("--use-askpass"),
        "wget --use-askpass should be rejected; stderr: {}",
        stderr
    );
}

// G4/#100: --output-document / -O (arbitrary file overwrite), --input-file /
// -i (arbitrary file read), and --load-cookies (cookie-theft pivot) must be
// rejected in every shape: short, long, space-separated and attached-value.
fn wget_must_reject(args: &[&str], label: &str) {
    let out = run_cc(&[], args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "wget {label} should be rejected; args={args:?}; stderr: {stderr}"
    );
}

#[test]
fn wget_rejects_output_document_all_forms() {
    wget_must_reject(
        &["wget", "https://example.com", "-O", "/home/user/.bashrc"],
        "-O (space form)",
    );
    wget_must_reject(
        &["wget", "https://example.com", "-O=/home/user/.bashrc"],
        "-O=x (attached form)",
    );
    wget_must_reject(
        &["wget", "https://example.com", "--output-document", "/tmp/x"],
        "--output-document (space form)",
    );
    wget_must_reject(
        &["wget", "https://example.com", "--output-document=/tmp/x"],
        "--output-document=x (attached form)",
    );
}

#[test]
fn wget_rejects_input_file_all_forms() {
    wget_must_reject(
        &["wget", "-i", "/etc/passwd"],
        "-i (space form)",
    );
    wget_must_reject(
        &["wget", "-i=/etc/passwd"],
        "-i=x (attached form)",
    );
    wget_must_reject(
        &["wget", "--input-file", "/etc/passwd"],
        "--input-file (space form)",
    );
    wget_must_reject(
        &["wget", "--input-file=/etc/passwd"],
        "--input-file=x (attached form)",
    );
}

#[test]
fn wget_rejects_load_cookies_all_forms() {
    wget_must_reject(
        &["wget", "https://example.com", "--load-cookies", "/tmp/jar"],
        "--load-cookies (space form)",
    );
    wget_must_reject(
        &["wget", "https://example.com", "--load-cookies=/tmp/jar"],
        "--load-cookies=x (attached form)",
    );
}
