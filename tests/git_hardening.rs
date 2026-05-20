//! Integration tests for the git wrapper hardening (issue #35).
//!
//! Each test invokes the built `contextcrawler` binary with one of the
//! known git env-var or `-c` RCE vectors armed, then asserts that the
//! attacker-controlled marker payload never ran. The marker mechanism is
//! the same shape used in PR #33 for the rg hardening: a shell script
//! that, if executed, would create a sentinel file in a tempdir. We
//! then check for the absence of the sentinel.
//!
//! These tests deliberately exercise the BUILT binary (via
//! `CARGO_BIN_EXE_contextcrawler`) rather than calling the helpers
//! in-process, because the hardening lives at the spawn boundary —
//! the only way to confirm it actually severs the env is to spawn
//! a real child with the env set.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Build a `Command` that runs the contextcrawler binary inside `cwd`
/// (which should be a git repo so `git diff` / `git status` etc. don't
/// short-circuit before the env-driven hook fires).
fn ccrawl_in(cwd: &std::path::Path) -> Command {
    let mut c = Command::new(binary_path());
    c.current_dir(cwd);
    // Empty PATH-adjacent env-var noise; preserve PATH so git is findable.
    if let Ok(path) = std::env::var("PATH") {
        c.env_clear();
        c.env("PATH", path);
        if let Ok(home) = std::env::var("HOME") {
            c.env("HOME", home);
        }
    }
    // Issue #91 — sentinel for release-built spawned binary. MUST be set
    // AFTER env_clear() above (env_clear wipes everything including this).
    c.env("CONTEXTCRAWLER_TEST_MODE", "1");
    c
}

/// Create a throwaway git repo with one commit so `git diff HEAD~1` and
/// friends have something to diff. Returns the tempdir handle (which
/// must be kept alive to keep the dir on disk) and its path.
fn make_repo() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir for repo");
    let path = dir.path().to_path_buf();

    // git init + minimal commit. Use Command directly (not contextcrawler)
    // so the setup itself can't be confused with the system under test.
    //
    // Pass `-c commit.gpgsign=false -c tag.gpgsign=false` on every git call
    // (issue #57). Without it the fixture inherits the developer's global
    // `commit.gpgsign=true` and silently fails on workstations where the
    // signing agent (1Password, gpg-agent, ssh-agent) is unavailable or
    // locked — the entire test suite then dies on `make_repo()` with
    // "1Password: agent returned an error" and reports the cause as the
    // security test, not the fixture. Isolating with these flags keeps
    // the test hermetic against the host's git config.
    let run = |args: &[&str]| {
        let mut full_args: Vec<&str> = vec![
            "-c", "commit.gpgsign=false",
            "-c", "tag.gpgsign=false",
        ];
        full_args.extend_from_slice(args);
        let status = Command::new("git")
            .args(&full_args)
            .current_dir(&path)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git command runs");
        assert!(
            status.status.success(),
            "git {:?} failed: stderr={}",
            full_args,
            String::from_utf8_lossy(&status.stderr)
        );
    };

    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    // Belt-and-braces: also pin signing off via local config, so any
    // future helper that forgets the -c flags still gets a hermetic
    // commit. Cheap insurance.
    run(&["config", "commit.gpgsign", "false"]);
    run(&["config", "tag.gpgsign", "false"]);
    fs::write(path.join("a.txt"), "hello\n").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "-q", "-m", "init"]);
    fs::write(path.join("a.txt"), "hello world\n").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "-q", "-m", "update"]);

    (dir, path)
}

/// Write an executable shell script at `path` that `touch`es `marker`
/// when run. Returns the script path. On non-unix platforms this test
/// is skipped at the call site.
#[cfg(unix)]
fn make_marker_script(dir: &std::path::Path, marker: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("evil.sh");
    let body = format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display());
    fs::write(&script, body).expect("write script");
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).expect("chmod +x script");
    script
}

#[test]
#[cfg(unix)]
fn git_external_diff_env_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_external_diff");
    let script = make_marker_script(repo.path(), &marker);

    // Pre-PoC sanity: run raw git with the var set, confirm the marker
    // *does* get written (i.e. our PoC is real). If this fails the test
    // is unsound — surface that loudly rather than silently passing.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_EXTERNAL_DIFF", &script)
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_EXTERNAL_DIFF set \
         did NOT touch the marker, so this test cannot prove anything. \
         git stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    // Now the real test: same env, same args, but through contextcrawler.
    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_EXTERNAL_DIFF", &script)
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still executed GIT_EXTERNAL_DIFF helper. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(unix)]
fn git_config_count_env_injection_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_config_count");
    let script = make_marker_script(repo.path(), &marker);

    // PoC sanity: raw git with GIT_CONFIG_COUNT=1 + KEY_0=diff.external
    // + VALUE_0=<script> triggers the helper. If not, the env-var
    // injection vector we're claiming to neutralize isn't actually
    // reachable on this platform and the test is moot.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "diff.external")
        .env("GIT_CONFIG_VALUE_0", script.to_str().unwrap())
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_CONFIG_COUNT injection \
         did NOT touch the marker. Stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "diff.external")
        .env("GIT_CONFIG_VALUE_0", script.to_str().unwrap())
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still honored GIT_CONFIG_COUNT injection. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(unix)]
fn git_config_global_env_pointing_at_evil_gitconfig_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_config_global");
    let script = make_marker_script(repo.path(), &marker);

    // Fixture .gitconfig that sets diff.external = <script>.
    let cfg = repo.path().join("evil.gitconfig");
    fs::write(
        &cfg,
        format!("[diff]\n    external = {}\n", script.display()),
    )
    .expect("write evil gitconfig");

    // PoC sanity.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_CONFIG_GLOBAL", &cfg)
        // Some git builds also consult GIT_CONFIG_SYSTEM; explicitly
        // unset it to avoid noise.
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_CONFIG_GLOBAL injection \
         did NOT touch the marker. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_CONFIG_GLOBAL", &cfg)
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still honored GIT_CONFIG_GLOBAL injection. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn c_diff_external_arg_is_rejected_with_deny_error() {
    // No need to actually be in a repo — the deny check fires before
    // git is spawned. Use a tempdir for cwd to avoid mutating whatever
    // tree the test is run from.
    let _guard = common::env_lock();
    let dir = tempfile::tempdir().expect("tempdir");
    let out = ccrawl_in(dir.path())
        .args(["git", "-c", "diff.external=/tmp/evil.sh", "diff"])
        .output()
        .expect("contextcrawler git runs");

    assert!(
        !out.status.success(),
        "contextcrawler must reject -c diff.external=… with non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("contextcrawler") && stderr.contains("#35"),
        "stderr must explain why and reference issue #35. got={:?}",
        stderr
    );
}

#[test]
fn benign_git_status_still_succeeds() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    let out = ccrawl_in(&repo_path)
        .args(["git", "status"])
        .output()
        .expect("contextcrawler git status runs");
    assert!(
        out.status.success(),
        "contextcrawler git status (no attack args) must still succeed. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- G4/#100: git exit-code propagation ------------------------------------
//
// run_status (compact), run_stash (list/show) and run_worktree (list) applied
// the output filter BEFORE checking git's exit code. A non-zero git exit was
// absorbed and the caller saw apparent success. These tests run each path in
// a NON-repo tempdir — git exits 128 — and assert contextcrawler propagates a
// non-zero exit instead of reporting success.

/// A bare tempdir that is deliberately NOT a git repo. git invoked here
/// exits non-zero ("fatal: not a git repository").
fn non_repo_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create non-repo tempdir")
}

#[test]
fn git_status_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "status"])
        .output()
        .expect("contextcrawler git status runs");
    assert!(
        !out.status.success(),
        "git status outside a repo must propagate a non-zero exit, not be \
         filtered into apparent success. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_stash_list_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "stash", "list"])
        .output()
        .expect("contextcrawler git stash list runs");
    assert!(
        !out.status.success(),
        "git stash list outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_stash_show_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "stash", "show"])
        .output()
        .expect("contextcrawler git stash show runs");
    assert!(
        !out.status.success(),
        "git stash show outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_worktree_list_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "worktree", "list"])
        .output()
        .expect("contextcrawler git worktree list runs");
    assert!(
        !out.status.success(),
        "git worktree list outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn benign_git_log_still_succeeds() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    let out = ccrawl_in(&repo_path)
        .args(["git", "log", "-3", "--oneline"])
        .output()
        .expect("contextcrawler git log runs");
    assert!(
        out.status.success(),
        "contextcrawler git log -3 --oneline must still succeed. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
