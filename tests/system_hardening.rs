//! Integration tests for the system-command wrapper hardening
//! (issue #100, group G5).
//!
//! Covers the `ls` / `tree` path-as-flag boundary: user path operands that
//! begin with `-` must not be reinterpreted as command options. The wrappers
//! now insert a `--` separator before path operands, so a directory whose
//! name starts with `-` is listed as a path rather than parsed as a flag.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ctxc-g5-{}-{}-{}", tag, pid, ts))
}

/// `ls` of a directory that contains an entry named `-la` must succeed and
/// show the dash-prefixed entry — the `--` boundary keeps `ls` from parsing
/// any operand as an option.
#[test]
fn ls_lists_dash_prefixed_entry() {
    let root = unique_dir("ls");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("-la")).expect("create -la subdir");
    fs::write(root.join("normal.txt"), "hi").expect("write normal.txt");

    let out = Command::new(binary_path())
        .arg("ls")
        .arg(&root)
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .output()
        .expect("spawn contextcrawler ls");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "ls of a dir with a dash-prefixed entry should succeed; got:\n{}",
        combined,
    );
    assert!(
        combined.contains("-la"),
        "dash-prefixed entry should be listed, got:\n{}",
        combined,
    );
    assert!(
        combined.contains("normal.txt"),
        "normal entry should still be listed, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// `tree` of a directory whose only child is named `-la` must succeed: the
/// `--` boundary stops `tree` parsing the path operand as an option.
#[test]
fn tree_handles_dash_prefixed_path() {
    if Command::new("tree").arg("--version").output().is_err() {
        eprintln!("[skip] tree not on PATH");
        return;
    }

    let root = unique_dir("tree");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("-la")).expect("create -la subdir");

    let out = Command::new(binary_path())
        .arg("tree")
        .arg(&root)
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .output()
        .expect("spawn contextcrawler tree");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "tree of a dir with a dash-prefixed child should succeed; got:\n{}",
        combined,
    );
    assert!(
        combined.contains("-la"),
        "dash-prefixed child should appear in tree output, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// A grep pattern shaped like `--pre=<cmd>` must NOT be parsed by rg as the
/// `--pre` preprocessor flag (confirmed RCE, #32 / #111 G5). With the `--`
/// boundary in front of the pattern, rg treats it as a literal pattern, so
/// the marker file the "preprocessor" would create is never written.
#[test]
fn grep_pattern_shaped_like_pre_flag_is_not_executed() {
    let root = unique_dir("grep-pre");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create grep-pre dir");
    fs::write(root.join("haystack.txt"), "nothing interesting here\n")
        .expect("write haystack.txt");

    // If `--pre` were honoured, rg would exec this script per file.
    let marker = root.join("pwned.marker");
    let script = root.join("evil.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\ncat \"$1\"\n", marker.display()),
    )
    .expect("write evil.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let out = Command::new(binary_path())
        .arg("grep")
        .arg(format!("--pre={}", script.display()))
        .arg(&root)
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .output()
        .expect("spawn contextcrawler grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        !marker.exists(),
        "preprocessor script must NOT have run — `--`-shaped pattern reached rg as a flag; got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// A grep `path` operand that begins with `-` must be treated as a path, not
/// parsed as an rg/grep option — the `--` boundary precedes the path.
#[test]
fn grep_path_starting_with_dash_is_treated_as_path() {
    let root = unique_dir("grep-dashpath");
    let _ = fs::remove_dir_all(&root);
    let dash_dir = root.join("-dashdir");
    fs::create_dir_all(&dash_dir).expect("create -dashdir");
    fs::write(dash_dir.join("file.txt"), "findme_token\n").expect("write file.txt");

    let out = Command::new(binary_path())
        .arg("grep")
        .arg("findme_token")
        .arg(&dash_dir)
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .output()
        .expect("spawn contextcrawler grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        combined.contains("findme_token"),
        "grep should search a dash-prefixed path and find the match, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}
