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
