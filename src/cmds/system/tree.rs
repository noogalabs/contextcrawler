//! tree command - proxy to native tree with token-optimized output
//!
//! This module proxies to the native `tree` command and filters the output
//! to reduce token usage while preserving structure visibility.
//!
//! Token optimization: automatically excludes noise directories via -I pattern
//! unless -a flag is present (respecting user intent).

use super::constants::NOISE_DIRS;
use crate::core::runner::{self, RunOptions};
use crate::core::utils::{resolved_command, tool_exists};
use anyhow::Result;

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    if !tool_exists("tree") {
        anyhow::bail!(
            "tree command not found. Install it first:\n\
             - macOS: brew install tree\n\
             - Ubuntu/Debian: sudo apt install tree\n\
             - Fedora/RHEL: sudo dnf install tree\n\
             - Arch: sudo pacman -S tree"
        );
    }

    let mut cmd = resolved_command("tree");

    let show_all = args.iter().any(|a| a == "-a" || a == "--all");
    let has_ignore = args.iter().any(|a| a == "-I" || a.starts_with("--ignore="));

    if !show_all && !has_ignore {
        let ignore_pattern = NOISE_DIRS.join("|");
        cmd.arg("-I").arg(&ignore_pattern);
    }

    // Forward options first, then a `--` boundary, then path operands. Without
    // the boundary a user path beginning with `-` (e.g. a directory named
    // `-la`) would be parsed by `tree` as an option (#100, G5#2).
    let (flags, paths) = split_flags_and_paths(args);
    for flag in flags {
        cmd.arg(flag);
    }
    cmd.arg("--");
    for path in paths {
        cmd.arg(path);
    }

    runner::run_filtered(
        cmd,
        "tree",
        &args.join(" "),
        |raw| {
            let filtered = filter_tree_output(raw);
            if verbose > 0 {
                eprintln!(
                    "Lines: {} → {} ({}% reduction)",
                    raw.lines().count(),
                    filtered.lines().count(),
                    if raw.lines().count() > 0 {
                        100 - (filtered.lines().count() * 100 / raw.lines().count())
                    } else {
                        0
                    }
                );
            }
            filtered
        },
        RunOptions::stdout_only()
            .early_exit_on_failure()
            .no_trailing_newline(),
    )
}

/// Split raw `tree` args into `(flags, paths)`.
///
/// `tree` short options that consume the following argument as their value;
/// that argument must stay on the option side of the `--` boundary so it is
/// not mistaken for a search path. `-o` is genuine: native tree (v2.x,
/// `tree --help`) documents `-o filename` — "Output to file instead of
/// stdout" — so the token after `-o` is a filename operand, not a path.
fn split_flags_and_paths(args: &[String]) -> (Vec<&str>, Vec<&str>) {
    const VALUE_FLAGS: &[&str] = &["-L", "-I", "-P", "-o", "--filelimit"];
    let mut flags: Vec<&str> = Vec::new();
    let mut paths: Vec<&str> = Vec::new();
    let mut expect_value = false;
    for arg in args {
        if expect_value {
            flags.push(arg);
            expect_value = false;
        } else if arg.starts_with('-') {
            flags.push(arg);
            expect_value = VALUE_FLAGS.contains(&arg.as_str());
        } else {
            paths.push(arg);
        }
    }
    (flags, paths)
}

fn filter_tree_output(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();

    if lines.is_empty() {
        return "\n".to_string();
    }

    let mut filtered_lines = Vec::new();

    for line in lines {
        // Skip the final summary line (e.g., "5 directories, 23 files")
        if line.contains("director") && line.contains("file") {
            continue;
        }

        // Skip empty lines at the end
        if line.trim().is_empty() && filtered_lines.is_empty() {
            continue;
        }

        filtered_lines.push(line);
    }

    // Remove trailing empty lines
    while filtered_lines.last().is_some_and(|l| l.trim().is_empty()) {
        filtered_lines.pop();
    }

    filtered_lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_removes_summary() {
        let input = ".\n├── src\n│   └── main.rs\n└── Cargo.toml\n\n2 directories, 3 files\n";
        let output = filter_tree_output(input);
        assert!(!output.contains("directories"));
        assert!(!output.contains("files"));
        assert!(output.contains("main.rs"));
        assert!(output.contains("Cargo.toml"));
    }

    #[test]
    fn test_filter_preserves_structure() {
        let input = ".\n├── src\n│   ├── main.rs\n│   └── lib.rs\n└── tests\n    └── test.rs\n";
        let output = filter_tree_output(input);
        assert!(output.contains("├──"));
        assert!(output.contains("│"));
        assert!(output.contains("└──"));
        assert!(output.contains("main.rs"));
        assert!(output.contains("test.rs"));
    }

    #[test]
    fn test_filter_handles_empty() {
        let input = "";
        let output = filter_tree_output(input);
        assert_eq!(output, "\n");
    }

    #[test]
    fn test_filter_removes_trailing_empty_lines() {
        let input = ".\n├── file.txt\n\n\n";
        let output = filter_tree_output(input);
        assert_eq!(output.matches('\n').count(), 2); // Root + file.txt + final newline
    }

    #[test]
    fn test_filter_summary_variations() {
        // Test different summary formats
        let inputs = vec![
            (".\n└── file.txt\n\n0 directories, 1 file\n", "1 file"),
            (".\n└── file.txt\n\n1 directory, 0 files\n", "1 directory"),
            (".\n└── file.txt\n\n10 directories, 25 files\n", "25 files"),
        ];

        for (input, summary_fragment) in inputs {
            let output = filter_tree_output(input);
            assert!(
                !output.contains(summary_fragment),
                "Should remove summary '{}' from output",
                summary_fragment
            );
            assert!(
                output.contains("file.txt"),
                "Should preserve file.txt in output"
            );
        }
    }

    fn sv(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    // #111 G5: `-o filename` is tree's output-file flag — `filename` is its
    // value and must stay on the flag side, while the trailing operand is
    // still recognised as the search path.
    #[test]
    fn test_split_o_consumes_filename_value() {
        let args = sv(&["-o", "out.txt", "somedir"]);
        let (flags, paths) = split_flags_and_paths(&args);
        assert_eq!(flags, vec!["-o", "out.txt"]);
        assert_eq!(paths, vec!["somedir"], "search path must survive -o value");
    }

    #[test]
    fn test_split_plain_path_only() {
        let args = sv(&["somedir"]);
        let (flags, paths) = split_flags_and_paths(&args);
        assert!(flags.is_empty());
        assert_eq!(paths, vec!["somedir"]);
    }

    #[test]
    fn test_split_value_flags_then_path() {
        let args = sv(&["-L", "2", "-P", "*.rs", "src"]);
        let (flags, paths) = split_flags_and_paths(&args);
        assert_eq!(flags, vec!["-L", "2", "-P", "*.rs"]);
        assert_eq!(paths, vec!["src"]);
    }

    #[test]
    fn test_noise_dirs_constant() {
        // Verify NOISE_DIRS contains expected patterns
        assert!(NOISE_DIRS.contains(&"node_modules"));
        assert!(NOISE_DIRS.contains(&".git"));
        assert!(NOISE_DIRS.contains(&"target"));
        assert!(NOISE_DIRS.contains(&"__pycache__"));
        assert!(NOISE_DIRS.contains(&".next"));
        assert!(NOISE_DIRS.contains(&"dist"));
        assert!(NOISE_DIRS.contains(&"build"));
    }
}
