//! Runs a command and produces a heuristic summary of its output.

use crate::core::stream::exec_capture;
use crate::core::tracking;
use crate::core::utils::truncate;
use anyhow::{Context, Result};
use regex::Regex;
use std::process::Command;

// See cmds/rust/runner.rs: argv mode rejects shell metacharacters so
// agent-rewritten input cannot smuggle pipes/redirects/chains into the child,
// and refuses to spawn a known shell binary so an agent cannot trivially
// reintroduce sh -c by emitting `sh -c '<payload>'` as the whole argv.
const SHELL_METACHARS: &[char] = &['|', ';', '&', '<', '>', '`', '$', '\n'];
const SHELL_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash",
    "sh.exe", "bash.exe", "zsh.exe", "dash.exe", "ksh.exe", "fish.exe",
    "tcsh.exe", "csh.exe", "ash.exe",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "busybox", "busybox.exe", "toybox",
    "env", "nice", "nohup", "time", "timeout", "gtimeout",
    "ionice", "chroot", "setpriv", "unshare", "taskset", "stdbuf",
    "script", "xargs", "watch", "sudo", "doas",
    "su", "runuser", "pkexec",
];

fn is_shell_binary(bin: &str) -> bool {
    let basename = std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    SHELL_BINARIES.iter().any(|s| s.eq_ignore_ascii_case(basename))
}

fn build_command(command: &str, use_shell: bool) -> Result<Command> {
    if use_shell {
        let cmd = if cfg!(target_os = "windows") {
            let mut c = Command::new("cmd");
            c.args(["/C", command]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", command]);
            c
        };
        return Ok(cmd);
    }
    if let Some(meta) = command.chars().find(|c| SHELL_METACHARS.contains(c)) {
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

/// Run a command and provide a heuristic summary
pub fn run(command: &str, use_shell: bool, verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Running and summarizing: {}", command);
    }

    let mut cmd = build_command(command, use_shell)?;
    let result = exec_capture(&mut cmd).context("Failed to execute command")?;

    let raw = format!("{}\n{}", result.stdout, result.stderr);

    // If the capture cap fired, a synthesised summary built from a prefix
    // of the real output would silently mislead the caller (wrong test /
    // error counts, partial JSON structure, etc). Prepend an explicit
    // truncation marker so the summary cannot be mistaken for complete data.
    let truncation_note = if result.truncated_stdout || result.truncated_stderr {
        Some(format!(
            "[!] OUTPUT TRUNCATED — summary built from a {} MiB prefix only; rerun with `contextcrawler proxy` for raw output.\n",
            crate::core::stream::DEFAULT_CAPTURE_STREAM_MAX / (1024 * 1024)
        ))
    } else {
        None
    };

    let summary = summarize_output(&raw, command, result.success());
    if let Some(note) = &truncation_note {
        println!("{}{}", note, summary);
    } else {
        println!("{}", summary);
    }
    timer.track(command, "rtk summary", &raw, &summary);
    Ok(result.exit_code)
}

fn summarize_output(output: &str, command: &str, success: bool) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let mut result = Vec::new();

    // Status
    let status_icon = if success { "[ok]" } else { "[FAIL]" };
    result.push(format!(
        "{} Command: {}",
        status_icon,
        truncate(command, 60)
    ));
    result.push(format!("   {} lines of output", lines.len()));
    result.push(String::new());

    // Detect type of output and summarize accordingly
    let output_type = detect_output_type(output, command);

    match output_type {
        OutputType::TestResults => summarize_tests(output, &mut result),
        OutputType::BuildOutput => summarize_build(output, &mut result),
        OutputType::LogOutput => summarize_logs_quick(output, &mut result),
        OutputType::ListOutput => summarize_list(output, &mut result),
        OutputType::JsonOutput => summarize_json(output, &mut result),
        OutputType::Generic => summarize_generic(output, &mut result),
    }

    result.join("\n")
}

#[derive(Debug)]
enum OutputType {
    TestResults,
    BuildOutput,
    LogOutput,
    ListOutput,
    JsonOutput,
    Generic,
}

fn detect_output_type(output: &str, command: &str) -> OutputType {
    let cmd_lower = command.to_lowercase();
    let out_lower = output.to_lowercase();

    if cmd_lower.contains("test") || out_lower.contains("passed") && out_lower.contains("failed") {
        OutputType::TestResults
    } else if cmd_lower.contains("build")
        || cmd_lower.contains("compile")
        || out_lower.contains("compiling")
    {
        OutputType::BuildOutput
    } else if out_lower.contains("error:")
        || out_lower.contains("warn:")
        || out_lower.contains("[info]")
    {
        OutputType::LogOutput
    } else if output.trim_start().starts_with('{') || output.trim_start().starts_with('[') {
        OutputType::JsonOutput
    } else if output.lines().all(|l| {
        l.len() < 200
            && if l.contains('\t') {
                false
            } else {
                l.split_whitespace().count() < 10
            }
    }) {
        OutputType::ListOutput
    } else {
        OutputType::Generic
    }
}

fn summarize_tests(output: &str, result: &mut Vec<String>) {
    result.push("Test Results:".to_string());

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut failures = Vec::new();

    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("passed") || lower.contains("✓") || lower.contains("ok") {
            // Try to extract number
            if let Some(n) = extract_number(&lower, "passed") {
                passed = n;
            } else {
                passed += 1;
            }
        }
        if lower.contains("failed") || lower.contains("[x]") || lower.contains("fail") {
            if let Some(n) = extract_number(&lower, "failed") {
                failed = n;
            }
            if !line.contains("0 failed") {
                failures.push(line.to_string());
            }
        }
        if lower.contains("skipped") || lower.contains("ignored") {
            if let Some(n) = extract_number(&lower, "skipped").or(extract_number(&lower, "ignored"))
            {
                skipped = n;
            }
        }
    }

    result.push(format!("   [ok] {} passed", passed));
    if failed > 0 {
        result.push(format!("   [FAIL] {} failed", failed));
    }
    if skipped > 0 {
        result.push(format!("   skip {} skipped", skipped));
    }

    if !failures.is_empty() {
        result.push(String::new());
        result.push("   Failures:".to_string());
        for f in failures.iter().take(5) {
            result.push(format!("   • {}", truncate(f, 70)));
        }
    }
}

fn summarize_build(output: &str, result: &mut Vec<String>) {
    result.push("Build Summary:".to_string());

    let mut errors = 0;
    let mut warnings = 0;
    let mut compiled = 0;
    let mut error_msgs = Vec::new();

    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("error") && !lower.contains("0 error") {
            errors += 1;
            if error_msgs.len() < 5 {
                error_msgs.push(line.to_string());
            }
        }
        if lower.contains("warning") && !lower.contains("0 warning") {
            warnings += 1;
        }
        if lower.contains("compiling") || lower.contains("compiled") {
            compiled += 1;
        }
    }

    if compiled > 0 {
        result.push(format!("   {} crates/files compiled", compiled));
    }
    if errors > 0 {
        result.push(format!("   [error] {} errors", errors));
    }
    if warnings > 0 {
        result.push(format!("   [warn] {} warnings", warnings));
    }
    if errors == 0 && warnings == 0 {
        result.push("   [ok] Build successful".to_string());
    }

    if !error_msgs.is_empty() {
        result.push(String::new());
        result.push("   Errors:".to_string());
        for e in &error_msgs {
            result.push(format!("   • {}", truncate(e, 70)));
        }
    }
}

fn summarize_logs_quick(output: &str, result: &mut Vec<String>) {
    result.push("Log Summary:".to_string());

    let mut errors = 0;
    let mut warnings = 0;
    let mut info = 0;

    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("error") || lower.contains("fatal") {
            errors += 1;
        } else if lower.contains("warn") {
            warnings += 1;
        } else if lower.contains("info") {
            info += 1;
        }
    }

    result.push(format!("   [error] {} errors", errors));
    result.push(format!("   [warn] {} warnings", warnings));
    result.push(format!("   [info] {} info", info));
}

fn summarize_list(output: &str, result: &mut Vec<String>) {
    let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
    result.push(format!("List ({} items):", lines.len()));

    for line in lines.iter().take(10) {
        result.push(format!("   • {}", truncate(line, 70)));
    }
    if lines.len() > 10 {
        result.push(format!("   ... +{} more", lines.len() - 10));
    }
}

fn summarize_json(output: &str, result: &mut Vec<String>) {
    result.push("JSON Output:".to_string());

    // Try to parse and show structure
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(output) {
        match &value {
            serde_json::Value::Array(arr) => {
                result.push(format!("   Array with {} items", arr.len()));
            }
            serde_json::Value::Object(obj) => {
                result.push(format!("   Object with {} keys:", obj.len()));
                for key in obj.keys().take(10) {
                    result.push(format!("   • {}", key));
                }
                if obj.len() > 10 {
                    result.push(format!("   ... +{} more keys", obj.len() - 10));
                }
            }
            _ => {
                result.push(format!("   {}", truncate(&value.to_string(), 100)));
            }
        }
    } else {
        result.push("   (Invalid JSON)".to_string());
    }
}

fn summarize_generic(output: &str, result: &mut Vec<String>) {
    let lines: Vec<&str> = output.lines().collect();

    result.push("Output:".to_string());

    // First few lines
    for line in lines.iter().take(5) {
        if !line.trim().is_empty() {
            result.push(format!("   {}", truncate(line, 75)));
        }
    }

    if lines.len() > 10 {
        result.push("   ...".to_string());
        // Last few lines
        for line in lines.iter().skip(lines.len() - 3) {
            if !line.trim().is_empty() {
                result.push(format!("   {}", truncate(line, 75)));
            }
        }
    }
}

fn extract_number(text: &str, after: &str) -> Option<usize> {
    let re = Regex::new(&format!(r"(\d+)\s*{}", after)).ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}
