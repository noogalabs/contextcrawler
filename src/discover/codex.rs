//! Scans Codex CLI job logs to measure `contextcrawler ` adoption compliance.
//!
//! Codex's `codex-companion` plugin writes per-job logs to
//! `~/.claude/plugins/data/codex-openai-codex/state/<slug>/jobs/*.log`.
//! Each log contains `Running command: /bin/zsh -lc "<cmd>"` lines that
//! we can scan for the `contextcrawler ` prefix. Commands missing the
//! prefix are the compliance gap.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

/// Root for codex-companion plugin state, relative to `$HOME`.
const CODEX_STATE_REL: &str = ".claude/plugins/data/codex-openai-codex/state";

/// Tools that have a wrapped `contextcrawler <tool>` form. A raw invocation
/// of any of these in a codex log is a compliance gap.
const WRAPPED_TOOLS: &[&str] = &[
    "git", "gh", "glab", "gt", "rg", "grep", "find", "ls", "tree", "wc", "diff", "log", "cat",
    "head", "tail", "nl", "sed", "awk", "cargo", "npm", "pnpm", "yarn", "pytest", "ruff", "black",
    "mypy", "tsc", "vitest", "jest", "prettier", "docker", "kubectl", "aws", "psql", "wget",
    "curl", "dotnet", "go", "ruby", "rake", "rspec", "rubocop",
];

#[derive(Debug, Default)]
pub struct CodexCompliance {
    pub logs_scanned: usize,
    pub total_commands: usize,
    pub wrapped_commands: usize,
    /// Map from canonicalised gap pattern (e.g. `nl -ba | sed -n`) to count
    /// of raw commands matching it.
    pub gap_patterns: HashMap<String, usize>,
    /// Top raw commands with counts, sorted descending.
    pub raw_examples: Vec<(String, usize)>,
}

impl CodexCompliance {
    pub fn compliance_pct(&self) -> f64 {
        if self.total_commands == 0 {
            0.0
        } else {
            self.wrapped_commands as f64 * 100.0 / self.total_commands as f64
        }
    }

    pub fn raw_count(&self) -> usize {
        self.total_commands - self.wrapped_commands
    }
}

/// Default location of codex job logs.
pub fn default_state_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(CODEX_STATE_REL))
}

/// Walk a state directory and collect `.log` files modified within `since_days`.
pub fn discover_logs(state_dir: &Path, since_days: Option<u64>) -> Result<Vec<PathBuf>> {
    if !state_dir.try_exists().with_context(|| {
        format!(
            "failed to access codex state dir: {}",
            state_dir.display()
        )
    })? {
        return Ok(Vec::new());
    }

    let cutoff = since_days.map(|days| {
        SystemTime::now()
            .checked_sub(Duration::from_secs(days * 86400))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });

    let mut logs = Vec::new();
    for entry in WalkDir::new(state_dir)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        if let Some(cutoff_time) = cutoff {
            if let Ok(meta) = fs::metadata(path) {
                if let Ok(mtime) = meta.modified() {
                    if mtime < cutoff_time {
                        continue;
                    }
                }
            }
        }
        logs.push(path.to_path_buf());
    }
    Ok(logs)
}

/// Scan a single codex log file and append findings to `compliance`.
pub fn scan_log(path: &Path, raw_counts: &mut HashMap<String, usize>, compliance: &mut CodexCompliance) -> Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(|l| l.ok()) {
        if let Some(cmd) = extract_command(&line) {
            compliance.total_commands += 1;
            if is_wrapped(&cmd) {
                compliance.wrapped_commands += 1;
            } else {
                let pattern = canonicalise_pattern(&cmd);
                *compliance.gap_patterns.entry(pattern).or_insert(0) += 1;
                let example = truncate_for_display(&cmd);
                *raw_counts.entry(example).or_insert(0) += 1;
            }
        }
    }
    Ok(())
}

/// Extract the user-facing command from a `Running command:` log line.
///
/// Codex writes lines like:
///   `[2026-05-18T05:49:12.293Z] Running command: /bin/zsh -lc "contextcrawler git diff …"`
/// or with single quotes:
///   `[2026-05-18T05:49:12.293Z] Running command: /bin/zsh -lc 'rg -n "pat"'`
///
/// We return the command inside the outermost quotes; `None` if the line is
/// not a `Running command:` line or doesn't match the expected shape.
pub fn extract_command(line: &str) -> Option<String> {
    let marker = "Running command:";
    let idx = line.find(marker)?;
    let after = line[idx + marker.len()..].trim_start();

    // Strip the shell prefix if present (`/bin/zsh -lc `, `/bin/bash -lc `, etc.).
    // The actual command is the contents of the next quoted string.
    let quote_start = after.find(['"', '\''])?;
    let quote_char = after.as_bytes()[quote_start] as char;
    let after_quote = &after[quote_start + 1..];
    // Naive: find the next unescaped matching quote. We don't try to parse
    // backslash escapes — for our compliance purposes a truncated tail is
    // fine because we only inspect the first token / prefix anyway.
    let mut end = None;
    let bytes = after_quote.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == quote_char as u8 && (i == 0 || bytes[i - 1] != b'\\') {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let cmd = match end {
        Some(e) => &after_quote[..e],
        None => after_quote, // unterminated — accept what we have
    };
    Some(cmd.trim().to_string())
}

/// Shell-builtin "navigation" prefixes that don't consume token budget and
/// don't need wrapping themselves. A composition like `cd <dir> && <wrapped>`
/// counts as compliant — the substantive command IS wrapped.
const NAV_BUILTINS: &[&str] = &["cd", "pwd", "echo", "true", "false", "export", "unset"];

/// `true` if the command is wrapped. Three accept paths:
/// 1. Starts with `contextcrawler ` (most common case; also covers wrapped
///    commands whose args contain `&&`/`;` inside quoted strings, e.g.
///    `contextcrawler awk 'NR>=1 && NR<=10'`).
/// 2. Starts with a nav builtin (`cd`, `pwd`, etc.) followed by `&&` /
///    `||` / `;` joining a `contextcrawler `-prefixed second segment.
/// 3. Is a standalone nav builtin (`cd /tmp`) — no substantive command.
///
/// We deliberately do not try to parse arbitrary shell compositions —
/// the goal is to recognise the two patterns codex actually uses, not
/// to be a shell tokenizer.
pub fn is_wrapped(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Case 1: direct prefix. Safe even when args contain `&&` etc.
    if trimmed.starts_with("contextcrawler ") {
        return true;
    }

    // Case 2/3: nav-builtin lead. First token = leading run of non-{whitespace,
    // shell-connector} chars. So both `pwd ...` and `pwd;contextcrawler ls`
    // yield first == "pwd".
    let first_end = trimmed
        .find(|c: char| matches!(c, ' ' | '\t' | ';' | '&' | '|'))
        .unwrap_or(trimmed.len());
    let first = &trimmed[..first_end];
    if !NAV_BUILTINS.contains(&first) {
        return false;
    }

    // Find the FIRST sequential connector at top level. We only split on the
    // first occurrence so awk-style quoted `&&` inside a wrapped second
    // segment is preserved. Both spaced (`; `) and unspaced (`;`) semicolons
    // are accepted because codex occasionally emits tightly-packed forms.
    let mut tail: Option<&str> = None;
    for connector in &[" && ", " || ", "; ", ";"] {
        if let Some(idx) = trimmed.find(connector) {
            tail = Some(&trimmed[idx + connector.len()..]);
            break;
        }
    }

    match tail {
        None => true, // standalone nav builtin — case 3
        Some(rest) => is_wrapped(rest), // recurse on the tail
    }
}

/// Reduce a raw command to a coarse pattern label so the report aggregates
/// e.g. `nl -ba /a/b.rs | sed -n '10,20p'` and `nl -ba /c/d.rs | sed -n '5,8p'`
/// under one bucket.
pub fn canonicalise_pattern(cmd: &str) -> String {
    let trimmed = cmd.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Specific composed patterns first.
    if lower.contains("nl -ba") && lower.contains("| sed") {
        return "nl -ba <file> | sed -n '<range>p'".to_string();
    }
    // CASE-SENSITIVE: `-C <dir>` is project-dir override; `-c key=val` is
    // config override. Lowercasing would collapse them into one bucket and
    // mis-attribute every CI `git -c core.X=Y` invocation to the gap. Keep
    // these two checks on the original-cased `trimmed`.
    if trimmed.starts_with("git -C ") || trimmed.starts_with("git -C\t") {
        return "git -C <dir> <subcmd>".to_string();
    }
    if trimmed.starts_with("git -c ") || trimmed.starts_with("git -c\t") {
        return "git -c <key=val> <subcmd>".to_string();
    }
    if lower.starts_with("rg ") || lower.starts_with("rg\t") {
        return "rg <args>".to_string();
    }
    if lower.starts_with("nl ") {
        return "nl <args>".to_string();
    }
    if lower.starts_with("sed ") {
        return "sed <args>".to_string();
    }
    if lower.starts_with("awk ") {
        return "awk <args>".to_string();
    }

    // Fallback: first token only.
    trimmed
        .split_whitespace()
        .next()
        .unwrap_or(trimmed)
        .to_string()
}

fn truncate_for_display(cmd: &str) -> String {
    const MAX_CHARS: usize = 100;
    let s = cmd.trim();
    // Use char_indices, not byte slicing — command strings from arbitrary logs
    // may contain multibyte UTF-8 (paths with Japanese, emoji in piped output)
    // and byte-slicing across a char boundary panics.
    let cut = s
        .char_indices()
        .nth(MAX_CHARS)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    if cut == s.len() {
        s.to_string()
    } else {
        format!("{}…", &s[..cut])
    }
}

/// Run a full compliance scan over `state_dir` (or the default location if
/// `None`) and return the aggregated report.
pub fn scan(state_dir: Option<&Path>, since_days: Option<u64>) -> Result<CodexCompliance> {
    let owned;
    let dir = match state_dir {
        Some(p) => p,
        None => {
            owned = default_state_dir()?;
            owned.as_path()
        }
    };

    let logs = discover_logs(dir, since_days)?;
    let mut compliance = CodexCompliance::default();
    let mut raw_counts: HashMap<String, usize> = HashMap::new();
    for log in &logs {
        if let Err(e) = scan_log(log, &mut raw_counts, &mut compliance) {
            eprintln!("[contextcrawler] discover --codex: skipping {}: {}", log.display(), e);
        }
    }
    compliance.logs_scanned = logs.len();

    // Sort raw examples by count, descending; cap at 20 for display.
    let mut sorted: Vec<(String, usize)> = raw_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    compliance.raw_examples = sorted.into_iter().take(20).collect();

    Ok(compliance)
}

/// Format a `CodexCompliance` report as human-readable text.
pub fn format_text(c: &CodexCompliance) -> String {
    let mut out = String::new();
    out.push_str("ContextCrawler — Codex CLI Compliance\n");
    out.push_str("════════════════════════════════════════════════════════════\n\n");
    out.push_str(&format!("Logs scanned     : {}\n", c.logs_scanned));
    out.push_str(&format!("Total commands   : {}\n", c.total_commands));
    out.push_str(&format!(
        "Wrapped          : {} ({:.1}%)\n",
        c.wrapped_commands,
        c.compliance_pct()
    ));
    out.push_str(&format!(
        "Raw (gap)        : {} ({:.1}%)\n\n",
        c.raw_count(),
        100.0 - c.compliance_pct()
    ));

    if !WRAPPED_TOOLS.is_empty() && c.raw_count() > 0 {
        out.push_str("Gap patterns (canonicalised):\n");
        let mut patterns: Vec<(&String, &usize)> = c.gap_patterns.iter().collect();
        patterns.sort_by(|a, b| b.1.cmp(a.1));
        for (pat, count) in patterns.iter().take(10) {
            out.push_str(&format!("  {:>5}  {}\n", count, pat));
        }
        out.push('\n');

        out.push_str("Top raw command examples:\n");
        for (ex, count) in c.raw_examples.iter().take(15) {
            out.push_str(&format!("  {:>5}  {}\n", count, ex));
        }
        out.push('\n');
    }

    if c.compliance_pct() < 95.0 && c.total_commands > 0 {
        out.push_str(&format!(
            "→ Compliance below target (≥95%). Gap = {} commands.\n",
            c.raw_count()
        ));
        out.push_str("  Update ~/.codex/CONTEXTCRAWLER.md (run `contextcrawler init --codex` to refresh).\n");
    } else if c.total_commands > 0 {
        out.push_str("✓ Compliance at target (≥95%).\n");
    }

    out
}

/// Format a `CodexCompliance` report as JSON.
pub fn format_json(c: &CodexCompliance) -> String {
    let patterns: HashMap<&str, usize> =
        c.gap_patterns.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    let examples: Vec<serde_json::Value> = c
        .raw_examples
        .iter()
        .map(|(ex, count)| serde_json::json!({ "command": ex, "count": count }))
        .collect();
    serde_json::json!({
        "logs_scanned": c.logs_scanned,
        "total_commands": c.total_commands,
        "wrapped_commands": c.wrapped_commands,
        "raw_commands": c.raw_count(),
        "compliance_pct": (c.compliance_pct() * 10.0).round() / 10.0,
        "gap_patterns": patterns,
        "top_raw_examples": examples,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extract_command_double_quoted() {
        let line = r#"[2026-05-18T05:49:12.293Z] Running command: /bin/zsh -lc "contextcrawler git diff develop"#;
        let cmd = extract_command(line).expect("should extract");
        assert!(cmd.starts_with("contextcrawler git diff"));
    }

    #[test]
    fn extract_command_single_quoted() {
        let line = r#"[2026-05-18T05:49:12.293Z] Running command: /bin/zsh -lc 'rg -n "pat" src/'"#;
        let cmd = extract_command(line).expect("should extract");
        assert_eq!(cmd, r#"rg -n "pat" src/"#);
    }

    #[test]
    fn extract_command_no_marker() {
        assert_eq!(extract_command("[ts] Command completed: foo (exit 0)"), None);
        assert_eq!(extract_command(""), None);
    }

    #[test]
    fn is_wrapped_basic() {
        assert!(is_wrapped("contextcrawler git status"));
        assert!(is_wrapped("  contextcrawler rg foo"));
        assert!(!is_wrapped("git status"));
        assert!(!is_wrapped("nl -ba src/x.rs | sed -n '1,10p'"));
        // Adjacent (no space) prefix is not a wrap.
        assert!(!is_wrapped("contextcrawlerthing"));
    }

    #[test]
    fn truncate_for_display_handles_multibyte() {
        // REGRESSION (pre-PR review): byte-index slice across a multibyte
        // boundary panics. Use a string where the 100th char is multibyte.
        let s: String = "日本語パスで読み込み".chars().cycle().take(150).collect();
        // Should not panic; result is well-formed UTF-8 with the ellipsis.
        let out = truncate_for_display(&s);
        assert!(out.ends_with('…'));
        assert!(out.is_char_boundary(out.len() - '…'.len_utf8()));
    }

    #[test]
    fn is_wrapped_handles_cd_compositions() {
        assert!(is_wrapped("cd /tmp && contextcrawler git status"));
        assert!(is_wrapped(
            "cd /tmp && cd ../other && contextcrawler git diff"
        ));
        assert!(is_wrapped("pwd; contextcrawler ls"));
        // Bare cd alone is fine — no substantive command at all.
        assert!(is_wrapped("cd /tmp"));
        // cd + raw command = still a gap.
        assert!(!is_wrapped("cd /tmp && git status"));
        // Empty / whitespace.
        assert!(!is_wrapped(""));
        assert!(!is_wrapped("   "));
    }

    #[test]
    fn is_wrapped_handles_tightly_packed_semicolons() {
        // REGRESSION (pre-PR review): connector list previously only had
        // `"; "` (with trailing space), so `pwd;contextcrawler ls` would
        // fall through to "standalone nav builtin" and falsely report wrapped.
        // Now both `; ` and `;` are accepted as connectors.
        assert!(is_wrapped("pwd;contextcrawler ls"));
        assert!(!is_wrapped("pwd;ls"));
        assert!(is_wrapped("export FOO=bar;contextcrawler git status"));
        assert!(!is_wrapped("export FOO=bar;git status"));
    }

    #[test]
    fn is_wrapped_known_limitation_pipe_to_raw() {
        // Documented limitation: a wrapped command piped into a raw filter is
        // currently counted as wrapped (case 1 matches the leading prefix and
        // we don't shell-tokenise the rest). This is a slight overcount but is
        // accepted to keep the scanner simple and avoid mis-handling quoted
        // `|` inside wrapped tool args (e.g. `contextcrawler awk '$1|$2'`).
        assert!(is_wrapped("contextcrawler ls | grep foo"));
    }

    #[test]
    fn canonicalise_nl_sed_pipe() {
        let p = canonicalise_pattern("nl -ba /a/b.rs | sed -n '10,20p'");
        assert_eq!(p, "nl -ba <file> | sed -n '<range>p'");
    }

    #[test]
    fn canonicalise_git_dash_c() {
        let p = canonicalise_pattern("git -C /Users/x/repo status --short");
        assert_eq!(p, "git -C <dir> <subcmd>");
    }

    #[test]
    fn canonicalise_git_lowercase_c_is_separate_bucket() {
        // REGRESSION (pre-PR review): the original implementation lowercased
        // the command before matching, collapsing `git -c` (config override)
        // into the `git -C <dir>` bucket. Every CI `git -c core.X=Y` invocation
        // would inflate the gap report. Keep these two buckets distinct.
        let lower = canonicalise_pattern("git -c core.pager=cat log --oneline");
        assert_eq!(lower, "git -c <key=val> <subcmd>");
        let upper = canonicalise_pattern("git -C /repo log");
        assert_eq!(upper, "git -C <dir> <subcmd>");
        assert_ne!(lower, upper);
    }

    #[test]
    fn canonicalise_rg() {
        assert_eq!(canonicalise_pattern("rg -n foo src/"), "rg <args>");
        assert_eq!(canonicalise_pattern("rg foo"), "rg <args>");
    }

    #[test]
    fn canonicalise_fallback_first_token() {
        assert_eq!(canonicalise_pattern("mvn clean install"), "mvn");
    }

    #[test]
    fn scan_log_counts_wrapped_and_raw() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"[2026-05-18T05:49:12.293Z] Running command: /bin/zsh -lc "contextcrawler git status""#
        )
        .unwrap();
        writeln!(
            f,
            r#"[2026-05-18T05:49:13.293Z] Running command: /bin/zsh -lc "nl -ba x.rs | sed -n '1,5p'""#
        )
        .unwrap();
        writeln!(
            f,
            r#"[2026-05-18T05:49:14.293Z] Running command: /bin/zsh -lc "git -C /repo log""#
        )
        .unwrap();
        writeln!(f, "[2026-05-18T05:49:15.293Z] Some unrelated line.").unwrap();
        f.flush().unwrap();

        let mut c = CodexCompliance::default();
        let mut raw = HashMap::new();
        scan_log(f.path(), &mut raw, &mut c).unwrap();
        assert_eq!(c.total_commands, 3);
        assert_eq!(c.wrapped_commands, 1);
        assert_eq!(c.raw_count(), 2);
        assert!(c
            .gap_patterns
            .contains_key("nl -ba <file> | sed -n '<range>p'"));
        assert!(c.gap_patterns.contains_key("git -C <dir> <subcmd>"));
    }

    #[test]
    fn scan_returns_empty_for_missing_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let c = scan(Some(&missing), None).unwrap();
        assert_eq!(c.logs_scanned, 0);
        assert_eq!(c.total_commands, 0);
    }

    #[test]
    fn format_text_renders_compliance_line() {
        let mut c = CodexCompliance::default();
        c.logs_scanned = 1;
        c.total_commands = 100;
        c.wrapped_commands = 84;
        c.gap_patterns.insert("nl -ba <file> | sed -n '<range>p'".to_string(), 10);
        c.raw_examples.push(("nl -ba /x | sed -n '1,5p'".to_string(), 10));
        let text = format_text(&c);
        assert!(text.contains("Wrapped"));
        assert!(text.contains("84"));
        assert!(text.contains("84.0%"));
        assert!(text.contains("nl -ba <file>"));
        assert!(text.contains("→ Compliance below target"));
    }

    #[test]
    fn format_text_target_met() {
        let mut c = CodexCompliance::default();
        c.logs_scanned = 1;
        c.total_commands = 100;
        c.wrapped_commands = 97;
        let text = format_text(&c);
        assert!(text.contains("✓ Compliance at target"));
    }

    #[test]
    fn format_json_shape() {
        let mut c = CodexCompliance::default();
        c.total_commands = 10;
        c.wrapped_commands = 9;
        let json = format_json(&c);
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["total_commands"], 10);
        assert_eq!(val["wrapped_commands"], 9);
        assert_eq!(val["raw_commands"], 1);
        assert_eq!(val["compliance_pct"], 90.0);
    }
}
