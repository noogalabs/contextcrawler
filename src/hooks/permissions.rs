use super::constants::{CLAUDE_DIR, SETTINGS_JSON, SETTINGS_LOCAL_JSON};
use crate::core::stream::exec_capture_short;
use crate::discover::lexer::{extract_substitutions, shell_split, split_on_operators, strip_quotes};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// Wall-clock budget for the `git rev-parse --show-toplevel` fallback in
/// `find_project_root`. This runs inside Claude Code's PreToolUse hook
/// path; a stalled git (dead NFS / hung FUSE / network mount) would
/// otherwise freeze the agent. 10s is generous for a healthy git and
/// short enough that fall-through to "no project root" is the right
/// answer when git is wedged. See docs/security/AUDIT-subprocess-timeouts.md
/// finding F-02.
const GIT_TOPLEVEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Verdict from checking a command against Claude Code's permission rules.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PermissionVerdict {
    /// An explicit allow rule matched — safe to auto-allow.
    Allow,
    /// A deny rule matched — pass through to Claude Code's native deny handling.
    Deny,
    /// An ask rule matched — rewrite the command but let Claude Code prompt the user.
    Ask,
    /// No rule matched — default to ask (matches Claude Code's least-privilege default).
    Default,
}

/// Check `cmd` against Claude Code's deny/ask/allow permission rules.
///
/// Precedence: Deny > Ask > Allow > Default (ask).
/// Returns `Default` when no rules match — callers should treat this as ask
/// to match Claude Code's least-privilege default.
pub fn check_command(cmd: &str) -> PermissionVerdict {
    let (deny_rules, ask_rules, allow_rules) = load_permission_rules();
    check_command_with_rules(cmd, &deny_rules, &ask_rules, &allow_rules)
}

/// Internal implementation allowing tests to inject rules without file I/O.
pub(crate) fn check_command_with_rules(
    cmd: &str,
    deny_rules: &[String],
    ask_rules: &[String],
    allow_rules: &[String],
) -> PermissionVerdict {
    let segments = split_compound_command(cmd);
    let mut any_ask = false;
    // Every non-empty segment must independently match an allow rule for the
    // compound command to receive Allow. See issue #1213: previously a single
    // matching segment escalated the entire chain to Allow, enabling bypass.
    let mut all_segments_allowed = true;
    let mut saw_segment = false;

    for segment in &segments {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        saw_segment = true;

        // Deny takes highest priority — any segment matching Deny blocks the whole chain.
        for pattern in deny_rules {
            if command_matches_pattern(segment, pattern) {
                return PermissionVerdict::Deny;
            }
        }

        // Ask — if any segment matches an ask rule, the final verdict is Ask.
        if !any_ask {
            for pattern in ask_rules {
                if command_matches_pattern(segment, pattern) {
                    any_ask = true;
                    break;
                }
            }
        }

        // Allow — every non-empty segment must match an allow rule independently.
        // As soon as one segment fails to match, the entire chain loses Allow status.
        if all_segments_allowed {
            let matched = allow_rules
                .iter()
                .any(|pattern| command_matches_pattern(segment, pattern));
            if !matched {
                all_segments_allowed = false;
            }
        }
    }

    // Precedence: Deny > Ask > Allow > Default (ask).
    // Allow requires (1) at least one segment seen, (2) all segments matched, (3) non-empty rules.
    if any_ask {
        PermissionVerdict::Ask
    } else if saw_segment && all_segments_allowed && !allow_rules.is_empty() {
        PermissionVerdict::Allow
    } else {
        PermissionVerdict::Default
    }
}

/// Load deny, ask, and allow Bash rules from all Claude Code settings files.
///
/// Files read (in order, later files do not override earlier ones — all are merged):
/// 1. `$PROJECT_ROOT/.claude/settings.json`
/// 2. `$PROJECT_ROOT/.claude/settings.local.json`
/// 3. `~/.claude/settings.json`
/// 4. `~/.claude/settings.local.json`
///
/// Missing files and malformed JSON are silently skipped.
fn load_permission_rules() -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut deny_rules = Vec::new();
    let mut ask_rules = Vec::new();
    let mut allow_rules = Vec::new();

    for path in get_settings_paths() {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&content) else {
            eprintln!(
                "[contextcrawler] warning: failed to parse permissions from {}",
                path.display()
            );
            continue;
        };
        let Some(permissions) = json.get("permissions") else {
            continue;
        };

        append_bash_rules(permissions.get("deny"), &mut deny_rules);
        append_bash_rules(permissions.get("ask"), &mut ask_rules);
        append_bash_rules(permissions.get("allow"), &mut allow_rules);
    }

    (deny_rules, ask_rules, allow_rules)
}

/// Extract Bash-scoped patterns from a JSON array and append them to `target`.
///
/// Only rules with a `Bash(...)` prefix are kept. Non-Bash rules (e.g. `Read(...)`) are ignored.
fn append_bash_rules(rules_value: Option<&Value>, target: &mut Vec<String>) {
    let Some(arr) = rules_value.and_then(|v| v.as_array()) else {
        return;
    };
    for rule in arr {
        if let Some(s) = rule.as_str() {
            if s.starts_with("Bash(") {
                target.push(extract_bash_pattern(s).to_string());
            }
        }
    }
}

/// Return the ordered list of Claude Code settings file paths to check.
fn get_settings_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(root) = find_project_root() {
        paths.push(root.join(CLAUDE_DIR).join(SETTINGS_JSON));
        paths.push(root.join(CLAUDE_DIR).join(SETTINGS_LOCAL_JSON));
    }
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(CLAUDE_DIR).join(SETTINGS_JSON));
        paths.push(home.join(CLAUDE_DIR).join(SETTINGS_LOCAL_JSON));
    }

    paths
}

/// Locate the project root by walking up from CWD looking for `.claude/`.
///
/// Falls back to `git rev-parse --show-toplevel` if not found via directory walk.
fn find_project_root() -> Option<PathBuf> {
    // Fast path: walk up CWD looking for .claude/ — no subprocess needed.
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join(CLAUDE_DIR).exists() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }

    // Fallback: git (spawns a subprocess, slower but handles monorepo layouts).
    // exec_capture_short bounds the wall-clock so a stalled git can't freeze
    // the PreToolUse hook. Timeout → None → caller treats as "no project root".
    // `secure_git_command` strips the env-driven RCE vectors (GIT_EXTERNAL_DIFF,
    // GIT_SSH_COMMAND, GIT_CONFIG_GLOBAL, GIT_CONFIG_COUNT/_KEY_/_VALUE_, …)
    // — even though `rev-parse --show-toplevel` itself is not a known exec
    // sink, hardening uniformly avoids surprises if a future git version
    // grows one. See issue #35.
    let mut cmd = crate::core::utils::secure_git_command();
    cmd.args(["rev-parse", "--show-toplevel"]);
    let result = exec_capture_short(&mut cmd, GIT_TOPLEVEL_TIMEOUT).ok()?;

    if result.success() {
        return Some(PathBuf::from(result.stdout.trim()));
    }

    None
}

/// Extract the pattern string from inside `Bash(pattern)`.
///
/// Returns the original string unchanged if it does not match the expected format.
pub(crate) fn extract_bash_pattern(rule: &str) -> &str {
    if let Some(inner) = rule.strip_prefix("Bash(") {
        if let Some(pattern) = inner.strip_suffix(')') {
            return pattern;
        }
    }
    rule
}

/// Normalise a command (or pattern) into a canonical token sequence.
///
/// Tokenises via the shell lexer (`shell_split`), which collapses runs of
/// whitespace, honours quotes, and resolves backslash escapes. Each token
/// then has one layer of surrounding quotes stripped, so `"push"` and
/// `push` compare equal.
///
/// This is the SEC-C3 fix: byte-prefix matching let an attacker dodge a
/// deny rule with `git  push  --force` (double space) or `git "push"
/// --force` (quoted token). Comparing normalised token *sequences* makes
/// those variants identical to the canonical command.
fn normalise_tokens(s: &str) -> Vec<String> {
    shell_split(s)
        .into_iter()
        .map(|t| strip_quotes(&t))
        .collect()
}

/// Re-join a command into a canonical, single-space-separated form.
///
/// Used so the glob/wildcard matcher sees the same whitespace-normalised
/// string regardless of how the attacker spaced or quoted the original.
fn canonical_command(cmd: &str) -> String {
    normalise_tokens(cmd).join(" ")
}

/// Check if `cmd` matches a Claude Code permission pattern.
///
/// Matching is **token-aware** (SEC-C3): both `cmd` and `pattern` are
/// normalised into token sequences (whitespace collapsed, surrounding
/// quotes stripped) before comparison, so `git  push  --force` and
/// `git "push" --force` match a `git push --force` rule.
///
/// Pattern forms:
/// - `*` → matches everything
/// - `prefix:*` or `prefix *` (trailing `*`, no other wildcards) → token-prefix match
/// - `* suffix`, `pre * suf` → glob matching where `*` matches any sequence of characters
/// - `pattern` → exact match or token-prefix match (pattern tokens must prefix cmd tokens)
pub(crate) fn command_matches_pattern(cmd: &str, pattern: &str) -> bool {
    // 1. Global wildcard
    if pattern == "*" {
        return true;
    }

    // 2. Trailing-only wildcard: token-prefix match with word-boundary preservation
    //    Handles: "git push*", "git push *", "sudo:*"
    if let Some(p) = pattern.strip_suffix('*') {
        let prefix = p.trim_end_matches(':').trim_end();
        // Bug 2 fix: after stripping, if prefix is empty or just wildcards, match everything
        if prefix.is_empty() || prefix == "*" {
            return true;
        }
        // No other wildcards in prefix -> token-prefix fast path
        if !prefix.contains('*') {
            return tokens_prefix_match(cmd, prefix);
        }
        // Prefix still contains '*' -> fall through to glob matching
    }

    // 3. Complex wildcards (leading, middle, multiple): glob matching.
    //    Run against the whitespace-normalised command so spacing/quoting
    //    variants cannot evade a glob deny rule either.
    if pattern.contains('*') {
        return glob_matches(&canonical_command(cmd), pattern);
    }

    // 4. No wildcard: token-sequence comparison — the pattern's tokens must
    //    be a prefix of the command's tokens (exact when equal length).
    tokens_prefix_match(cmd, pattern)
}

/// True when `pattern`'s normalised token sequence is a prefix of `cmd`'s.
///
/// Equal-length sequences mean an exact command match; a shorter pattern
/// means a prefix match with a word (token) boundary — `git push --force`
/// matches a `git push` pattern, but `git pushy` does not.
fn tokens_prefix_match(cmd: &str, pattern: &str) -> bool {
    let cmd_tokens = normalise_tokens(cmd);
    let pat_tokens = normalise_tokens(pattern);
    if pat_tokens.is_empty() || pat_tokens.len() > cmd_tokens.len() {
        return false;
    }
    cmd_tokens
        .iter()
        .zip(pat_tokens.iter())
        .all(|(c, p)| c == p)
}

/// Glob-style matching where `*` matches any character sequence (including empty).
///
/// Colon syntax normalized: `sudo:*` treated as `sudo *` for word separation.
fn glob_matches(cmd: &str, pattern: &str) -> bool {
    // Normalize colon-wildcard syntax: "sudo:*" -> "sudo *", "*:rm" -> "* rm"
    let normalized = pattern.replace(":*", " *").replace("*:", "* ");
    let parts: Vec<&str> = normalized.split('*').collect();

    // All-stars pattern (e.g. "***") matches everything
    if parts.iter().all(|p| p.is_empty()) {
        return true;
    }

    let mut search_from = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 {
            // First segment: must be prefix (pattern doesn't start with *)
            if !cmd.starts_with(part) {
                return false;
            }
            search_from = part.len();
        } else if i == parts.len() - 1 {
            // Last segment: must be suffix (pattern doesn't end with *)
            if !cmd[search_from..].ends_with(*part) {
                return false;
            }
        } else {
            // Middle segment: find next occurrence.
            // Also accept end-of-string when the segment ends with whitespace — this
            // handles commands that terminate at the middle token without trailing args,
            // e.g. "git -C * diff:*" should match bare "git -C /path diff" (#1105).
            let remaining = &cmd[search_from..];
            if let Some(pos) = remaining.find(*part) {
                search_from += pos + part.len();
            } else {
                let trimmed = part.trim_end();
                if !trimmed.is_empty() && remaining.ends_with(trimmed) {
                    search_from += remaining.len();
                } else {
                    return false;
                }
            }
        }
    }

    true
}

/// Decompose a command into independently-checkable segments.
///
/// Splits on shell operators (`&&`, `||`, `;`, `|`) AND surfaces the inner
/// payload of every command substitution (`$(...)`, backtick, `<(...)`,
/// `>(...)`) as its own segment — including nested substitutions.
///
/// This is the SEC-C2 fix: previously a deny rule like `rm -rf` was fully
/// bypassed by `echo $(rm -rf /x)`, because the inner `rm` was only a
/// substring of the outer segment and `command_matches_pattern` does
/// token-prefix matching, not substring matching. By promoting the inner
/// command to a first-class segment, `check_command_with_rules` evaluates
/// it against the deny/ask/allow rules directly.
///
/// Fail-closed: a malformed (unbalanced) substitution surfaces a sentinel
/// segment that no allow rule can match, so the compound command can never
/// reach `Allow` while carrying an un-evaluatable substitution.
fn split_compound_command(cmd: &str) -> Vec<String> {
    let mut segments: Vec<String> = split_on_operators(cmd, false)
        .into_iter()
        .map(str::to_string)
        .collect();

    // Surface command-substitution payloads. Each inner command is itself
    // split on operators so a substitution containing a chain is fully
    // decomposed.
    for sub in extract_substitutions(cmd) {
        // A malformed (unbalanced) substitution still gets its recovered
        // inner text evaluated — a deny rule inside it must still bite —
        // AND a fail-closed sentinel is pushed so the chain can never
        // reach Allow while carrying an un-parsable construct.
        if sub.malformed {
            segments.push(SUBST_FAIL_CLOSED_SENTINEL.to_string());
        }
        for inner_seg in split_on_operators(&sub.inner, false) {
            let trimmed = inner_seg.trim();
            if !trimmed.is_empty() {
                segments.push(trimmed.to_string());
            }
        }
    }

    segments
}

/// Sentinel segment emitted for a malformed/un-evaluatable command
/// substitution. Contains characters no real command starts with, so it
/// matches no allow rule (forcing the chain off `Allow`) and no deny rule.
const SUBST_FAIL_CLOSED_SENTINEL: &str = "\u{0}contextcrawler-unparsable-substitution\u{0}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_pattern() {
        assert_eq!(
            extract_bash_pattern("Bash(git push --force)"),
            "git push --force"
        );
        assert_eq!(extract_bash_pattern("Bash(*)"), "*");
        assert_eq!(extract_bash_pattern("Bash(sudo:*)"), "sudo:*");
        assert_eq!(extract_bash_pattern("Read(**/.env*)"), "Read(**/.env*)"); // unchanged
    }

    #[test]
    fn test_exact_match() {
        assert!(command_matches_pattern(
            "git push --force",
            "git push --force"
        ));
    }

    #[test]
    fn test_wildcard_colon() {
        assert!(command_matches_pattern("sudo rm -rf /", "sudo:*"));
    }

    #[test]
    fn test_no_match() {
        assert!(!command_matches_pattern("git status", "git push --force"));
    }

    #[test]
    fn test_deny_precedence_over_ask() {
        let deny = vec!["git push --force".to_string()];
        let ask = vec!["git push --force".to_string()];
        assert_eq!(
            check_command_with_rules("git push --force", &deny, &ask, &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_non_bash_rules_ignored() {
        assert_eq!(extract_bash_pattern("Read(**/.env*)"), "Read(**/.env*)");

        // With empty rule sets, verdict is Default (not Allow).
        assert_eq!(
            check_command_with_rules("cat .env", &[], &[], &[]),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_empty_permissions() {
        // No rules at all → Default (ask), not Allow.
        assert_eq!(
            check_command_with_rules("git push --force", &[], &[], &[]),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_prefix_match() {
        assert!(command_matches_pattern(
            "git push --force origin main",
            "git push --force"
        ));
    }

    #[test]
    fn test_wildcard_all() {
        assert!(command_matches_pattern("anything at all", "*"));
        assert!(command_matches_pattern("", "*"));
    }

    #[test]
    fn test_no_partial_word_match() {
        // "git push --forceful" must NOT match pattern "git push --force".
        assert!(!command_matches_pattern(
            "git push --forceful",
            "git push --force"
        ));
    }

    #[test]
    fn test_compound_command_deny() {
        let deny = vec!["git push --force".to_string()];
        assert_eq!(
            check_command_with_rules("git status && git push --force", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_compound_command_ask() {
        let ask = vec!["git push".to_string()];
        assert_eq!(
            check_command_with_rules("git status && git push origin main", &[], &ask, &[]),
            PermissionVerdict::Ask
        );
    }

    #[test]
    fn test_compound_command_deny_overrides_ask() {
        let deny = vec!["git push --force".to_string()];
        let ask = vec!["git status".to_string()];
        assert_eq!(
            check_command_with_rules("git status && git push --force", &deny, &ask, &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_quoted_operators_not_split() {
        // "&&" inside quotes must NOT cause a split — old naive splitter got this wrong
        let deny = vec!["git push --force".to_string()];
        assert_eq!(
            check_command_with_rules(r#"echo "git push --force && danger""#, &deny, &[], &[]),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_pipe_segments_checked() {
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("cat file | rm -rf /", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_ask_verdict() {
        let ask = vec!["git push".to_string()];
        assert_eq!(
            check_command_with_rules("git push origin main", &[], &ask, &[]),
            PermissionVerdict::Ask
        );
    }

    #[test]
    fn test_sudo_wildcard_no_false_positive() {
        // "sudoedit" must NOT match "sudo:*" (word boundary respected).
        assert!(!command_matches_pattern("sudoedit /etc/hosts", "sudo:*"));
    }

    // Bug 2: *:* catch-all must match everything
    #[test]
    fn test_star_colon_star_matches_everything() {
        assert!(command_matches_pattern("rm -rf /", "*:*"));
        assert!(command_matches_pattern("git push --force", "*:*"));
        assert!(command_matches_pattern("anything", "*:*"));
    }

    // Bug 3: leading wildcard — positive
    #[test]
    fn test_leading_wildcard() {
        assert!(command_matches_pattern("git push --force", "* --force"));
        assert!(command_matches_pattern("npm run --force", "* --force"));
    }

    // Bug 3: leading wildcard — negative (suffix anchoring)
    #[test]
    fn test_leading_wildcard_no_partial() {
        assert!(!command_matches_pattern("git push --forceful", "* --force"));
        assert!(!command_matches_pattern("git push", "* --force"));
    }

    // Bug 3: middle wildcard — positive
    #[test]
    fn test_middle_wildcard() {
        assert!(command_matches_pattern("git push main", "git * main"));
        assert!(command_matches_pattern("git rebase main", "git * main"));
    }

    // Bug 3: middle wildcard — negative
    #[test]
    fn test_middle_wildcard_no_match() {
        assert!(!command_matches_pattern("git push develop", "git * main"));
    }

    // Bug 3: middle wildcard at end-of-command (no trailing args) — #1105
    #[test]
    fn test_middle_wildcard_at_end_of_command() {
        // "git -C * diff:*" should match bare "git -C /path diff" (no trailing flags)
        assert!(command_matches_pattern(
            "git -C /path diff",
            "git -C * diff:*"
        ));
        // Must still match when there ARE trailing args
        assert!(command_matches_pattern(
            "git -C /path diff --stat",
            "git -C * diff:*"
        ));
        // Must NOT match a different subcommand
        assert!(!command_matches_pattern(
            "git -C /path status",
            "git -C * diff:*"
        ));
    }

    // Bug 3: multiple wildcards
    #[test]
    fn test_multiple_wildcards() {
        assert!(command_matches_pattern(
            "git push --force origin main",
            "git * --force *"
        ));
        assert!(!command_matches_pattern(
            "git pull origin main",
            "git * --force *"
        ));
    }

    // Integration: deny with leading wildcard
    #[test]
    fn test_deny_with_leading_wildcard() {
        let deny = vec!["* --force".to_string()];
        assert_eq!(
            check_command_with_rules("git push --force", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
        assert_eq!(
            check_command_with_rules("git push", &deny, &[], &[]),
            PermissionVerdict::Default
        );
    }

    // Integration: deny *:* blocks everything
    #[test]
    fn test_deny_star_colon_star() {
        let deny = vec!["*:*".to_string()];
        assert_eq!(
            check_command_with_rules("rm -rf /", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    // --- Allow rules tests ---

    #[test]
    fn test_explicit_allow_rule() {
        let allow = vec!["git status".to_string()];
        assert_eq!(
            check_command_with_rules("git status", &[], &[], &allow),
            PermissionVerdict::Allow
        );
    }

    #[test]
    fn test_allow_wildcard() {
        let allow = vec!["git *".to_string()];
        assert_eq!(
            check_command_with_rules("git log --oneline", &[], &[], &allow),
            PermissionVerdict::Allow
        );
    }

    #[test]
    fn test_deny_overrides_allow() {
        let deny = vec!["git push --force".to_string()];
        let allow = vec!["git *".to_string()];
        assert_eq!(
            check_command_with_rules("git push --force", &deny, &[], &allow),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_ask_overrides_allow() {
        let ask = vec!["git push".to_string()];
        let allow = vec!["git *".to_string()];
        assert_eq!(
            check_command_with_rules("git push origin main", &[], &ask, &allow),
            PermissionVerdict::Ask
        );
    }

    #[test]
    fn test_no_rules_returns_default() {
        assert_eq!(
            check_command_with_rules("cargo test", &[], &[], &[]),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_default_not_allow_when_unmatched() {
        // Commands not in any list should get Default, not Allow
        let allow = vec!["git *".to_string()];
        assert_eq!(
            check_command_with_rules("cargo build", &[], &[], &allow),
            PermissionVerdict::Default
        );
    }

    // --- Regression tests for #1213 ---
    // Compound command permission escalation: a single allowed segment must NOT
    // grant Allow to the entire chain. Every non-empty segment must match
    // independently.

    #[test]
    fn test_compound_allow_requires_every_segment() {
        // Reproduces #1213: `git status` is allowed but `git add .` is not.
        // Previously the chain was escalated to Allow — must now demote to Default.
        let allow = vec![
            "git status *".to_string(),
            "git status".to_string(),
            "cargo *".to_string(),
        ];

        // Single allowed command → Allow
        assert_eq!(
            check_command_with_rules("git status", &[], &[], &allow),
            PermissionVerdict::Allow
        );

        // Single unallowed command → Default
        assert_eq!(
            check_command_with_rules("git add .", &[], &[], &allow),
            PermissionVerdict::Default
        );

        // BUG #1213: chain with one allowed + one unallowed → must be Default
        assert_eq!(
            check_command_with_rules("git status && git add .", &[], &[], &allow),
            PermissionVerdict::Default,
            "allowed segment must not escalate unallowed segment"
        );

        // Three-segment chain with middle unallowed → Default
        assert_eq!(
            check_command_with_rules(
                "cargo test && git add . && git commit -m foo",
                &[],
                &[],
                &allow,
            ),
            PermissionVerdict::Default,
            "middle unallowed segment must demote the whole chain"
        );

        // Unallowed-then-allowed ordering must also demote
        assert_eq!(
            check_command_with_rules("git add . && git status", &[], &[], &allow),
            PermissionVerdict::Default,
            "unallowed first segment must demote the chain"
        );
    }

    #[test]
    fn test_compound_allow_all_segments_matched() {
        // All segments match → Allow (regression: wildcard allow still works)
        let allow = vec!["git *".to_string(), "cargo *".to_string()];

        assert_eq!(
            check_command_with_rules("git status && cargo test", &[], &[], &allow),
            PermissionVerdict::Allow
        );

        assert_eq!(
            check_command_with_rules(
                "git log --oneline && cargo build && git status",
                &[],
                &[],
                &allow
            ),
            PermissionVerdict::Allow
        );
    }

    #[test]
    fn test_compound_allow_semicolon_separator() {
        // `;` separator must be handled identically to `&&`.
        let allow = vec!["git status".to_string()];
        assert_eq!(
            check_command_with_rules("git status; git push", &[], &[], &allow),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_compound_allow_pipe_separator() {
        // `|` separator must be handled identically to `&&`.
        let allow = vec!["git log".to_string()];
        assert_eq!(
            check_command_with_rules("git log | grep foo", &[], &[], &allow),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_compound_allow_or_separator() {
        // `||` separator must also split segments.
        let allow = vec!["cargo build".to_string()];
        assert_eq!(
            check_command_with_rules("cargo build || cargo clean", &[], &[], &allow),
            PermissionVerdict::Default
        );
    }

    #[test]
    fn test_compound_ask_still_wins_over_partial_allow() {
        // If any segment hits an ask rule, verdict is Ask (ask > allow).
        let ask = vec!["git push".to_string()];
        let allow = vec!["git *".to_string()];
        assert_eq!(
            check_command_with_rules("git status && git push origin main", &[], &ask, &allow),
            PermissionVerdict::Ask
        );
    }

    // --- SEC-C3: token-aware matching ---
    // Byte-prefix matching let an attacker dodge a deny rule with trivial
    // whitespace/quoting variation. Matching must be token-aware: collapse
    // whitespace, strip surrounding quotes from tokens, compare token
    // sequences (pattern tokens must prefix command tokens).

    #[test]
    fn test_c3_double_space_still_matches() {
        // "git  push  --force" (double spaces) is the SAME command as
        // "git push --force" and MUST still match the deny pattern.
        assert!(command_matches_pattern(
            "git  push  --force",
            "git push --force"
        ));
    }

    #[test]
    fn test_c3_trailing_double_space_still_matches() {
        assert!(command_matches_pattern(
            "git push  --force",
            "git push --force"
        ));
    }

    #[test]
    fn test_c3_quoted_token_still_matches() {
        // 'git "push" --force' is the same command — quoting an argument
        // must not let it slip past the deny rule.
        assert!(command_matches_pattern(
            r#"git "push" --force"#,
            "git push --force"
        ));
    }

    #[test]
    fn test_c3_positive_control_exact_still_matches() {
        // Positive control: an unaltered command must still match.
        assert!(command_matches_pattern(
            "git push --force",
            "git push --force"
        ));
    }

    #[test]
    fn test_c3_positive_control_different_command_no_match() {
        // Positive control: a genuinely different command must NOT match.
        assert!(!command_matches_pattern("git status", "git push --force"));
    }

    #[test]
    fn test_c3_no_partial_token_match() {
        // "--forceful" must not match the "--force" token (token, not byte).
        assert!(!command_matches_pattern(
            "git push --forceful",
            "git push --force"
        ));
    }

    #[test]
    fn test_c3_deny_double_space_denied() {
        let deny = vec!["git push --force".to_string()];
        for cmd in &[
            "git  push  --force",
            "git push  --force",
            r#"git "push" --force"#,
            "git push --force",
        ] {
            assert_eq!(
                check_command_with_rules(cmd, &deny, &[], &[]),
                PermissionVerdict::Deny,
                "C3 bypass shape must be DENIED: {cmd}"
            );
        }
        // Positive control: a benign command is not denied.
        assert_eq!(
            check_command_with_rules("git status", &deny, &[], &[]),
            PermissionVerdict::Default,
            "git status must not be denied"
        );
    }

    // --- SEC-C2: substitution-aware decomposition ---
    // Command substitution ($(...), backtick, <(...)/>(...)) hid an inner
    // command from the permission stack. The inner command must now be
    // evaluated against the rules too.

    #[test]
    fn test_c2_dollar_paren_substitution_denied() {
        let deny = vec!["rm -rf".to_string()];
        assert_ne!(
            check_command_with_rules("echo $(rm -rf /x)", &deny, &[], &[]),
            PermissionVerdict::Allow,
            "$(...) substitution must not reach Allow"
        );
        assert_eq!(
            check_command_with_rules("echo $(rm -rf /x)", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_c2_backtick_substitution_denied() {
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("echo `rm -rf /x`", &deny, &[], &[]),
            PermissionVerdict::Deny,
            "backtick substitution must be decomposed and denied"
        );
    }

    #[test]
    fn test_c2_process_substitution_denied() {
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("cat <(rm -rf /x)", &deny, &[], &[]),
            PermissionVerdict::Deny,
            "<(...) process substitution must be decomposed and denied"
        );
        assert_eq!(
            check_command_with_rules("cat >(rm -rf /x)", &deny, &[], &[]),
            PermissionVerdict::Deny,
            ">(...) process substitution must be decomposed and denied"
        );
    }

    #[test]
    fn test_c2_nested_substitution_denied() {
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("echo $(echo $(rm -rf /x))", &deny, &[], &[]),
            PermissionVerdict::Deny,
            "nested substitution must be decomposed and denied"
        );
    }

    #[test]
    fn test_c2_positive_control_benign_substitution() {
        // A substitution with a benign inner command must NOT be denied.
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("echo hello", &deny, &[], &[]),
            PermissionVerdict::Default,
            "benign command stays Default"
        );
        assert_eq!(
            check_command_with_rules("echo $(date)", &deny, &[], &[]),
            PermissionVerdict::Default,
            "benign substitution stays Default — no over-blocking"
        );
    }

    #[test]
    fn test_c2_malformed_substitution_inner_still_denied() {
        // Unbalanced `$(` — the recovered inner command must still hit deny.
        let deny = vec!["rm -rf".to_string()];
        assert_eq!(
            check_command_with_rules("echo $(rm -rf /x", &deny, &[], &[]),
            PermissionVerdict::Deny,
            "malformed substitution must not hide an inner deny"
        );
    }

    #[test]
    fn test_c2_malformed_substitution_fails_closed_off_allow() {
        // A benign-looking malformed substitution must NOT reach Allow:
        // the fail-closed sentinel demotes the chain to Default.
        let allow = vec!["echo *".to_string()];
        assert_eq!(
            check_command_with_rules("echo $(date", &[], &[], &allow),
            PermissionVerdict::Default,
            "un-parsable substitution must never auto-Allow"
        );
    }

    #[test]
    fn test_c2_benign_substitution_still_allowed() {
        // Substitution decomposition must not break a legitimate Allow.
        let allow = vec!["echo *".to_string(), "date".to_string()];
        assert_eq!(
            check_command_with_rules("echo $(date)", &[], &[], &allow),
            PermissionVerdict::Allow,
            "all segments allowed → Allow even with substitution"
        );
    }
}
