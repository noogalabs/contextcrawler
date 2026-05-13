//! Translates a raw shell command into its RTK-optimized equivalent.

use super::permissions::{check_command, PermissionVerdict};
use crate::discover::registry;
use std::io::Write;

// ===== contextzip-downstream: Tirith pre-execution gate begin =====
// When an Allow verdict would otherwise auto-approve a rewrite, consult
// `tirith check --format json` first. Block-level findings downgrade the
// verdict to Ask so the user reviews the command. Default fail-open if
// Tirith is missing or errors; set CONTEXTZIP_TIRITH_REQUIRED=1 for
// fail-closed (refuses auto-allow without a working Tirith verdict).
//
// Subprocess-call only; no statically-linked AGPL code.
mod tirith_gate {
    use std::process::Command;

    pub enum Verdict {
        Allow,
        Block,
        // Tirith missing, errored, or returned an unrecognized verdict.
        // Caller decides fail-open (proceed) vs fail-closed (downgrade).
        Unavailable,
    }

    pub fn check(cmd: &str) -> Verdict {
        // Soft opt-out for debugging.
        if std::env::var("CONTEXTZIP_TIRITH_DISABLED").as_deref() == Ok("1") {
            return Verdict::Unavailable;
        }

        // Try `tirith` from $PATH; fall back to ~/.cargo/bin/tirith.
        let bin = if which::which("tirith").is_ok() {
            "tirith".to_string()
        } else {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Verdict::Unavailable,
            };
            let cargo_bin = home.join(".cargo/bin/tirith");
            if !cargo_bin.exists() {
                return Verdict::Unavailable;
            }
            cargo_bin.to_string_lossy().to_string()
        };

        // Tirith puts the verdict in stdout JSON; exit code is 0 even on block.
        let output = Command::new(&bin)
            .args([
                "check",
                "--format",
                "json",
                "--non-interactive",
                "--no-daemon",
                "--",
            ])
            .arg(cmd)
            .output();

        let output = match output {
            Ok(o) => o,
            Err(_) => return Verdict::Unavailable,
        };
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Cheap parse: avoid pulling serde_json into the hot rewrite path.
        if stdout.contains("\"action\":\"block\"") {
            Verdict::Block
        } else if stdout.contains("\"action\":\"allow\"") {
            Verdict::Allow
        } else {
            Verdict::Unavailable
        }
    }

    pub fn require_tirith() -> bool {
        std::env::var("CONTEXTZIP_TIRITH_REQUIRED").as_deref() == Ok("1")
    }
}
// ===== contextzip-downstream: Tirith pre-execution gate end =====

/// Run the `rtk rewrite` command.
///
/// Prints the RTK-rewritten command to stdout and exits with a code that tells
/// the caller how to handle permissions:
///
/// | Exit | Stdout   | Meaning                                                      |
/// |------|----------|--------------------------------------------------------------|
/// | 0    | rewritten| Rewrite allowed — hook may auto-allow the rewritten command. |
/// | 1    | (none)   | No RTK equivalent — hook passes through unchanged.           |
/// | 2    | (none)   | Deny rule matched — hook defers to Claude Code native deny.  |
/// | 3    | rewritten| Ask rule matched — hook rewrites but lets Claude Code prompt.|
pub fn run(cmd: &str) -> anyhow::Result<()> {
    let excluded = crate::core::config::Config::load()
        .map(|c| c.hooks.exclude_commands)
        .unwrap_or_default();

    // SECURITY: check deny/ask BEFORE rewrite so non-RTK commands are also covered.
    let verdict = check_command(cmd);

    if verdict == PermissionVerdict::Deny {
        std::process::exit(2);
    }

    match registry::rewrite_command(cmd, &excluded) {
        Some(rewritten) => match verdict {
            PermissionVerdict::Allow => {
                // ===== contextzip-downstream: Tirith gate fires here =====
                // Downgrade an auto-approve verdict to Ask when Tirith
                // flags the command. Closes the prompt-injection-driven
                // auto-allow bypass when defense-in-depth is installed.
                let tirith_verdict = tirith_gate::check(cmd);
                let downgrade = matches!(tirith_verdict, tirith_gate::Verdict::Block)
                    || (matches!(tirith_verdict, tirith_gate::Verdict::Unavailable)
                        && tirith_gate::require_tirith());
                if downgrade {
                    if matches!(tirith_verdict, tirith_gate::Verdict::Block) {
                        eprintln!(
                            "[contextzip] Tirith flagged the command; downgrading auto-allow to Ask."
                        );
                    } else {
                        eprintln!(
                            "[contextzip] Tirith required but unavailable; downgrading auto-allow to Ask."
                        );
                    }
                    print!("{}", rewritten);
                    let _ = std::io::stdout().flush();
                    std::process::exit(3);
                }
                // ===== contextzip-downstream: end Tirith gate =====
                print!("{}", rewritten);
                let _ = std::io::stdout().flush();
                Ok(())
            }
            PermissionVerdict::Ask | PermissionVerdict::Default => {
                print!("{}", rewritten);
                let _ = std::io::stdout().flush();
                std::process::exit(3);
            }
            PermissionVerdict::Deny => unreachable!(),
        },
        None => {
            // No RTK equivalent. Exit 1 = passthrough.
            // Claude Code independently evaluates its own ask rules on the original cmd.
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_supported_command_succeeds() {
        assert!(registry::rewrite_command("git status", &[]).is_some());
    }

    #[test]
    fn test_run_unsupported_returns_none() {
        assert!(registry::rewrite_command("htop", &[]).is_none());
    }

    #[test]
    fn test_run_already_rtk_returns_some() {
        assert_eq!(
            registry::rewrite_command("rtk git status", &[]),
            Some("rtk git status".into())
        );
    }

    /// SECURITY: Verify the exit code protocol for permission verdicts.
    ///
    /// The bash hook (.claude/hooks/rtk-rewrite.sh) interprets exit codes as:
    ///   0 → auto-allow (sets permissionDecision: "allow")
    ///   1 → passthrough (no RTK equivalent)
    ///   2 → deny (let Claude Code handle natively)
    ///   3 → ask (rewrite but omit permissionDecision, forcing user prompt)
    ///
    /// CRITICAL: PermissionVerdict::Default MUST map to exit 3 (ask), NOT exit 0.
    /// If Default were mapped to exit 0, any command without an explicit permission
    /// rule would be auto-allowed — bypassing Claude Code's least-privilege default.
    /// See: https://github.com/rtk-ai/rtk/issues/1155
    mod exit_code_protocol {
        use super::registry;
        use crate::hooks::permissions::{check_command_with_rules, PermissionVerdict};

        /// Exit code that `run()` returns for each verdict:
        ///   Allow  → 0 (exit Ok(()))
        ///   Ask    → 3 (process::exit(3))
        ///   Default→ 3 (process::exit(3)) — grouped with Ask
        ///   Deny   → 2 (process::exit(2)) — handled before rewrite match
        fn expected_exit_code(verdict: &PermissionVerdict) -> i32 {
            match verdict {
                PermissionVerdict::Allow => 0,
                PermissionVerdict::Deny => 2,
                PermissionVerdict::Ask => 3,
                PermissionVerdict::Default => 3, // MUST be 3, not 0!
            }
        }

        #[test]
        fn test_default_verdict_maps_to_ask_exit_code() {
            // When no rules match, verdict is Default → exit code must be 3 (ask).
            let verdict = check_command_with_rules("git status", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Default);
            assert_eq!(
                expected_exit_code(&verdict),
                3,
                "Default verdict MUST exit with code 3 (ask), not 0 (allow)"
            );
        }

        #[test]
        fn test_allow_verdict_maps_to_allow_exit_code() {
            let allow = vec!["git *".to_string()];
            let verdict = check_command_with_rules("git status", &[], &[], &allow);
            assert_eq!(verdict, PermissionVerdict::Allow);
            assert_eq!(expected_exit_code(&verdict), 0);
        }

        #[test]
        fn test_ask_verdict_maps_to_ask_exit_code() {
            let ask = vec!["git push".to_string()];
            let verdict = check_command_with_rules("git push origin main", &[], &ask, &[]);
            assert_eq!(verdict, PermissionVerdict::Ask);
            assert_eq!(expected_exit_code(&verdict), 3);
        }

        #[test]
        fn test_deny_verdict_maps_to_deny_exit_code() {
            let deny = vec!["rm -rf".to_string()];
            let verdict = check_command_with_rules("rm -rf /tmp/test", &deny, &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Deny);
            assert_eq!(expected_exit_code(&verdict), 2);
        }

        #[test]
        fn test_no_auto_allow_bypass_for_unrecognized_commands() {
            // SECURITY: A command with no permission rules and no matching allow rule
            // must NOT be auto-allowed. This is the core of issue #1155.
            // Even though `git status` can be rewritten to `rtk git status`,
            // the absence of an allow rule means Default → exit 3 → ask.
            let verdict = check_command_with_rules("git status", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Default);

            // Verify the rewrite exists (so the hook would output it),
            // but the exit code forces user confirmation.
            assert!(registry::rewrite_command("git status", &[]).is_some());
            assert_eq!(expected_exit_code(&verdict), 3);
        }

        #[test]
        fn test_default_never_equals_allow() {
            // Sentinel: ensure Default and Allow are distinct enum variants.
            // If this ever fails, the entire permission model is broken.
            assert_ne!(PermissionVerdict::Default, PermissionVerdict::Allow);
        }
    }
}
