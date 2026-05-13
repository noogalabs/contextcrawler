// SPDX-License-Identifier: MIT
// Part of the ContextCrawler downstream of rtk-ai/rtk.
// Copyright (c) 2026 ContextCrawler contributors.
//
//! `rtk security` — surfaces Tirith audit data and gate status.
//!
//! Subprocess-calls `tirith` for the underlying data. AGPL boundary is clean:
//! we invoke a separate process and parse its stdout JSON. No statically
//! linked AGPL code.
//!
//! Phase 1: read-only reporting. Future iterations can add per-session
//! breakdowns, downgrade-event tracking (commands where rtk's auto-allow was
//! downgraded by Tirith), and cross-tool correlation with `rtk gain`.

use anyhow::Result;
use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct AuditStats {
    total_commands: u64,
    total_findings: u64,
    actions: AuditActions,
    top_rules: Vec<(String, u64)>,
}

#[derive(Debug, Deserialize, Default)]
struct AuditActions {
    #[serde(default, rename = "Block")]
    block: u64,
    #[serde(default, rename = "Warn")]
    warn: u64,
    #[serde(default, rename = "Allow")]
    allow: u64,
}

pub fn run(format: &str, _verbose: u8) -> Result<()> {
    let tirith_bin = resolve_tirith_bin();

    match (tirith_bin.as_deref(), format) {
        (None, "json") => {
            println!(r#"{{"tirith_installed": false}}"#);
            return Ok(());
        }
        (None, _) => {
            print_tirith_missing();
            return Ok(());
        }
        _ => {}
    }

    let bin = tirith_bin.unwrap();
    let stats = fetch_audit_stats(&bin);
    let doctor = fetch_doctor_status(&bin);

    match format {
        "json" => print_json(&bin, &stats, &doctor),
        _ => print_human(&bin, &stats, &doctor),
    }

    Ok(())
}

fn resolve_tirith_bin() -> Option<String> {
    if which::which("tirith").is_ok() {
        return Some("tirith".to_string());
    }
    let home = dirs::home_dir()?;
    let cargo_bin = home.join(".cargo/bin/tirith");
    if cargo_bin.exists() {
        return Some(cargo_bin.to_string_lossy().to_string());
    }
    None
}

fn fetch_audit_stats(bin: &str) -> Option<AuditStats> {
    let output = Command::new(bin)
        .args(["audit", "stats", "--format", "json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

#[derive(Default)]
struct DoctorStatus {
    version: Option<String>,
    hook_configured: bool,
    shell: Option<String>,
    raw: String,
}

fn fetch_doctor_status(bin: &str) -> DoctorStatus {
    let mut s = DoctorStatus::default();
    let output = match Command::new(bin).arg("doctor").output() {
        Ok(o) => o,
        Err(_) => return s,
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    s.raw = stdout.clone();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("tirith ") {
            s.version = Some(rest.split_whitespace().next().unwrap_or(rest).to_string());
        } else if let Some(rest) = line.strip_prefix("shell:") {
            s.shell = Some(rest.trim().to_string());
        } else if line.starts_with("hook status:") {
            s.hook_configured = line.contains("CONFIGURED") && !line.contains("NOT CONFIGURED");
        }
    }
    s
}

fn print_tirith_missing() {
    println!("ContextCrawler Security (Tirith Integration)");
    println!("{}", "═".repeat(60));
    println!();
    println!("  Tirith is not installed.");
    println!();
    println!("  ContextCrawler's auto-allow gate falls open when Tirith is");
    println!("  unavailable. Install for defense-in-depth:");
    println!();
    println!("    cargo install tirith");
    println!("    eval \"$(tirith init --shell zsh)\"   # or bash/fish");
    println!();
    println!("  Set CONTEXTZIP_TIRITH_REQUIRED=1 to fail-closed when Tirith");
    println!("  is missing (refuses auto-allow without a verdict).");
}

fn print_human(bin: &str, stats: &Option<AuditStats>, doctor: &DoctorStatus) {
    println!("ContextCrawler Security (Tirith Integration)");
    println!("{}", "═".repeat(60));
    println!();
    println!(
        "  Tirith binary: {} ({})",
        bin,
        doctor.version.as_deref().unwrap_or("version unknown")
    );
    if let Some(shell) = &doctor.shell {
        println!("  Shell:         {}", shell);
    }
    println!(
        "  Shell hook:    {}",
        if doctor.hook_configured {
            "configured ✓"
        } else {
            "NOT configured (commands NOT intercepted at the shell)"
        }
    );

    let gate_state = match (
        std::env::var("CONTEXTZIP_TIRITH_REQUIRED").as_deref() == Ok("1"),
        std::env::var("CONTEXTZIP_TIRITH_DISABLED").as_deref() == Ok("1"),
    ) {
        (_, true) => "DISABLED (CONTEXTZIP_TIRITH_DISABLED=1)",
        (true, false) => "fail-closed (CONTEXTZIP_TIRITH_REQUIRED=1)",
        (false, false) => "fail-open (default)",
    };
    println!("  Rewrite gate:  {}", gate_state);

    println!();

    match stats {
        Some(s) => {
            let total: u64 = s.actions.allow + s.actions.warn + s.actions.block;
            let block_pct = if total > 0 {
                (s.actions.block as f64) / (total as f64) * 100.0
            } else {
                0.0
            };
            println!("Audit Log Summary");
            println!("{}", "─".repeat(60));
            println!("  Commands analyzed: {}", s.total_commands);
            println!("  Findings:          {}", s.total_findings);
            println!(
                "  Action breakdown:  Allow {} | Warn {} | Block {} ({:.1}% block rate)",
                s.actions.allow, s.actions.warn, s.actions.block, block_pct
            );
            if !s.top_rules.is_empty() {
                println!();
                println!("Top detection rules:");
                for (rule, count) in s.top_rules.iter().take(10) {
                    println!("  {:>5}  {}", count, rule);
                }
            }
        }
        None => {
            println!("Audit log: empty or unavailable.");
            println!(
                "Run shell-hook-intercepted commands or `tirith check -- '<cmd>'` to populate."
            );
        }
    }
}

fn print_json(bin: &str, stats: &Option<AuditStats>, doctor: &DoctorStatus) {
    use serde_json::json;
    let body = json!({
        "tirith_installed": true,
        "tirith_bin": bin,
        "tirith_version": doctor.version,
        "hook_configured": doctor.hook_configured,
        "shell": doctor.shell,
        "rewrite_gate": {
            "required": std::env::var("CONTEXTZIP_TIRITH_REQUIRED").as_deref() == Ok("1"),
            "disabled": std::env::var("CONTEXTZIP_TIRITH_DISABLED").as_deref() == Ok("1"),
        },
        "audit_stats": stats.as_ref().map(|s| json!({
            "total_commands": s.total_commands,
            "total_findings": s.total_findings,
            "actions": {
                "allow": s.actions.allow,
                "warn": s.actions.warn,
                "block": s.actions.block,
            },
            "top_rules": s.top_rules,
        })),
    });
    println!("{}", body);
}
