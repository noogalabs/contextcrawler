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
use std::time::Duration;

use crate::core::stream::exec_capture_short;

/// Wall-clock budget for tirith subprocess calls from `rtk security`.
/// Matches the 8s cap the gate uses in src/hooks/tirith_gate.rs — the
/// dashboard poll path shares the same hung-tirith failure mode the gate
/// hardening exists to fix. See docs/security/AUDIT-subprocess-timeouts.md
/// finding F-06: the v0.1.6 overnight summary claimed this was already
/// hardened, but `Command::new(bin).output()` was still in place.
const TIRITH_QUERY_TIMEOUT: Duration = Duration::from_secs(8);

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

/// Show the Tirith integration dashboard. Entry point for `contextcrawler security`.
pub fn run_dashboard(format: &str, _verbose: u8) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Unified gate-activity log: merges Tirith downgrades and supply-chain events
// from two JSONL files into one timestamped stream.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum LogEvent {
    Tirith {
        ts: String,
        reason: String,
        cmd: String,
        findings: Vec<(String, String, String)>, // (severity, rule_id, title)
    },
    SupplyChain {
        ts: String,
        verdict: String,
        cmd: String,
        findings: Vec<SupplyChainFinding>,
    },
}

#[derive(Debug)]
struct SupplyChainFinding {
    package: String,
    ecosystem: String,
    severity: String,
    detail: String,
}

impl LogEvent {
    fn timestamp(&self) -> &str {
        match self {
            LogEvent::Tirith { ts, .. } => ts,
            LogEvent::SupplyChain { ts, .. } => ts,
        }
    }
}

/// Entry point for `contextcrawler security log`.
pub fn run_log(format: &str, limit: usize, histogram: bool, _verbose: u8) -> Result<()> {
    let dir = dirs::data_local_dir()
        .map(|d| d.join("contextcrawler"))
        .ok_or_else(|| anyhow::anyhow!("could not resolve data_local_dir"))?;

    let tirith_path = dir.join("downgrades.jsonl");
    let sc_path = dir.join("supply_chain.jsonl");

    let mut events: Vec<LogEvent> = Vec::new();

    if let Ok(content) = std::fs::read_to_string(&tirith_path) {
        for line in content.lines() {
            if let Some(ev) = parse_tirith_line(line) {
                events.push(ev);
            }
        }
    }
    if let Ok(content) = std::fs::read_to_string(&sc_path) {
        for line in content.lines() {
            if let Some(ev) = parse_supply_chain_line(line) {
                events.push(ev);
            }
        }
    }

    // Sort by timestamp ascending (oldest first), then take the tail.
    events.sort_by(|a, b| a.timestamp().cmp(b.timestamp()));
    let total = events.len();

    if histogram {
        let buckets = bucket_events(&events);
        match format {
            "json" => render_histogram_json(&dir, total, &buckets),
            _ => render_histogram_human(&dir, total, &buckets),
        }
        return Ok(());
    }

    let start = total.saturating_sub(limit);
    let tail = &events[start..];

    match format {
        "json" => render_log_json(&dir, total, tail),
        _ => render_log_human(&dir, total, tail),
    }
    Ok(())
}

/// Group events by (source, category) where category is the Tirith reason or
/// the supply-chain verdict. Returns buckets sorted by count descending.
fn bucket_events(events: &[LogEvent]) -> Vec<(&'static str, String, usize)> {
    use std::collections::HashMap;
    let mut counts: HashMap<(&'static str, String), usize> = HashMap::new();
    for ev in events {
        match ev {
            LogEvent::Tirith { reason, .. } => {
                *counts.entry(("tirith", reason.clone())).or_insert(0) += 1;
            }
            LogEvent::SupplyChain { verdict, .. } => {
                *counts
                    .entry(("supply-chain", verdict.to_lowercase()))
                    .or_insert(0) += 1;
            }
        }
    }
    let mut buckets: Vec<(&'static str, String, usize)> = counts
        .into_iter()
        .map(|((src, cat), n)| (src, cat, n))
        .collect();
    buckets.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)).then(a.1.cmp(&b.1)));
    buckets
}

fn render_histogram_human(
    dir: &std::path::Path,
    total: usize,
    buckets: &[(&'static str, String, usize)],
) {
    println!("ContextCrawler Gate Activity — Histogram");
    println!("{}", "═".repeat(60));
    println!("  Sources:");
    println!("    {}", dir.join("downgrades.jsonl").display());
    println!("    {}", dir.join("supply_chain.jsonl").display());
    println!("  Total events: {}", total);
    println!();
    if buckets.is_empty() {
        println!("  No gate activity yet. Enable the gates and run a few commands.");
        return;
    }
    let max = buckets.iter().map(|b| b.2).max().unwrap_or(1);
    // Bar width: scale longest bucket to 24 cells.
    let bar_max = 24usize;
    for (src, cat, n) in buckets {
        let cells = ((*n as f64) / (max as f64) * (bar_max as f64)).round() as usize;
        let bar = "█".repeat(cells.max(1));
        println!("  {:<13} {:<30} {:>5}  {}", src, cat, n, bar);
    }
    println!();
    println!("  Auto-allow decisions are not logged — only gate downgrades and");
    println!("  supply-chain verdicts. Use `contextcrawler gain` for total command volume.");
}

fn render_histogram_json(
    dir: &std::path::Path,
    total: usize,
    buckets: &[(&'static str, String, usize)],
) {
    let arr: Vec<serde_json::Value> = buckets
        .iter()
        .map(|(src, cat, n)| {
            serde_json::json!({ "source": src, "category": cat, "count": n })
        })
        .collect();
    let body = serde_json::json!({
        "sources": {
            "tirith": dir.join("downgrades.jsonl").display().to_string(),
            "supply_chain": dir.join("supply_chain.jsonl").display().to_string(),
        },
        "total": total,
        "buckets": arr,
    });
    println!("{}", body);
}

fn parse_tirith_line(line: &str) -> Option<LogEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("ts")?.as_str()?.to_string();
    let reason = v.get("reason")?.as_str()?.to_string();
    let cmd = v.get("cmd")?.as_str()?.to_string();
    let mut findings = Vec::new();
    if let Some(arr) = v.pointer("/tirith/findings").and_then(|x| x.as_array()) {
        for f in arr {
            let sev = f.get("severity").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let rule = f.get("rule_id").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let title = f.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
            findings.push((sev, rule, title));
        }
    }
    Some(LogEvent::Tirith {
        ts,
        reason,
        cmd,
        findings,
    })
}

fn parse_supply_chain_line(line: &str) -> Option<LogEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("ts")?.as_str()?.to_string();
    let verdict = v.get("verdict")?.as_str()?.to_string();
    let cmd = v.get("cmd")?.as_str()?.to_string();
    let mut findings = Vec::new();
    if let Some(arr) = v.get("findings").and_then(|x| x.as_array()) {
        for f in arr {
            let package = f.get("package").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let ecosystem = f.get("ecosystem").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let severity = f
                .get("severity")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_uppercase();
            let detail = if let Some(reason) = f.get("reason") {
                if let Some(kind) = reason.get("kind").and_then(|x| x.as_str()) {
                    match kind {
                        "RecentRelease" => {
                            let age = reason
                                .get("age_days")
                                .and_then(|x| x.as_f64())
                                .unwrap_or(0.0);
                            let cd = reason
                                .get("cooldown_days")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0);
                            let ver = reason
                                .get("version")
                                .and_then(|x| x.as_str())
                                .unwrap_or("?");
                            format!("@{} published {:.2}d ago (cooldown {}d)", ver, age, cd)
                        }
                        "KnownVulnerability" => {
                            let id = reason.get("id").and_then(|x| x.as_str()).unwrap_or("?");
                            let summary = reason
                                .get("summary")
                                .and_then(|x| x.as_str())
                                .unwrap_or("");
                            format!("CVE {} — {}", id, summary)
                        }
                        _ => kind.to_string(),
                    }
                } else {
                    "(unknown reason)".to_string()
                }
            } else {
                "(no reason)".to_string()
            };
            findings.push(SupplyChainFinding {
                package,
                ecosystem,
                severity,
                detail,
            });
        }
    }
    Some(LogEvent::SupplyChain {
        ts,
        verdict,
        cmd,
        findings,
    })
}

fn render_log_human(dir: &std::path::Path, total: usize, tail: &[LogEvent]) {
    println!("ContextCrawler Gate Activity Log");
    println!("{}", "═".repeat(60));
    println!("  Sources:");
    println!("    {}", dir.join("downgrades.jsonl").display());
    println!("    {}", dir.join("supply_chain.jsonl").display());
    println!("  Total events: {}", total);
    println!("  Showing:      last {} (use --limit to change)", tail.len());
    println!();
    if tail.is_empty() {
        println!("  No gate activity yet. Enable the gates and run a few commands.");
        return;
    }
    for ev in tail {
        match ev {
            LogEvent::Tirith {
                ts,
                reason,
                cmd,
                findings,
            } => {
                println!("[{}]  TIRITH  ({})", ts, reason);
                println!("  cmd: {}", truncate(cmd, 100));
                if findings.is_empty() {
                    println!("  (no findings recorded)");
                } else {
                    println!("  findings ({}):", findings.len());
                    for (sev, rule, title) in findings.iter().take(5) {
                        println!("    {:<8} {:<25} — {}", sev, rule, truncate(title, 60));
                    }
                    if findings.len() > 5 {
                        println!("    ... +{} more", findings.len() - 5);
                    }
                }
                println!();
            }
            LogEvent::SupplyChain {
                ts,
                verdict,
                cmd,
                findings,
            } => {
                println!("[{}]  SUPPLY-CHAIN  ({})", ts, verdict.to_uppercase());
                println!("  cmd: {}", truncate(cmd, 100));
                if findings.is_empty() {
                    // Skip/allow events have no findings; just show the verdict.
                } else {
                    println!("  findings ({}):", findings.len());
                    for f in findings.iter().take(8) {
                        println!(
                            "    {:<8} {} [{}]  {}",
                            f.severity,
                            truncate(&f.package, 24),
                            f.ecosystem,
                            truncate(&f.detail, 70)
                        );
                    }
                    if findings.len() > 8 {
                        println!("    ... +{} more", findings.len() - 8);
                    }
                }
                println!();
            }
        }
    }
}

fn render_log_json(dir: &std::path::Path, total: usize, tail: &[LogEvent]) {
    let arr: Vec<serde_json::Value> = tail
        .iter()
        .map(|ev| match ev {
            LogEvent::Tirith {
                ts,
                reason,
                cmd,
                findings,
            } => {
                serde_json::json!({
                    "source": "tirith",
                    "ts": ts,
                    "reason": reason,
                    "cmd": cmd,
                    "findings": findings.iter().map(|(s, r, t)| serde_json::json!({
                        "severity": s,
                        "rule_id": r,
                        "title": t,
                    })).collect::<Vec<_>>(),
                })
            }
            LogEvent::SupplyChain {
                ts,
                verdict,
                cmd,
                findings,
            } => {
                serde_json::json!({
                    "source": "supply-chain",
                    "ts": ts,
                    "verdict": verdict,
                    "cmd": cmd,
                    "findings": findings.iter().map(|f| serde_json::json!({
                        "severity": f.severity,
                        "package": f.package,
                        "ecosystem": f.ecosystem,
                        "detail": f.detail,
                    })).collect::<Vec<_>>(),
                })
            }
        })
        .collect();
    let body = serde_json::json!({
        "sources": {
            "tirith": dir.join("downgrades.jsonl").display().to_string(),
            "supply_chain": dir.join("supply_chain.jsonl").display().to_string(),
        },
        "total": total,
        "showing": tail.len(),
        "events": arr,
    });
    println!("{}", body);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
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
    let mut cmd = Command::new(bin);
    cmd.args(["audit", "stats", "--format", "json"]);
    let result = exec_capture_short(&mut cmd, TIRITH_QUERY_TIMEOUT).ok()?;
    if !result.success() {
        return None;
    }
    serde_json::from_str(&result.stdout).ok()
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
    let mut cmd = Command::new(bin);
    cmd.arg("doctor");
    let result = match exec_capture_short(&mut cmd, TIRITH_QUERY_TIMEOUT) {
        Ok(r) => r,
        Err(_) => return s,
    };
    s.raw = result.stdout.clone();
    for line in result.stdout.lines() {
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
    println!();
    println!("  ContextCrawler calls tirith as a subprocess from the agent path,");
    println!("  so the binary on PATH is all the gate needs — no shell hook required.");
    println!();
    println!("  Set CONTEXTCRAWLER_TIRITH_REQUIRED=1 to fail-closed when Tirith");
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
        std::env::var("CONTEXTCRAWLER_TIRITH_REQUIRED").as_deref() == Ok("1"),
        std::env::var("CONTEXTCRAWLER_TIRITH_DISABLED").as_deref() == Ok("1"),
    ) {
        (_, true) => "DISABLED (CONTEXTCRAWLER_TIRITH_DISABLED=1)",
        (true, false) => "fail-closed (CONTEXTCRAWLER_TIRITH_REQUIRED=1)",
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
            "required": std::env::var("CONTEXTCRAWLER_TIRITH_REQUIRED").as_deref() == Ok("1"),
            "disabled": std::env::var("CONTEXTCRAWLER_TIRITH_DISABLED").as_deref() == Ok("1"),
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
