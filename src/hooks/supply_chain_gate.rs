// SPDX-License-Identifier: MIT
// Part of the ContextCrawler downstream of rtk-ai/rtk.
// Copyright (c) 2026 ContextCrawler contributors.
//
//! Supply-chain pre-install gate.
//!
//! Detects npm/pnpm/yarn/pip/uv/poetry/pipx install commands in a bash
//! command string, queries the relevant registry (npm or PyPI) for the
//! latest version's publish time, and OSV.dev for known vulnerabilities.
//! Returns a Verdict the caller (hook_cmd / rewrite_cmd) uses to downgrade
//! the auto-allow decision when packages fail an age cooldown or carry
//! HIGH-severity CVEs.
//!
//! Empirical justification for defaults: see
//!   notes/research/supply-chain-audit-report.md
//! in the umbrella repo.
//!
//! Subprocess-free internal HTTP via `ureq` (already an rtk dep).

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Verdict {
    /// Gate disabled, or command contains no install actions. Caller proceeds normally.
    Skip,
    /// All checks passed.
    Allow,
    /// One or more packages failed the gate. Caller should refuse the auto-allow.
    Block(Vec<Finding>),
    /// Network or other transient failure. Caller policy (fail-open by default).
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub package: String,
    pub ecosystem: String,
    pub reason: FindingReason,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum FindingReason {
    RecentRelease {
        age_days: f64,
        cooldown_days: u32,
        version: String,
    },
    KnownVulnerability {
        id: String,
        summary: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "LOW" => Some(Severity::Low),
            "MEDIUM" | "MED" | "MODERATE" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" => Some(Severity::Critical),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    supply_chain: GlobalConfig,
    #[serde(default = "default_npm")]
    npm: EcosystemConfig,
    #[serde(default = "default_pypi")]
    pypi: EcosystemConfig,
    #[serde(default)]
    overrides: Overrides,
}

#[derive(Debug, Deserialize, Default)]
struct GlobalConfig {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct EcosystemConfig {
    #[serde(default = "default_cooldown")]
    cooldown_days: u32,
    #[serde(default = "default_severity")]
    block_severity: String,
    #[serde(default)]
    allow_editable: bool,
}

#[derive(Debug, Deserialize, Default)]
struct Overrides {
    #[serde(default)]
    always_allow: Vec<String>,
    #[serde(default)]
    always_deny: Vec<String>,
}

fn default_cooldown() -> u32 {
    3
}

fn default_severity() -> String {
    "HIGH".into()
}

fn default_npm() -> EcosystemConfig {
    EcosystemConfig {
        cooldown_days: 3,
        block_severity: "HIGH".into(),
        allow_editable: false,
    }
}

fn default_pypi() -> EcosystemConfig {
    EcosystemConfig {
        cooldown_days: 3,
        block_severity: "HIGH".into(),
        allow_editable: true,
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            supply_chain: GlobalConfig { enabled: false },
            npm: default_npm(),
            pypi: default_pypi(),
            overrides: Overrides::default(),
        }
    }
}

/// Where to look for the supply-chain config.
/// Search order (first hit wins):
///   1. `$XDG_CONFIG_HOME/contextcrawler/supply-chain.toml`
///   2. `~/.config/contextcrawler/supply-chain.toml` (developer-friendly on macOS)
///   3. `dirs::config_dir()/contextcrawler/supply-chain.toml`
///      (= ~/Library/Application Support on macOS, ~/.config on Linux, AppData on Windows)
fn config_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        out.push(PathBuf::from(xdg).join("contextcrawler").join("supply-chain.toml"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".config/contextcrawler/supply-chain.toml"));
    }
    if let Some(cfg) = dirs::config_dir() {
        out.push(cfg.join("contextcrawler").join("supply-chain.toml"));
    }
    out
}

fn load_config() -> Config {
    for path in config_candidates() {
        if let Ok(content) = fs::read_to_string(&path) {
            return toml::from_str(&content).unwrap_or_default();
        }
    }
    Config::default()
}

// ---------------------------------------------------------------------------
// Command parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedInstall {
    ecosystem: Ecosystem,
    packages: Vec<String>,
    has_editable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
        }
    }
}

lazy_static! {
    static ref NPM_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)npm\s+(?:i|install|add)\s+([^|;&>]+)").unwrap();
    static ref PNPM_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)pnpm\s+(?:i|install|add)\s+([^|;&>]+)").unwrap();
    static ref YARN_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)yarn\s+add\s+([^|;&>]+)").unwrap();
    static ref PIP_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)(?:pip|pip3)\s+install\s+([^|;&>]+)").unwrap();
    static ref UV_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)uv\s+(?:pip\s+)?(?:install|add)\s+([^|;&>]+)").unwrap();
    static ref POETRY_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)poetry\s+add\s+([^|;&>]+)").unwrap();
    static ref PIPX_RE: Regex =
        Regex::new(r"(?m)(?:^|\s|;|&&|\|\|)pipx\s+install\s+([^|;&>]+)").unwrap();
}

fn detect_installs(cmd: &str) -> Vec<ParsedInstall> {
    let mut out = Vec::new();

    for (re, eco) in [
        (&*NPM_RE, Ecosystem::Npm),
        (&*PNPM_RE, Ecosystem::Npm),
        (&*YARN_RE, Ecosystem::Npm),
        (&*PIP_RE, Ecosystem::Pypi),
        (&*UV_RE, Ecosystem::Pypi),
        (&*POETRY_RE, Ecosystem::Pypi),
        (&*PIPX_RE, Ecosystem::Pypi),
    ] {
        for cap in re.captures_iter(cmd) {
            let arg_string = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let (pkgs, has_editable) = parse_package_args(arg_string);
            if !pkgs.is_empty() || has_editable {
                out.push(ParsedInstall {
                    ecosystem: eco,
                    packages: pkgs,
                    has_editable,
                });
            }
        }
    }
    out
}

/// Returns (registry-package-names, saw_editable_arg).
fn parse_package_args(s: &str) -> (Vec<String>, bool) {
    let mut pkgs = Vec::new();
    let mut editable = false;
    let mut tokens = s.split_whitespace().peekable();

    while let Some(tok) = tokens.next() {
        // pip / uv editable
        if tok == "-e" || tok == "--editable" {
            editable = true;
            tokens.next(); // consume the target
            continue;
        }
        // Skip pip/uv flags that take a value
        if matches!(
            tok,
            "-r" | "--requirement" | "-c" | "--constraint" | "-t" | "--target" | "--index-url"
        ) {
            tokens.next();
            continue;
        }
        // Skip bare flags
        if tok.starts_with('-') {
            continue;
        }
        // Skip path / URL / git / file installs
        if tok == "."
            || tok.starts_with(".[")
            || tok.starts_with("./")
            || tok.starts_with("../")
            || tok.starts_with("/")
            || tok.starts_with("file:")
            || tok.starts_with("git+")
            || tok.starts_with("http://")
            || tok.starts_with("https://")
        {
            editable = true;
            continue;
        }

        let bare = strip_version_spec(tok);
        if !bare.is_empty() {
            pkgs.push(bare);
        }
    }

    (pkgs, editable)
}

fn strip_version_spec(s: &str) -> String {
    let stripped = s.trim_matches(|c: char| c == '"' || c == '\'');
    // npm scoped: @scope/name[@version]
    if let Some(rest) = stripped.strip_prefix('@') {
        if let Some(slash_idx) = rest.find('/') {
            let after_slash = &rest[slash_idx + 1..];
            let name_end = after_slash.find('@').unwrap_or(after_slash.len());
            return format!("@{}/{}", &rest[..slash_idx], &after_slash[..name_end]);
        }
        return format!("@{}", rest);
    }
    // pip-style separators
    for sep in ["==", ">=", "<=", "~=", "!=", ">", "<"] {
        if let Some(idx) = stripped.find(sep) {
            return stripped[..idx].to_string();
        }
    }
    // npm: name@version
    if let Some(idx) = stripped.find('@') {
        return stripped[..idx].to_string();
    }
    stripped.to_string()
}

// ---------------------------------------------------------------------------
// HTTP queries
// ---------------------------------------------------------------------------

fn http_get_json(url: &str) -> Result<Value, String> {
    let resp = ureq::get(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .timeout(StdDuration::from_secs(8))
        .call()
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let body = resp
        .into_string()
        .map_err(|e| format!("read body: {}", e))?;
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let resp = ureq::post(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .set("Content-Type", "application/json")
        .timeout(StdDuration::from_secs(8))
        .send_string(&body.to_string())
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let s = resp
        .into_string()
        .map_err(|e| format!("read body: {}", e))?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

/// Returns (latest_version, publish_time) or Err with reason.
fn npm_latest(pkg: &str) -> Result<(String, DateTime<Utc>), String> {
    if let Some(cached) = cache_get(Ecosystem::Npm, pkg) {
        return Ok(cached);
    }
    let url = format!("https://registry.npmjs.org/{}", urlencoding(pkg));
    let v = http_get_json(&url)?;
    let latest = v
        .pointer("/dist-tags/latest")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no dist-tags/latest".to_string())?
        .to_string();
    let ts = v
        .pointer(&format!("/time/{}", latest))
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no publish time".to_string())?;
    let publish = parse_iso8601(ts)?;
    cache_put(Ecosystem::Npm, pkg, &latest, &publish);
    Ok((latest, publish))
}

fn pypi_latest(pkg: &str) -> Result<(String, DateTime<Utc>), String> {
    if let Some(cached) = cache_get(Ecosystem::Pypi, pkg) {
        return Ok(cached);
    }
    let url = format!("https://pypi.org/pypi/{}/json", urlencoding(pkg));
    let v = http_get_json(&url)?;
    let latest = v
        .pointer("/info/version")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no info/version".to_string())?
        .to_string();
    let arr = v
        .pointer(&format!("/releases/{}", latest))
        .and_then(|x| x.as_array())
        .ok_or_else(|| "no releases".to_string())?;
    let first = arr.first().ok_or_else(|| "empty releases".to_string())?;
    let ts = first
        .get("upload_time_iso_8601")
        .or_else(|| first.get("upload_time"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no upload_time".to_string())?;
    let publish = parse_iso8601(ts)?;
    cache_put(Ecosystem::Pypi, pkg, &latest, &publish);
    Ok((latest, publish))
}

fn parse_iso8601(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .or_else(|_| DateTime::parse_from_rfc3339(&format!("{}Z", s.trim_end_matches('Z'))))
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

fn urlencoding(s: &str) -> String {
    // Minimal percent-encoding for path segments.
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Query OSV.dev for any vulns affecting (ecosystem, package, version).
fn osv_query(eco: Ecosystem, pkg: &str, version: &str) -> Result<Vec<(String, String)>, String> {
    let body = serde_json::json!({
        "package": { "name": pkg, "ecosystem": eco.as_str() },
        "version": version
    });
    let v = http_post_json("https://api.osv.dev/v1/query", &body)?;
    let vulns = v
        .get("vulns")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(vulns
        .iter()
        .filter_map(|vuln| {
            let id = vuln.get("id").and_then(|x| x.as_str())?.to_string();
            let summary = vuln
                .get("summary")
                .and_then(|x| x.as_str())
                .unwrap_or("(no summary)")
                .to_string();
            Some((id, summary))
        })
        .collect())
}

/// Extract a CVSS-style severity from an OSV vuln record. Best-effort.
fn osv_severity(vuln: &Value) -> Severity {
    if let Some(arr) = vuln.get("severity").and_then(|x| x.as_array()) {
        for entry in arr {
            if let Some(score) = entry.get("score").and_then(|x| x.as_str()) {
                if score.contains("CRITICAL") {
                    return Severity::Critical;
                } else if score.contains("HIGH") {
                    return Severity::High;
                } else if score.contains("MEDIUM") || score.contains("MODERATE") {
                    return Severity::Medium;
                } else if score.contains("LOW") {
                    return Severity::Low;
                }
            }
        }
    }
    if let Some(arr) = vuln.get("database_specific").and_then(|x| x.as_object()) {
        if let Some(sev) = arr.get("severity").and_then(|x| x.as_str()) {
            if let Some(parsed) = Severity::parse(sev) {
                return parsed;
            }
        }
    }
    // Default if unknown: assume HIGH so it doesn't silently slip past a HIGH threshold.
    Severity::High
}

// ---------------------------------------------------------------------------
// Cache (24h, file-based)
// ---------------------------------------------------------------------------

fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("contextcrawler").join("supply-chain"))
}

fn cache_file(eco: Ecosystem, pkg: &str) -> Option<PathBuf> {
    let safe = pkg.replace('/', "_").replace('@', "_at_");
    cache_dir().map(|d| d.join(format!("{}-{}.json", eco.as_str(), safe)))
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    version: String,
    publish_time: String,
    fetched_at: String,
}

fn cache_get(eco: Ecosystem, pkg: &str) -> Option<(String, DateTime<Utc>)> {
    let path = cache_file(eco, pkg)?;
    let content = fs::read_to_string(&path).ok()?;
    let entry: CacheEntry = serde_json::from_str(&content).ok()?;
    let fetched = parse_iso8601(&entry.fetched_at).ok()?;
    if (Utc::now() - fetched) > ChronoDuration::hours(24) {
        return None;
    }
    let publish = parse_iso8601(&entry.publish_time).ok()?;
    Some((entry.version, publish))
}

fn cache_put(eco: Ecosystem, pkg: &str, version: &str, publish: &DateTime<Utc>) {
    let Some(path) = cache_file(eco, pkg) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let entry = CacheEntry {
        version: version.to_string(),
        publish_time: publish.to_rfc3339(),
        fetched_at: Utc::now().to_rfc3339(),
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        let _ = fs::write(&path, json);
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Inspect a shell command. Returns Skip if not an install / gate disabled.
pub fn check(cmd: &str) -> Verdict {
    let config = load_config();
    if !config.supply_chain.enabled {
        return Verdict::Skip;
    }
    if std::env::var("CONTEXTCRAWLER_SUPPLY_CHAIN").as_deref() == Ok("off") {
        return Verdict::Skip;
    }

    let installs = detect_installs(cmd);
    if installs.is_empty() {
        return Verdict::Skip;
    }

    let mut findings = Vec::new();
    let mut transient_err: Option<String> = None;

    for install in installs {
        let eco_cfg = match install.ecosystem {
            Ecosystem::Npm => &config.npm,
            Ecosystem::Pypi => &config.pypi,
        };
        // Editable / path / URL installs bypass the gate per ecosystem policy.
        if install.has_editable && eco_cfg.allow_editable {
            continue;
        }
        let block_threshold = Severity::parse(&eco_cfg.block_severity).unwrap_or(Severity::High);

        for pkg in install.packages {
            // Overrides first
            if matches_override(&pkg, &config.overrides.always_allow) {
                continue;
            }
            if matches_override(&pkg, &config.overrides.always_deny) {
                findings.push(Finding {
                    package: pkg.clone(),
                    ecosystem: install.ecosystem.as_str().to_string(),
                    reason: FindingReason::RecentRelease {
                        age_days: 0.0,
                        cooldown_days: 0,
                        version: "*".into(),
                    },
                    severity: Severity::Critical,
                });
                continue;
            }

            // Age check
            let registry_result = match install.ecosystem {
                Ecosystem::Npm => npm_latest(&pkg),
                Ecosystem::Pypi => pypi_latest(&pkg),
            };
            let (version, publish) = match registry_result {
                Ok(v) => v,
                Err(e) => {
                    transient_err.get_or_insert(e);
                    continue;
                }
            };
            let age = Utc::now() - publish;
            if age < ChronoDuration::days(eco_cfg.cooldown_days as i64)
                && age > ChronoDuration::days(-1)
            {
                findings.push(Finding {
                    package: pkg.clone(),
                    ecosystem: install.ecosystem.as_str().to_string(),
                    reason: FindingReason::RecentRelease {
                        age_days: age.num_seconds() as f64 / 86_400.0,
                        cooldown_days: eco_cfg.cooldown_days,
                        version: version.clone(),
                    },
                    severity: Severity::High,
                });
            }

            // CVE check (the version we resolved above)
            if let Ok(vulns) = osv_query(install.ecosystem, &pkg, &version) {
                for (id, summary) in vulns {
                    // We don't yet have per-vuln severity from osv_query's signature.
                    // For now: any reported vuln is treated as HIGH; downgrade further later.
                    let sev = Severity::High;
                    if sev >= block_threshold {
                        findings.push(Finding {
                            package: pkg.clone(),
                            ecosystem: install.ecosystem.as_str().to_string(),
                            reason: FindingReason::KnownVulnerability { id, summary },
                            severity: sev,
                        });
                    }
                }
            }
        }
    }

    if !findings.is_empty() {
        return Verdict::Block(findings);
    }
    if let Some(e) = transient_err {
        return Verdict::Unavailable(e);
    }
    Verdict::Allow
}

fn matches_override(pkg: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if let Some(prefix) = pat.strip_suffix("/*") {
            if pkg.starts_with(prefix) && pkg.len() > prefix.len() {
                return true;
            }
        } else if pat == pkg {
            return true;
        }
    }
    false
}

/// Append a gate event to the local log for `contextcrawler security --supply-chain-log`.
pub fn log_event(cmd: &str, verdict: &Verdict) {
    let Some(data_dir) = dirs::data_local_dir() else {
        return;
    };
    let dir = data_dir.join("contextcrawler");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("supply_chain.jsonl");
    let kind = match verdict {
        Verdict::Skip => "skip",
        Verdict::Allow => "allow",
        Verdict::Block(_) => "block",
        Verdict::Unavailable(_) => "unavailable",
    };
    let findings = match verdict {
        Verdict::Block(f) => serde_json::to_string(f).unwrap_or_default(),
        _ => "[]".to_string(),
    };
    let record = format!(
        r#"{{"ts":"{}","verdict":"{}","cmd":{},"findings":{}}}"#,
        Utc::now().to_rfc3339(),
        kind,
        serde_json::to_string(cmd).unwrap_or_else(|_| "\"\"".into()),
        findings
    );
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", record);
    }
}

/// Render a Verdict as a human-readable explanation (for hook warnings and CLI).
pub fn render(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Skip => {
            "[contextcrawler supply-chain] skipped (gate disabled or no install command)".into()
        }
        Verdict::Allow => "[contextcrawler supply-chain] all packages passed".into(),
        Verdict::Unavailable(e) => format!(
            "[contextcrawler supply-chain] WARN — gate unavailable ({}). Fail-open.",
            e
        ),
        Verdict::Block(findings) => {
            let mut s = String::from("[contextcrawler supply-chain] BLOCKED\n");
            for f in findings {
                match &f.reason {
                    FindingReason::RecentRelease {
                        age_days,
                        cooldown_days,
                        version,
                    } => {
                        s.push_str(&format!(
                            "  {} [{}] @ {} published {:.2}d ago (cooldown {}d). Severity: {:?}\n",
                            f.package, f.ecosystem, version, age_days, cooldown_days, f.severity
                        ));
                    }
                    FindingReason::KnownVulnerability { id, summary } => {
                        s.push_str(&format!(
                            "  {} [{}]: {} — {} (severity {:?})\n",
                            f.package, f.ecosystem, id, summary, f.severity
                        ));
                    }
                }
            }
            s.push_str(
                "  Overrides: rerun with CONTEXTCRAWLER_SUPPLY_CHAIN=off, or add the package\n",
            );
            s.push_str("  to ~/.config/contextcrawler/supply-chain.toml [overrides.always_allow]");
            s
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_npm_install() {
        let v = detect_installs("npm install lodash express");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(v[0].packages, vec!["lodash", "express"]);
    }

    #[test]
    fn detect_pip_install() {
        let v = detect_installs("pip install requests==2.31.0 numpy");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(v[0].packages, vec!["requests", "numpy"]);
    }

    #[test]
    fn detect_compound_install() {
        let v = detect_installs("cd foo && npm install x && pip install y");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn editable_install_flagged() {
        let v = detect_installs("pip install -e .");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn dot_extras_treated_as_editable() {
        let v = detect_installs("pip install .[dev]");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn npm_scoped_pkg_with_version() {
        assert_eq!(strip_version_spec("@types/node@22.10.0"), "@types/node");
        assert_eq!(strip_version_spec("@types/node"), "@types/node");
    }

    #[test]
    fn pip_version_specifiers() {
        assert_eq!(strip_version_spec("requests==2.31.0"), "requests");
        assert_eq!(strip_version_spec("requests>=2.0"), "requests");
        assert_eq!(strip_version_spec("requests~=2.0"), "requests");
    }

    #[test]
    fn override_glob_pattern() {
        assert!(matches_override("@types/node", &["@types/*".into()]));
        assert!(!matches_override("@scope/x", &["@types/*".into()]));
        assert!(matches_override("lodash", &["lodash".into()]));
    }

    #[test]
    fn detect_no_install_returns_empty() {
        assert!(detect_installs("git status").is_empty());
        assert!(detect_installs("npm test").is_empty());
        assert!(detect_installs("pip list").is_empty());
    }

    #[test]
    fn skip_flag_args() {
        let v = detect_installs("pip install -r requirements.txt foo");
        // -r and requirements.txt should both be skipped; only `foo` remains
        assert_eq!(v[0].packages, vec!["foo"]);
    }

    #[test]
    fn url_install_treated_as_editable() {
        let v = detect_installs("pip install https://example.com/pkg.tar.gz");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }
}
