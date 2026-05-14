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
    /// The install command contained an editable / path / URL token (e.g.
    /// `-e .`, `git+...`, `https://...`) and the ecosystem config does not
    /// allow these to bypass review.
    UnvettableSource {
        token_kind: String,
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
    /// (package_name, optional_pinned_version)
    packages: Vec<(String, Option<String>)>,
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
    // Run UV before PIP so `uv pip install foo` is claimed by the UV pattern
    // and PIP_RE matching the inner `pip install foo` substring is suppressed
    // for that span.
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    let mut out = Vec::new();

    let ordered = [
        (&*UV_RE, Ecosystem::Pypi),
        (&*NPM_RE, Ecosystem::Npm),
        (&*PNPM_RE, Ecosystem::Npm),
        (&*YARN_RE, Ecosystem::Npm),
        (&*PIP_RE, Ecosystem::Pypi),
        (&*POETRY_RE, Ecosystem::Pypi),
        (&*PIPX_RE, Ecosystem::Pypi),
    ];

    for (re, eco) in ordered {
        for m in re.find_iter(cmd) {
            let (start, end) = (m.start(), m.end());
            // Skip if any earlier (higher-priority) pattern already claimed this span.
            if claimed
                .iter()
                .any(|(s, e)| start >= *s && start < *e)
            {
                continue;
            }
            claimed.push((start, end));
            let cap = re.captures_at(cmd, start).unwrap();
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

/// Returns (registry-package-names with optional pinned version, saw_editable_arg).
fn parse_package_args(s: &str) -> (Vec<(String, Option<String>)>, bool) {
    let mut pkgs = Vec::new();
    let mut editable = false;
    let mut tokens = s.split_whitespace().peekable();

    while let Some(tok) = tokens.next() {
        if tok == "-e" || tok == "--editable" {
            editable = true;
            tokens.next();
            continue;
        }
        if matches!(
            tok,
            "-r" | "--requirement" | "-c" | "--constraint" | "-t" | "--target" | "--index-url"
        ) {
            tokens.next();
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
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

        let (name, version) = split_name_version(tok);
        if !name.is_empty() {
            pkgs.push((name, version));
        }
    }

    (pkgs, editable)
}

/// Split a token like `requests==2.20.0`, `@types/node@22.10.0`, or `lodash`
/// into (name, optional pinned version). Only exact pins (`==X`, `name@X`)
/// are returned; ranges like `>=2.0` yield None for the version (we don't
/// pin a range to query).
fn split_name_version(s: &str) -> (String, Option<String>) {
    let stripped = s.trim_matches(|c: char| c == '"' || c == '\'');

    // npm scoped: @scope/name[@version]
    if let Some(rest) = stripped.strip_prefix('@') {
        if let Some(slash_idx) = rest.find('/') {
            let after_slash = &rest[slash_idx + 1..];
            if let Some(at_idx) = after_slash.find('@') {
                let name = format!("@{}/{}", &rest[..slash_idx], &after_slash[..at_idx]);
                let ver = after_slash[at_idx + 1..].to_string();
                let ver = if ver.is_empty() { None } else { Some(ver) };
                return (name, ver);
            }
            return (format!("@{}/{}", &rest[..slash_idx], after_slash), None);
        }
        return (format!("@{}", rest), None);
    }
    // pip exact pin
    if let Some(idx) = stripped.find("==") {
        return (
            stripped[..idx].to_string(),
            Some(stripped[idx + 2..].to_string()),
        );
    }
    // pip range specifiers — drop the spec, leave version None
    for sep in [">=", "<=", "~=", "!=", ">", "<"] {
        if let Some(idx) = stripped.find(sep) {
            return (stripped[..idx].to_string(), None);
        }
    }
    // npm: name@version
    if let Some(idx) = stripped.find('@') {
        return (
            stripped[..idx].to_string(),
            Some(stripped[idx + 1..].to_string()),
        );
    }
    (stripped.to_string(), None)
}

// ---------------------------------------------------------------------------
// HTTP queries
// ---------------------------------------------------------------------------

/// 64 MB cap. npm's `/<pkg>` for popular packages (e.g. `@types/node`) can
/// run ~30 MB. ureq's `into_string()` caps at 10 MB which fails them.
const HTTP_MAX_BYTES: u64 = 64 * 1024 * 1024;

fn read_body(resp: ureq::Response) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(HTTP_MAX_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {}", e))?;
    Ok(buf)
}

fn http_get_json(url: &str) -> Result<Value, String> {
    let resp = ureq::get(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .timeout(StdDuration::from_secs(8))
        .call()
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let buf = read_body(resp)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let resp = ureq::post(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .set("Content-Type", "application/json")
        .timeout(StdDuration::from_secs(8))
        .send_string(&body.to_string())
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let buf = read_body(resp)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// Resolve (version, publish_time) for the package. If `pinned` is Some, use
/// that version; otherwise resolve and use the registry's `latest`.
/// Cache keys include the version so pinned-and-unpinned don't collide.
fn npm_metadata(pkg: &str, pinned: Option<&str>) -> Result<(String, DateTime<Utc>), String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    if let Some(cached) = cache_get(Ecosystem::Npm, &cache_key) {
        return Ok(cached);
    }
    // Always query the full /<pkg> doc since per-version endpoints don't
    // expose publish times.
    let url = format!("https://registry.npmjs.org/{}", urlencoding(pkg));
    let v = http_get_json(&url)?;
    let resolved = match pinned {
        Some(ver) => ver.to_string(),
        None => v
            .pointer("/dist-tags/latest")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "no dist-tags/latest".to_string())?
            .to_string(),
    };
    let ts = v
        .pointer(&format!("/time/{}", resolved))
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("no publish time for version {}", resolved))?;
    let publish = parse_iso8601(ts)?;
    cache_put(Ecosystem::Npm, &cache_key, &resolved, &publish);
    Ok((resolved, publish))
}

fn pypi_metadata(pkg: &str, pinned: Option<&str>) -> Result<(String, DateTime<Utc>), String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    if let Some(cached) = cache_get(Ecosystem::Pypi, &cache_key) {
        return Ok(cached);
    }
    // When pinned, use the version-specific endpoint (smaller response).
    // Otherwise hit the package endpoint to discover `info.version` and the
    // release files.
    if let Some(ver) = pinned {
        let url = format!(
            "https://pypi.org/pypi/{}/{}/json",
            urlencoding(pkg),
            urlencoding(ver)
        );
        let v = http_get_json(&url)?;
        let urls = v
            .get("urls")
            .and_then(|x| x.as_array())
            .ok_or_else(|| "no urls in pypi response".to_string())?;
        let first = urls
            .first()
            .ok_or_else(|| "empty urls list".to_string())?;
        let ts = first
            .get("upload_time_iso_8601")
            .or_else(|| first.get("upload_time"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| "no upload_time".to_string())?;
        let publish = parse_iso8601(ts)?;
        cache_put(Ecosystem::Pypi, &cache_key, ver, &publish);
        return Ok((ver.to_string(), publish));
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
    cache_put(Ecosystem::Pypi, &cache_key, &latest, &publish);
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
/// Returns (id, summary, severity) per vuln so callers can apply a threshold.
fn osv_query(
    eco: Ecosystem,
    pkg: &str,
    version: &str,
) -> Result<Vec<(String, String, Severity)>, String> {
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
            let severity = osv_severity(vuln);
            Some((id, summary, severity))
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
    // Refuse anything that could escape the cache directory or smuggle a
    // path separator the caller didn't anticipate. Real npm/pypi names
    // are an allowlist of [A-Za-z0-9._@/-]; we additionally reject `..`
    // sequences and any backslash. If we can't represent the name
    // safely we skip the cache (worst case: re-query the registry).
    if pkg.is_empty()
        || pkg.contains("..")
        || pkg.contains('\\')
        || pkg
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '*' || c == '?')
    {
        return None;
    }
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
        let block_threshold = Severity::parse(&eco_cfg.block_severity).unwrap_or(Severity::High);

        // Editable / path / URL token detected. If the ecosystem disallows
        // these (default for npm), we can't query a registry for that
        // source — surface a finding so the user reviews manually. Either
        // way we fall through and still vet any sibling named packages
        // (e.g. `pip install -e . requests` must still check `requests`).
        if install.has_editable && !eco_cfg.allow_editable {
            findings.push(Finding {
                package: "<editable / path / url>".to_string(),
                ecosystem: install.ecosystem.as_str().to_string(),
                reason: FindingReason::UnvettableSource {
                    token_kind: "editable_or_url".to_string(),
                },
                severity: Severity::High,
            });
        }

        // Dedupe within an install: pip install foo bar foo -> check foo once.
        let mut seen = std::collections::HashSet::<(String, Option<String>)>::new();
        for (pkg, pinned) in install.packages {
            let key = (pkg.clone(), pinned.clone());
            if !seen.insert(key) {
                continue;
            }

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

            // Age check against (resolved or pinned) version
            let registry_result = match install.ecosystem {
                Ecosystem::Npm => npm_metadata(&pkg, pinned.as_deref()),
                Ecosystem::Pypi => pypi_metadata(&pkg, pinned.as_deref()),
            };
            let (version, publish) = match registry_result {
                Ok(v) => v,
                Err(e) => {
                    transient_err.get_or_insert(e);
                    continue;
                }
            };
            // Clamp negative ages (registry/publisher clock skew, or a
            // genuinely future-dated entry) to zero so they always fall
            // below the cooldown threshold instead of skating past both
            // bounds of the old `> -1d` guard.
            let age = (Utc::now() - publish).max(ChronoDuration::zero());
            if age < ChronoDuration::days(eco_cfg.cooldown_days as i64) {
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

            // CVE check against the specific resolved/pinned version
            if let Ok(vulns) = osv_query(install.ecosystem, &pkg, &version) {
                for (id, summary, sev) in vulns {
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
                    FindingReason::UnvettableSource { token_kind } => {
                        s.push_str(&format!(
                            "  {} [{}]: install command contained an {} token that the gate cannot query (severity {:?})\n",
                            f.package, f.ecosystem, token_kind, f.severity
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

    fn names(install: &ParsedInstall) -> Vec<&str> {
        install.packages.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn detect_npm_install() {
        let v = detect_installs("npm install lodash express");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash", "express"]);
    }

    #[test]
    fn detect_pip_install_with_pin() {
        let v = detect_installs("pip install requests==2.31.0 numpy");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(v[0].packages[0].0, "requests");
        assert_eq!(v[0].packages[0].1.as_deref(), Some("2.31.0"));
        assert_eq!(v[0].packages[1].0, "numpy");
        assert_eq!(v[0].packages[1].1, None);
    }

    #[test]
    fn detect_compound_install() {
        let v = detect_installs("cd foo && npm install x && pip install y");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn uv_does_not_double_match_via_pip() {
        // `uv pip install foo` must match the UV pattern once, NOT also
        // the bare PIP pattern on the inner `pip install foo` substring.
        let v = detect_installs("uv pip install requests");
        assert_eq!(v.len(), 1, "expected exactly one detection, got {}", v.len());
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
    fn npm_scoped_pkg_with_version_preserved() {
        let (n, v) = split_name_version("@types/node@22.10.0");
        assert_eq!(n, "@types/node");
        assert_eq!(v.as_deref(), Some("22.10.0"));
        let (n, v) = split_name_version("@types/node");
        assert_eq!(n, "@types/node");
        assert_eq!(v, None);
    }

    #[test]
    fn pip_version_specifiers() {
        assert_eq!(split_name_version("requests==2.31.0").0, "requests");
        assert_eq!(
            split_name_version("requests==2.31.0").1.as_deref(),
            Some("2.31.0")
        );
        assert_eq!(split_name_version("requests>=2.0").0, "requests");
        assert_eq!(split_name_version("requests>=2.0").1, None);
        assert_eq!(split_name_version("requests~=2.0").0, "requests");
        assert_eq!(split_name_version("requests~=2.0").1, None);
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
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn url_install_treated_as_editable() {
        let v = detect_installs("pip install https://example.com/pkg.tar.gz");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn mixed_editable_and_named_keeps_named_packages() {
        // `pip install -e . requests` must still surface `requests` as a
        // vettable package — the editable token is a sibling, not a free
        // pass for the whole install.
        let v = detect_installs("pip install -e . requests");
        assert_eq!(v.len(), 1);
        assert!(v[0].has_editable);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn cache_file_rejects_traversal() {
        // Package name containing `..` must not resolve to a cache path
        // (would write to parent directory).
        assert!(cache_file(Ecosystem::Npm, "..").is_none());
        assert!(cache_file(Ecosystem::Npm, "../etc/passwd").is_none());
        assert!(cache_file(Ecosystem::Pypi, "foo..bar").is_none());
        assert!(cache_file(Ecosystem::Pypi, "").is_none());
        assert!(cache_file(Ecosystem::Npm, "foo\\bar").is_none());
        // Real names still work.
        assert!(cache_file(Ecosystem::Npm, "lodash").is_some());
        assert!(cache_file(Ecosystem::Npm, "@types/node").is_some());
    }

    #[test]
    fn osv_severity_extracts_from_database_specific() {
        let v: Value = serde_json::from_str(
            r#"{"database_specific":{"severity":"MODERATE"}}"#,
        )
        .unwrap();
        assert_eq!(osv_severity(&v), Severity::Medium);

        let v: Value = serde_json::from_str(
            r#"{"severity":[{"score":"CVSS:3.1/.../A:H CRITICAL"}]}"#,
        )
        .unwrap();
        assert_eq!(osv_severity(&v), Severity::Critical);

        // No severity info → default High (so it doesn't slip past a HIGH threshold).
        let v: Value = serde_json::from_str(r#"{"id":"OSV-2024"}"#).unwrap();
        assert_eq!(osv_severity(&v), Severity::High);
    }
}
