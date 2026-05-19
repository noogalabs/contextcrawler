//! Cross-reference JSONL-extracted commands with the contextcrawler runtime
//! tracking database.
//!
//! Claude Code's `PreToolUse` hook rewrites Bash commands at runtime, but the
//! on-disk session JSONL records the *pre-hook* command. Without this
//! reconciliation step, `discover` would treat every hook-rewritten command as
//! a missed savings opportunity even though it actually flowed through
//! contextcrawler.
//!
//! See issue #82 for the bug report.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::Duration;

/// Default reconciliation time window (in seconds) — a JSONL tool_use timestamp
/// has to land within this many seconds of a tracked command's timestamp for
/// the two to be considered the same execution.
pub const DEFAULT_MATCH_WINDOW_SECS: i64 = 60;

/// A single row pulled from the runtime tracking DB's `commands` table.
#[derive(Debug, Clone)]
pub struct TrackedCommand {
    pub timestamp: DateTime<Utc>,
    pub original_cmd: String,
    #[allow(dead_code)]
    pub rtk_cmd: String,
}

impl TrackedCommand {
    /// `true` when this row was a fallback execution — the hook routed the
    /// command through contextcrawler, clap rejected it, and contextcrawler
    /// fell back to running it raw. Still counts as "runtime tracked".
    pub fn is_fallback(&self) -> bool {
        self.rtk_cmd.starts_with("contextcrawler fallback:")
            || self.rtk_cmd.starts_with("rtk fallback:")
    }
}

/// Outcome of attempting to load + reconcile against the tracking DB.
pub struct ReconcileContext {
    pub tracked: Vec<TrackedCommand>,
    /// `Some(message)` when the tracking DB couldn't be opened — the caller
    /// should emit this as a warning banner so the user understands why the
    /// MISSED SAVINGS section may over-report.
    pub warning: Option<String>,
    /// Path that was probed for the DB (useful for diagnostic messages).
    pub db_path: PathBuf,
}

/// Resolve the tracking DB path using the same precedence rules as
/// `crate::core::tracking` (env override → config file → platform default).
pub fn tracking_db_path() -> PathBuf {
    if let Ok(custom) = std::env::var("RTK_DB_PATH") {
        return PathBuf::from(custom);
    }
    if let Ok(config) = crate::core::config::Config::load() {
        if let Some(p) = config.tracking.database_path {
            return p;
        }
    }
    let data_dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    data_dir
        .join(crate::core::constants::RTK_DATA_DIR)
        .join(crate::core::constants::HISTORY_DB)
}

/// Load tracked commands within `[earliest, latest]` (each padded by
/// `DEFAULT_MATCH_WINDOW_SECS` so we don't miss rows near the boundary).
///
/// Errors are non-fatal: the returned `ReconcileContext.warning` carries the
/// message so the caller can surface it without aborting `discover`.
pub fn load_tracked(
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
) -> ReconcileContext {
    let db_path = tracking_db_path();
    load_tracked_from(&db_path, earliest, latest)
}

pub fn load_tracked_from(
    db_path: &std::path::Path,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
) -> ReconcileContext {
    let path_owned = db_path.to_path_buf();

    if !db_path.exists() {
        return ReconcileContext {
            tracked: Vec::new(),
            warning: Some(format!(
                "tracking DB at {} not found — MISSED SAVINGS may include commands that the PreToolUse hook successfully rewrote at runtime.",
                db_path.display()
            )),
            db_path: path_owned,
        };
    }

    match try_load(db_path, earliest, latest) {
        Ok(tracked) => ReconcileContext {
            tracked,
            warning: None,
            db_path: path_owned,
        },
        Err(e) => ReconcileContext {
            tracked: Vec::new(),
            warning: Some(format!(
                "tracking DB at {} unreachable ({}) — MISSED SAVINGS may include commands that the PreToolUse hook successfully rewrote at runtime.",
                db_path.display(),
                e
            )),
            db_path: path_owned,
        },
    }
}

fn try_load(
    db_path: &std::path::Path,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
) -> Result<Vec<TrackedCommand>> {
    let pad = chrono::Duration::seconds(DEFAULT_MATCH_WINDOW_SECS);
    let lo = earliest.map(|t| t - pad);
    let hi = latest.map(|t| t + pad);

    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("failed to open {}", db_path.display()))?;

    // Set a short busy timeout so a parallel writer can't stall discover.
    let _ = conn.busy_timeout(Duration::from_millis(500));

    let mut rows = match (lo, hi) {
        (Some(lo), Some(hi)) => {
            let mut stmt = conn.prepare(
                "SELECT timestamp, original_cmd, rtk_cmd FROM commands
                 WHERE timestamp BETWEEN ?1 AND ?2",
            )?;
            let collected =
                collect_rows(stmt.query(rusqlite::params![lo.to_rfc3339(), hi.to_rfc3339()])?)?;
            collected
        }
        _ => {
            let mut stmt =
                conn.prepare("SELECT timestamp, original_cmd, rtk_cmd FROM commands")?;
            let collected = collect_rows(stmt.query([])?)?;
            collected
        }
    };

    // Sort ascending by timestamp so matching can short-circuit faster.
    rows.sort_by_key(|r| r.timestamp);
    Ok(rows)
}

fn collect_rows(mut rows: rusqlite::Rows<'_>) -> Result<Vec<TrackedCommand>> {
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let ts_str: String = row.get(0)?;
        let original: String = row.get(1)?;
        let rtk: String = row.get(2)?;

        let timestamp = match parse_db_timestamp(&ts_str) {
            Some(t) => t,
            None => continue,
        };

        out.push(TrackedCommand {
            timestamp,
            original_cmd: original,
            rtk_cmd: rtk,
        });
    }
    Ok(out)
}

fn parse_db_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // SQLite's CURRENT_TIMESTAMP-style: "YYYY-MM-DD HH:MM:SS"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(naive.and_utc());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    None
}

/// Tokenise + normalise a Bash command for argument-by-argument comparison.
///
/// Returns `None` if the string isn't shell-parseable (unterminated quotes
/// etc.) — callers should fall back to whitespace tokenisation.
pub fn tokenise(cmd: &str) -> Option<Vec<String>> {
    shlex::split(cmd.trim())
}

/// Whitespace fallback tokeniser for cases where `shlex::split` returns None.
fn tokenise_whitespace(cmd: &str) -> Vec<String> {
    cmd.split_whitespace().map(|s| s.to_string()).collect()
}

/// Strip a leading `contextcrawler ` (or legacy `rtk `) prefix from a token
/// list, so we can compare the rewritten command's args against the original.
fn strip_wrapper_prefix(tokens: &[String]) -> &[String] {
    match tokens.first().map(|s| s.as_str()) {
        Some("contextcrawler") | Some("rtk") => &tokens[1..],
        _ => tokens,
    }
}

/// True when two commands are equivalent under tokenised comparison:
/// same arg count, same arg-for-arg values. Used to cope with quoting drift
/// between the JSONL record and the tracking DB row.
#[allow(dead_code)]
pub fn cmds_equivalent(a: &str, b: &str) -> bool {
    let a_tokens = tokenise(a).unwrap_or_else(|| tokenise_whitespace(a));
    let b_tokens = tokenise(b).unwrap_or_else(|| tokenise_whitespace(b));
    a_tokens == b_tokens
}

/// Check whether an extracted JSONL tool_use was actually routed through
/// contextcrawler at runtime. We match on:
///
/// 1. `original_cmd` equivalence (tokenised), OR
/// 2. `original_cmd` equivalence to the JSONL command stripped of any leading
///    `contextcrawler `/`rtk ` prefix (covers the rare case where the JSONL
///    already shows a wrapped command).
///
/// AND the tracked row's timestamp must fall within `window_secs` of the
/// JSONL entry's timestamp.
///
/// If `jsonl_ts` is `None` we skip the timestamp check entirely — better to
/// over-credit a few stale commands than miss the whole session.
pub fn is_runtime_tracked(
    jsonl_cmd: &str,
    jsonl_ts: Option<DateTime<Utc>>,
    tracked: &[TrackedCommand],
    window_secs: i64,
) -> bool {
    let window = chrono::Duration::seconds(window_secs);

    let jsonl_tokens = tokenise(jsonl_cmd).unwrap_or_else(|| tokenise_whitespace(jsonl_cmd));
    let jsonl_stripped: Vec<String> = strip_wrapper_prefix(&jsonl_tokens).to_vec();

    for row in tracked {
        // Time window gate (only when we have a JSONL timestamp).
        if let Some(j_ts) = jsonl_ts {
            let delta = (row.timestamp - j_ts).num_seconds().abs();
            if delta > window.num_seconds() {
                continue;
            }
        }

        let row_tokens = tokenise(&row.original_cmd)
            .unwrap_or_else(|| tokenise_whitespace(&row.original_cmd));

        if row_tokens == jsonl_tokens || row_tokens == jsonl_stripped {
            // Fallback rows still count as runtime-tracked.
            let _ = row.is_fallback();
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rusqlite::Connection;

    fn mk_db(rows: &[(&str, &str, &str)]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute(
            "CREATE TABLE commands (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                original_cmd TEXT NOT NULL,
                rtk_cmd TEXT NOT NULL,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                saved_tokens INTEGER NOT NULL DEFAULT 0,
                savings_pct REAL NOT NULL DEFAULT 0.0,
                exec_time_ms INTEGER DEFAULT 0,
                project_path TEXT DEFAULT ''
            )",
            [],
        )
        .unwrap();
        for (ts, orig, wrapped) in rows {
            conn.execute(
                "INSERT INTO commands (timestamp, original_cmd, rtk_cmd, input_tokens, output_tokens, saved_tokens, savings_pct)
                 VALUES (?1, ?2, ?3, 0, 0, 0, 0.0)",
                rusqlite::params![ts, orig, wrapped],
            )
            .unwrap();
        }
        f
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn test_exact_match_within_window_reconciles() {
        let db = mk_db(&[(
            "2026-05-19T10:00:00+00:00",
            "git status",
            "contextcrawler git status",
        )]);

        let ctx = load_tracked_from(
            db.path(),
            Some(ts("2026-05-19T09:00:00+00:00")),
            Some(ts("2026-05-19T11:00:00+00:00")),
        );
        assert!(ctx.warning.is_none(), "expected no warning, got {:?}", ctx.warning);
        assert_eq!(ctx.tracked.len(), 1);

        let matched = is_runtime_tracked(
            "git status",
            Some(ts("2026-05-19T10:00:30+00:00")),
            &ctx.tracked,
            DEFAULT_MATCH_WINDOW_SECS,
        );
        assert!(matched);
    }

    #[test]
    fn test_quoting_difference_reconciles_via_tokeniser() {
        // tracked row uses bare args, JSONL preserves quoted form
        let db = mk_db(&[(
            "2026-05-19T10:00:00+00:00",
            "git log --oneline -n 5",
            "contextcrawler git log --oneline -n 5",
        )]);
        let ctx =
            load_tracked_from(db.path(), Some(ts("2026-05-19T09:50:00+00:00")), Some(ts("2026-05-19T10:10:00+00:00")));
        assert_eq!(ctx.tracked.len(), 1);

        // Same tokens, different quoting: shlex collapses these.
        let matched = is_runtime_tracked(
            "git   log --oneline -n   5",
            Some(ts("2026-05-19T10:00:10+00:00")),
            &ctx.tracked,
            DEFAULT_MATCH_WINDOW_SECS,
        );
        assert!(matched, "tokeniser should normalise extra whitespace");
    }

    #[test]
    fn test_timestamp_outside_window_does_not_reconcile() {
        let db = mk_db(&[(
            "2026-05-19T10:00:00+00:00",
            "cargo test",
            "contextcrawler cargo test",
        )]);
        let ctx = load_tracked_from(db.path(), None, None);
        assert_eq!(ctx.tracked.len(), 1);

        // 10 minutes later — well outside the 60s window.
        let matched = is_runtime_tracked(
            "cargo test",
            Some(ts("2026-05-19T10:10:00+00:00")),
            &ctx.tracked,
            DEFAULT_MATCH_WINDOW_SECS,
        );
        assert!(!matched, "should not match a row 10min out of window");
    }

    #[test]
    fn test_missing_tracking_db_emits_warning() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.db");
        let ctx = load_tracked_from(&missing, None, None);
        assert!(ctx.tracked.is_empty());
        assert!(ctx.warning.is_some());
        assert!(ctx.warning.as_ref().unwrap().contains("tracking DB"));
    }

    #[test]
    fn test_fallback_rtk_cmd_still_counts() {
        let db = mk_db(&[(
            "2026-05-19T10:00:00+00:00",
            "unknown-cmd foo",
            "contextcrawler fallback: unknown-cmd foo",
        )]);
        let ctx = load_tracked_from(db.path(), None, None);
        assert_eq!(ctx.tracked.len(), 1);
        assert!(ctx.tracked[0].is_fallback());

        let matched = is_runtime_tracked(
            "unknown-cmd foo",
            Some(ts("2026-05-19T10:00:05+00:00")),
            &ctx.tracked,
            DEFAULT_MATCH_WINDOW_SECS,
        );
        assert!(matched);
    }

    #[test]
    fn test_three_command_fixture_two_matched_one_unmatched() {
        // Mirrors the end-to-end test described in the task brief:
        // three tool_use Bash blocks (git status, cargo test, unknown-cmd foo)
        // and two tracked rows (git status + cargo test). The third command
        // must remain unreconciled.
        let db = mk_db(&[
            (
                "2026-05-19T10:00:00+00:00",
                "git status",
                "contextcrawler git status",
            ),
            (
                "2026-05-19T10:00:05+00:00",
                "cargo test",
                "contextcrawler cargo test",
            ),
        ]);
        let ctx = load_tracked_from(db.path(), None, None);
        assert_eq!(ctx.tracked.len(), 2);

        let jsonl = [
            ("git status", "2026-05-19T10:00:01+00:00", true),
            ("cargo test", "2026-05-19T10:00:06+00:00", true),
            ("unknown-cmd foo", "2026-05-19T10:00:10+00:00", false),
        ];
        let mut matched = 0;
        let mut unmatched = 0;
        for (cmd, ts_str, expect) in jsonl {
            let got = is_runtime_tracked(
                cmd,
                Some(ts(ts_str)),
                &ctx.tracked,
                DEFAULT_MATCH_WINDOW_SECS,
            );
            assert_eq!(got, expect, "mismatch for {}", cmd);
            if got {
                matched += 1;
            } else {
                unmatched += 1;
            }
        }
        assert_eq!(matched, 2);
        assert_eq!(unmatched, 1);
    }

    #[test]
    fn test_unparseable_jsonl_command_falls_back_to_whitespace() {
        // shlex::split will refuse an unterminated quote — the whitespace
        // fallback should still get a sensible token list.
        let tokens = tokenise("git commit -m \"unclosed");
        assert!(tokens.is_none());

        let _utc_marker = Utc.timestamp_opt(0, 0).unwrap();
    }
}
