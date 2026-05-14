// SPDX-License-Identifier: MIT
// Adapted from jee599/contextzip (MIT). Original work by jee599 — not derived
// from upstream rtk-ai/rtk. Wires the JSONL session compactor into the
// ContextCrawler CLI as `contextcrawler sessions {compact|apply|expand}`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use super::jsonl_rewriter::{compact_session_file, compact_session_str, CompactStats};

pub fn run_compact(
    target: Option<&str>,
    dry_run: bool,
    all_sessions: bool,
    verbose: u8,
) -> Result<()> {
    if all_sessions {
        run_all_sessions(dry_run, verbose)
    } else {
        let target = target
            .ok_or_else(|| anyhow::anyhow!("missing <target>; use --all-sessions for batch mode"))?;
        run_with_options(target, dry_run, verbose)
    }
}

fn run_with_options(target: &str, dry_run: bool, verbose: u8) -> Result<()> {
    let session_path = resolve_session_path(target)?;

    if verbose > 0 {
        eprintln!(
            "compact{}: {}",
            if dry_run { " (dry-run)" } else { "" },
            session_path.display()
        );
    }

    let stats = if dry_run {
        let raw = std::fs::read_to_string(&session_path)
            .with_context(|| format!("Failed to read session: {}", session_path.display()))?;
        compact_session_str(&raw).1
    } else {
        let (_sidecar, stats) = compact_session_file(&session_path)
            .with_context(|| format!("Failed to compact session: {}", session_path.display()))?;
        stats
    };

    print_stats_line(&session_path, &stats, dry_run);
    Ok(())
}

fn run_all_sessions(dry_run: bool, verbose: u8) -> Result<()> {
    let root = projects_root()?;
    if !root.is_dir() {
        bail!(
            "No Claude Code projects directory at {}.\n\
             Set $CLAUDE_PROJECTS_DIR if your sessions live elsewhere.",
            root.display()
        );
    }

    let mut total_in = 0usize;
    let mut total_out = 0usize;
    let mut total_dedup = 0usize;
    let mut total_bash = 0usize;
    let mut sessions_done = 0usize;
    let mut sessions_skipped = 0usize;

    for project in
        std::fs::read_dir(&root).with_context(|| format!("Failed to read {}", root.display()))?
    {
        let Ok(project) = project else { continue };
        if !project.path().is_dir() {
            continue;
        }
        for file in std::fs::read_dir(project.path())? {
            let Ok(file) = file else { continue };
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let sidecar = sidecar_path(&path);
            if !dry_run && sidecar.exists() {
                sessions_skipped += 1;
                if verbose > 0 {
                    eprintln!("skip {} (sidecar exists)", path.display());
                }
                continue;
            }
            match run_with_options(path.to_string_lossy().as_ref(), dry_run, verbose.max(1)) {
                Ok(()) => {
                    sessions_done += 1;
                    if let Ok(raw) = std::fs::read_to_string(&path) {
                        let s = compact_session_str(&raw).1;
                        total_in += s.bytes_in;
                        total_out += s.bytes_out;
                        total_dedup += s.read_results_deduped;
                        total_bash += s.bash_results_recompressed;
                    }
                }
                Err(e) => eprintln!("FAIL {}: {}", path.display(), e),
            }
        }
    }

    let pct = if total_in > 0 {
        ((total_in - total_out.min(total_in)) as f64 / total_in as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "all-sessions: {} compacted, {} skipped\n  bytes: {} -> {} ({:.1}% saved)\n  axes: ReadDedup={}, BashHistoryCompact={}",
        sessions_done, sessions_skipped, total_in, total_out, pct, total_dedup, total_bash
    );
    Ok(())
}

pub fn run_apply(target: &str, verbose: u8) -> Result<()> {
    let session_path = resolve_session_path(target)?;
    let sidecar = sidecar_path(&session_path);
    let backup = backup_path(&session_path);

    if !sidecar.is_file() {
        bail!(
            "No sidecar at {}. Run `contextcrawler sessions compact {}` first.",
            sidecar.display(),
            target
        );
    }
    if backup.exists() {
        bail!(
            "Backup already exists at {}. Run `contextcrawler sessions expand {}` first, or remove the backup manually.",
            backup.display(),
            target
        );
    }

    if verbose > 0 {
        eprintln!(
            "apply: {} -> {} (backup at {})",
            sidecar.display(),
            session_path.display(),
            backup.display()
        );
    }

    std::fs::rename(&session_path, &backup)
        .with_context(|| format!("Failed to back up original session to {}", backup.display()))?;
    if let Err(e) = std::fs::rename(&sidecar, &session_path) {
        let _ = std::fs::rename(&backup, &session_path);
        return Err(e).context("Failed to promote sidecar to live session; backup restored");
    }

    println!(
        "apply: {} now active; original preserved at {}",
        session_path.display(),
        backup.display()
    );
    Ok(())
}

pub fn run_expand(target: &str, verbose: u8) -> Result<()> {
    let session_path = resolve_session_path(target)?;
    let backup = backup_path(&session_path);
    let sidecar = sidecar_path(&session_path);

    if !backup.is_file() {
        bail!("No backup at {}. Nothing to expand from.", backup.display());
    }

    if verbose > 0 {
        eprintln!(
            "expand: {} -> {} (current -> {})",
            backup.display(),
            session_path.display(),
            sidecar.display()
        );
    }

    if session_path.is_file() {
        std::fs::rename(&session_path, &sidecar).with_context(|| {
            format!(
                "Failed to move current session aside to {}",
                sidecar.display()
            )
        })?;
    }
    std::fs::rename(&backup, &session_path)
        .with_context(|| format!("Failed to restore backup from {}", backup.display()))?;

    println!(
        "expand: original restored at {} (compressed copy preserved at {})",
        session_path.display(),
        sidecar.display()
    );
    Ok(())
}

fn print_stats_line(path: &Path, stats: &CompactStats, dry_run: bool) {
    println!(
        "{}: {}\n  records: {}, bytes: {} -> {} ({:.1}% saved)\n  axes: ReadDedup={}, BashHistoryCompact={}",
        if dry_run { "compact (dry-run)" } else { "compact" },
        path.display(),
        stats.records_written,
        stats.bytes_in,
        stats.bytes_out,
        stats.percent_saved(),
        stats.read_results_deduped,
        stats.bash_results_recompressed,
    );
}

fn sidecar_path(session: &Path) -> PathBuf {
    let mut p = session.to_path_buf();
    let name = session
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("session.jsonl");
    p.set_file_name(format!("{}.compressed", name));
    p
}

fn backup_path(session: &Path) -> PathBuf {
    let mut p = session.to_path_buf();
    let name = session
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("session.jsonl");
    p.set_file_name(format!("{}.bak", name));
    p
}

fn resolve_session_path(target: &str) -> Result<PathBuf> {
    let direct = PathBuf::from(target);
    if direct.is_file() {
        return Ok(direct);
    }

    // When `target` is a bare session id (i.e. not a direct file path) we
    // join it under each project dir as `<dir>/<target>.jsonl`. Reject ids
    // that contain path separators or `..` components — otherwise an id
    // like `../foo` would resolve out of $CLAUDE_PROJECTS_DIR.
    if target.contains('/') || target.contains('\\') || target.contains("..") {
        bail!(
            "Invalid session id `{}`: must be a bare id (no path separators or `..`). \
             To target a file outside the projects root, pass the full path.",
            target
        );
    }

    let root = projects_root()?;
    let mut hits: Vec<PathBuf> = Vec::new();
    for project_dir in std::fs::read_dir(&root).with_context(|| {
        format!(
            "Failed to read Claude Code projects directory: {}",
            root.display()
        )
    })? {
        let Ok(project_dir) = project_dir else {
            continue;
        };
        if !project_dir.path().is_dir() {
            continue;
        }
        let candidate = project_dir.path().join(format!("{}.jsonl", target));
        if candidate.is_file() {
            hits.push(candidate);
        }
    }

    match hits.len() {
        0 => bail!(
            "No session found. Tried: {} (file) and `{}.jsonl` under {}",
            target,
            target,
            root.display()
        ),
        1 => Ok(hits.into_iter().next().unwrap()),
        n => bail!(
            "Session id `{}` matched {} files across multiple projects. Pass the full path instead.",
            target,
            n
        ),
    }
}

fn projects_root() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CLAUDE_PROJECTS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".claude").join("projects"))
}
