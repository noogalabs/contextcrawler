# Module audits — `src/analytics/{jsonl_rewriter,session_compact_cmd,security_cmd}.rs`

Combined audit of the three downstream-original analytics modules.
Lower-severity findings than the dispatch / network / trust gates
already covered.

## `src/analytics/jsonl_rewriter.rs` (557 lines)

Compacts a Claude Code session-JSONL file into a sidecar
`.compressed` file. Two passes: index Read tool-uses, then rewrite
repeated Read results as references and recompress Bash output.

### Good practices

- Pure-string entry point (`compact_session_str`) is testable and
  side-effect-free.
- Original file is never mutated. Sidecar is the output; rollback is
  `rm <sidecar>`.
- Line-level error tolerance: lines that aren't valid JSON pass
  through verbatim instead of aborting.
- 12+ inline tests covering dedup, bash recompression, edge cases.
- SHA-256 helper uses the same `sha2` dependency as the rest of the
  codebase (no new crypto surface).

### Findings

#### F-01: No size cap on `fs::read_to_string(input)` (LOW)

Session JSONLs are typically <10 MB, but a hostile
`CLAUDE_PROJECTS_DIR` pointing at a 50 GB file (or a symlink
chain into `/dev/zero`) would OOM us. Compromised-account threat
model normally; worth a `metadata().len() > MAX` check before
loading.

#### F-02: Sidecar overwrite without confirmation (INFO)

`compact_session_file` writes to `<input>.compressed` via
`fs::write`. If a user previously ran compact and the sidecar
exists, it's silently overwritten. `run_all_sessions` does check
`sidecar.exists()` and skips, but the single-file
`run_with_options` doesn't. Minor UX — no security impact.

## `src/analytics/session_compact_cmd.rs` (292 lines)

CLI wiring around `jsonl_rewriter`. Three operations: `compact`,
`apply`, `expand`.

### Good practices

- **Path traversal guard** at `resolve_session_path` (line 242)
  rejects `/`, `\`, and `..` in bare session ids — `../../etc/passwd`
  doesn't resolve out of `$CLAUDE_PROJECTS_DIR`.
- **`apply` has rollback** (line 148-150): if the second rename
  fails, the original is restored from backup.
- **Sidecar/backup paths** use `set_file_name` on the same directory
  as input — no cross-directory writes.
- **Multiple-match defence**: when a bare id matches multiple
  projects, bails out instead of picking one.

### Findings

#### F-01: `apply` is not atomic across the two renames (LOW)

Lines 146-151:
```rust
std::fs::rename(&session_path, &backup)?;
if let Err(e) = std::fs::rename(&sidecar, &session_path) {
    let _ = std::fs::rename(&backup, &session_path);
    return Err(e)...
}
```

Window between the two renames where the live session path
doesn't exist. A third process (e.g. Claude Code itself, still
running and writing to the session) would race and either lose
its in-progress writes or see ENOENT.

Mitigation already partial: the rollback handles the case where
the second rename fails. But it doesn't handle a third process
that opens the file path between renames.

Real-world impact is low (users typically run apply only after
the session is finished), but worth documenting in
`docs/contributing/RELEASING.md` or the apply command help text.

**Recommendation:** Document "stop Claude Code before running
`sessions apply` on an active session." Optionally: refuse to
apply if the session file has been modified within the last
60 seconds.

#### F-02: `CLAUDE_PROJECTS_DIR` env-var injection (INFO, out-of-scope)

`projects_root` reads `CLAUDE_PROJECTS_DIR` directly. An attacker
with env-var control can redirect to a hostile directory full of
crafted JSONL files. Single-user CLI threat model: env-var
control == compromised account == out of scope. Already documented
in `THREAT_MODEL.md`.

#### F-03: Verbose mode prints session paths to stderr (INFO)

Standard verbose-mode behaviour; not a leak per se. Worth noting
because session paths under `~/.claude/projects/<encoded-cwd>/`
encode the user's directory layout — a verbose session compact in
a shared terminal log would leak it. Not in scope to redact.

## `src/analytics/security_cmd.rs` (606 lines)

`contextcrawler security` dashboard. Subprocess-calls `tirith
audit stats` and `tirith doctor`, parses JSON, formats output.
Also reads `downgrades.jsonl` and `supply_chain.jsonl` from
`~/.local/share/contextcrawler/` for the unified log view.

### Good practices

- **Subprocess-only** to tirith — no AGPL static linking.
- **Best-effort parsing**: failed `serde_json::from_slice` → `None`,
  caller shows "Tirith stats unavailable" instead of crashing.
- **Path-relative log file resolution** via `dirs::data_local_dir`
  — no hardcoded paths.

### Findings

#### F-01: Same subprocess-timeout bug as tirith_gate (MEDIUM)

`fetch_audit_stats` (line 458) and `fetch_doctor_status` (line 477)
both use `Command::new(bin).args(...).output()` with no timeout.
A hung tirith would block `contextcrawler security` indefinitely.
Same class as `MODULE_AUDIT_tirith_gate.md` F-01, same fix:
spawn + `wait_timeout` with an 8s cap.

**Recommendation:** Reuse the same `wait_timeout` pattern from the
`feat/sec-tirith-timeout` branch. Two call sites in this file;
both benefit from a small helper `fn run_tirith_capture(&[&str])
-> Option<Vec<u8>>` that bundles the spawn/wait/read/cap.

#### F-02: Same `~/.cargo/bin/tirith` fallback (INFO)

`resolve_tirith_bin` (line 446) has the same fallback path as
`tirith_gate.rs::check`. An attacker who can write
`~/.cargo/bin/tirith` can install a fake binary that emits
adversarial stats. Same out-of-threat-model class (compromised
local account) as the tirith gate's F-03.

#### F-03: No stdout size cap on tirith output (LOW)

`fetch_audit_stats` reads tirith stdout to EOF. A misbehaving
tirith could emit gigabytes and OOM us. Same fix folds into F-01.

#### F-04: `parse_tirith_line` is silent on malformed JSON (INFO)

Line 116-117:
```rust
if let Some(ev) = parse_tirith_line(line) {
    ...
}
```

Lines that fail to parse are silently skipped. No telemetry, no
diagnostic. If `downgrades.jsonl` becomes corrupt (mid-write
crash, see the F-04 from `MODULE_AUDIT_tirith_gate.md` about
non-atomic JSON writes there), the user sees partial data with no
hint why. Hardening: count parse failures and surface them in
verbose mode.

## Test coverage gaps across these three modules

| Surface | Tested? |
|---|---|
| `compact_session_file` happy path | yes (dedup, bash compress) |
| `compact_session_file` with malformed JSON lines | yes (pass-through) |
| `compact_session_file` with huge input | no |
| `resolve_session_path` path-traversal rejection | not in inline tests |
| `apply` rollback on second-rename failure | no |
| `apply` race with concurrent writer | no (hard to test) |
| `security log` parsing malformed lines | no |
| `fetch_audit_stats` timeout behaviour (after F-01 fix) | future |

## Summary

Nothing High or Critical. Three Mediums:

- `session_compact_cmd.rs` F-01 — rename race (UX) → document.
- `security_cmd.rs` F-01 — same missing timeout as tirith gate →
  reuse the existing `wait_timeout` pattern in a v0.1.7 follow-up.

Plus six LOW/INFO hardening items. All three modules are well-
scoped, well-tested, and don't introduce a new attack class
beyond what's already in the threat model.

Suggested follow-up branch: `feat/sec-security-cmd-timeout` —
applies the same fix the tirith-timeout branch applied. ~30
minutes of work. Bundle with the tirith F-04 JSON re-escape fix
which is in the same neighbourhood of the codebase.
