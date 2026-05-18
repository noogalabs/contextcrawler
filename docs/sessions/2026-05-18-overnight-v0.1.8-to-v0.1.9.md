# Session handover — 2026-05-18 → 2026-05-19

**Session window:** ~12 hours, single overnight working session.
**Started at:** v0.1.7 develop tip (`b23dba1`)
**Ended at:** v0.1.9 develop tip (`0ff327f`)
**Deployed:** `~/.local/bin/contextcrawler` → v0.1.9 (sha256-verified)

---

## What shipped

**Two releases:** v0.1.8 (~mid-session) and v0.1.9 (end-of-session).

### v0.1.8 highlights
- Zero-trust CLI wrapper layer across 15 `secure_*_command` helpers
- `UNIVERSAL_ENV_STRIP` wired into all of them
- Confirmed RIPGREP_CONFIG_PATH → `--pre` RCE blocked (4/4 attack paths PoC-blocked)
- Real `contextcrawler security` Tirith dashboard (was doc-only)
- 19 PRs since v0.1.6

### v0.1.9 highlights (14 PRs since v0.1.8)
- **#62 — Claude Code hook actually works now** (the headline). `rewrite_command` was returning `rtk X` for every rewrite, but the binary is `contextcrawler`. Any user with raw-command Claude usage hit "rtk: command not found" on every rewrite. Fixed with full backcompat for legacy `rtk X` already-wrapped inputs. The bug was masked in-session because most traffic flowed via codex (which uses `contextcrawler X` directly per AGENTS.md template).
- gh/glab/gt zero-trust hardening (#58)
- pytest `-p` bare-relative + glued-form bypass close (#59)
- `$CODEX_HOME` escape warning (#66)
- Tier 2 Claude Code bench harness (#70) — 10.4% measured end-to-end savings
- Allowlist-based branding lint (#71) — catalogues ~50 known-debt RTK strings as a pinning list
- Cleanup PR (#64): deleted 6 orphan modules (-2953 lines), wired 2 latent legacy hook bugs, brought cargo warnings 80+ → 0
- 3 branding sweep rounds (#61, #63 inline; #71 the meta-lint refactor)

### Tooling milestones
- **First successful parallel-agent dispatch** — 3-way worktree-isolated agents
  (#48 + #67 + #29 Tier 2) all returned within 18 min, merged serially, zero
  conflicts. Strict file contracts + `isolation: "worktree"` + serialized merge
  prevented the PR-#34/#39 cascading-conflict failure mode from recurring.

---

## Quality bar at handover

| | |
|---|---|
| Develop tip | `0ff327f` (v0.1.9 merge) |
| Local install | `contextcrawler 0.1.9` |
| `cargo build` warnings | **0** |
| `cargo test --bin contextcrawler` | 2119 pass / 0 fail |
| Integration suites green | **10/10** (branding_lint, git_hardening, cargo_hardening, node_hardening, runtime_hardening, cloud_hardening, harness_standalone, proxy_nudge, gh_glab_gt_hardening, harness_claude_code) |

---

## Open backlog (ranked by ROI)

| # | Title | Status | Effort |
|---|---|---|---|
| **#67-debt** | ~50 catalogued RTK strings in dashboard / uninstall / etc. | lint-pinned, ready for solo cleanup | small |
| **#28** | codex compliance 80% → 95%+ | needs 24h post-#54 dashboard sample | small (after wait) |
| **#69** | unit-test `src/core/utils.rs` env race | follow-up to #48 | small |
| **#29 Tier 3** | Codex bench harness | symmetric with Tier 2 (#70) | medium |
| **#40** | trusted-PATH binary resolution | needs design discussion | larger |

Plus residual cosmetic: `"RTK auto-rewrite"` in `src/hooks/hook_cmd.rs:148,338` — label string in the hook's JSON response, doesn't break execution. Catalogued in #67-debt; will sweep with the rest.

---

## Active measurements (recommend re-checking after 24h)

The dispatch left three things needing dashboard data before we can claim the lifts landed:

1. **Codex compliance** — baseline 84.3% pre-#54. Target ≥95%. Re-measure with `contextcrawler discover --codex --since 1`.
2. **`proxy` row** — 307K input @ 0% pre-PR #54. Did the proxy nudge steer codex back to wrapped tools? Re-check `proxy` row absolute volume in `contextcrawler gain`.
3. **`git` aggregate** — 22.9% pre-PR #56. Target ≥45%. Re-measure in `contextcrawler gain`.

Methodology preserved in `[[contextcrawler-state-2026-05-18-post-v0_1_8]]` memory.

---

## Environment / hygiene notes

- **Workspace clean** except 2 untracked `hooks/hermes/__pycache__/` dirs (pre-existing all-session; never in scope; deferred).
- **Hook config** confirmed: native binary form (`contextcrawler hook claude` in `~/.claude/settings.json`). NOT the bash hook script — no re-init needed for v0.1.9 to take effect.
- **GPG signing** worked through the session after the early hiccup. `~/.local/bin/contextcrawler.bak-*` backups accumulated from each redeploy — fine to garbage-collect oldest if disk pressure mounts.
- **8 worktrees** cleaned up (3 agent + 1 deploy + earlier session). `git worktree list` should show only the main checkout.

---

## Resume checklist

When you come back, in order:

1. `cd /Users/thehoff/Workspace/contextZip/rtk-fork && git fetch contextcrawler && git checkout contextcrawler/develop` — pick up develop tip.
2. `contextcrawler discover --codex --since 1` — codex compliance number.
3. `contextcrawler gain` — dashboard for `git` + `proxy` rows.
4. Pick from the backlog above. Recommended next single-session unit: **#67-debt cleanup** (50 string replacements, lint already catalogues them).

---

## Cumulative session output (raw numbers)

- **24 PRs merged** (10 in v0.1.8 cycle + 14 in v0.1.9 cycle)
- **8 GH issues filed** this session (#53, #55, #57, #62, #67, #69, plus internal ones)
- **6 issues closed** during the session
- **5 memory files added** under `~/.claude/projects/-Users-thehoff-Workspace/memory/`:
  - `contextcrawler_release_v0_1_8.md`
  - `contextcrawler_state_2026-05-18-post-v0_1_8.md`
  - `feedback_no_binary_releases.md`
  - `contextcrawler_release_v0_1_9.md`
  - (plus updates to `MEMORY.md` index)
- **1 parallel-agent dispatch** (retrospective lessons captured in the v0.1.9 memory file)
