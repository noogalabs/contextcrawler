# Pi.dev as the 11th supported harness — design

Status: draft, awaiting review.
Author: thehoff + Claude (brainstorming session 2026-05-23).
Branch: `feat/pidev-harness` (stacks on `refactor/unify-harness-guidance`).

## Goal

Add ContextCrawler support for [Pi](https://pi.dev) — a TypeScript terminal
coding harness by [earendil-works](https://github.com/earendil-works/pi) —
on parity with the other ten harnesses unified in the preceding
`refactor/unify-harness-guidance` work. Pi gets both a command-rewriting
hook (so `git status` runs as `contextcrawler git status` transparently)
and the canonical agent guidance (so the model knows about meta-commands
and the security gate).

## Background — Pi facts

Empirically verified from the upstream repo before drafting this spec:

| Topic | Value | Source |
|---|---|---|
| Install | `npm install -g --ignore-scripts @earendil-works/pi-coding-agent` | pi.dev / repo README |
| Pi home | `~/.pi/agent/` | repo README "Context Files" |
| Instructions file | `AGENTS.md`, loaded from `~/.pi/agent/`, parent dirs, and cwd | repo README |
| Extensions dir | `~/.pi/agent/extensions/` (auto-discovered) | examples/extensions/README.md |
| Extension API | TypeScript modules from `@earendil-works/pi-coding-agent`, default export `(pi: ExtensionAPI) => void` | examples/extensions/permission-gate.ts |
| Bash rewrite API | `createBashTool(cwd, { spawnHook: ({command, cwd, env}) => {command, cwd, env} })` returns a tool to register via `pi.registerTool(...)` | examples/extensions/bash-spawn-hook.ts |

Pi's `AGENTS.md` discovery puts it in the same family as Codex, OpenCode
and Hermes — all four converge on `AGENTS.md`, the universal convention
the preceding refactor already standardised on.

## Architecture

Mirrors the OpenCode integration. Two artifacts installed by
`contextcrawler init --agent pidev`:

1. **Extension** at `~/.pi/agent/extensions/contextcrawler.ts` — a small
   TypeScript module that registers an overridden bash tool. The tool's
   `spawnHook` rewrites the command string to prefix `contextcrawler `
   before Pi spawns it. Rewrite logic mirrors `hooks/opencode/rtk.ts`:
   chain-aware (`&&` / `||` / `;` / `|`), skips already-prefixed
   commands, skips `contextcrawler` itself, skips the same exclusion
   list (cd, export, alias, etc.).

2. **Guidance** as a marked block upserted into `~/.pi/agent/AGENTS.md`
   using the existing `write_rtk_block` / `RTK_BLOCK_START` pattern. The
   block content is `agent_guidance(AGENT_PIDEV)` — the canonical body
   plus a hooked-agent mechanism para ("the Pi extension rewrites shell
   commands automatically…"). Coexists with any user content in
   AGENTS.md.

No new file conventions, no new install patterns — Pi maps onto pieces
that already exist.

## File changes

### New files

- `hooks/pi/rtk-extension.ts` — the TypeScript extension. ~50 lines.
  Imports `ExtensionAPI` and `createBashTool` from
  `@earendil-works/pi-coding-agent`; default-exports a function that
  registers the rewriting bash tool. Embedded into the binary via
  `include_str!`.

- `hooks/pi/README.md` — short maintainer note pointing at the
  extension, the spawn-hook API, and the canonical guidance source.

### `src/hooks/init.rs`

- New consts:
  - `const AGENT_PIDEV: &str = "pidev";`
  - `const PI_EXTENSION: &str = include_str!("../../hooks/pi/rtk-extension.ts");`
  - `const PI_AGENT_DIR: &str = ".pi/agent";`
  - `const PI_EXTENSIONS_SUBDIR: &str = "extensions";`
  - `const PI_EXTENSION_FILE: &str = "contextcrawler.ts";`
- `agent_guidance()`: add a `AGENT_PIDEV` arm — title `"Pi"`, hooked-
  agent mechanism para (reuse the existing parameterised string used for
  Cursor/Windsurf/etc.).
- `assert_guidance_invariants()`: include `AGENT_PIDEV` in the checked
  set (the helper already iterates from `agent_guidance()` output, so no
  parallel list to update — but the calling tests need a per-harness
  drift-guard).
- New `run_pidev_mode(global: bool, ctx: InitContext) -> Result<()>`:
  1. Resolve `~/.pi/agent/` via `resolve_home_subdir(PI_AGENT_DIR)`.
  2. `create_dir_all` the `extensions/` subdir (guarded by `!dry_run`).
  3. `write_if_changed` the extension file to
     `~/.pi/agent/extensions/contextcrawler.ts` (content =
     `PI_EXTENSION`).
  4. `write_rtk_block` the guidance into `~/.pi/agent/AGENTS.md` using
     `agent_guidance_block(AGENT_PIDEV)?`.
  5. Install-summary `println!`s matching the OpenCode/Hermes pattern.
- New `uninstall_pidev_at(home: &Path, ctx: InitContext)`:
  1. `strip_rtk_block_from_file` on `~/.pi/agent/AGENTS.md`.
  2. Remove `~/.pi/agent/extensions/contextcrawler.ts` if present.
  3. Report `removed` artefacts the same way Hermes uninstall does.

### `src/main.rs`

- Extend `AgentTarget` enum with a `Pidev` variant (doc comment "Pi
  coding agent (earendil-works)").
- Wire the new variant into the `Init` dispatch match so
  `--agent pidev` calls `run_pidev_mode`. Mirror how `--agent hermes`
  routes.

## Testing

Unit tests (in `src/hooks/init.rs` `#[cfg(test)] mod tests`):

- `test_guidance_drift_guard_pidev` — `agent_guidance(AGENT_PIDEV)?`
  non-empty, starts with `# ContextCrawler (Pi)`, contains the canonical
  markers (`## Meta commands`, `## Security gate`, `contextcrawler gain`),
  no maintainer HTML comment.
- `test_pidev_mode_writes_extension_and_agents_md` — uses a tmp HOME,
  runs `run_pidev_mode`, asserts:
  - `~/.pi/agent/extensions/contextcrawler.ts` exists and equals
    `PI_EXTENSION`.
  - `~/.pi/agent/AGENTS.md` contains the marked guidance block.
- `test_pidev_uninstall_strips_block_and_removes_extension` — install
  then uninstall in a tmp HOME, assert both artifacts are gone and any
  user AGENTS.md content the test pre-seeded is preserved.

The TS extension itself is not unit-tested in the Rust suite; its
correctness is established by the empirical verification below.

## Empirical verification (before commit)

1. `npm install -g --ignore-scripts @earendil-works/pi-coding-agent`.
2. `cargo build --bins` then run `./target/debug/contextcrawler init --agent pidev`
   against a throwaway `HOME`.
3. Confirm `~/.pi/agent/extensions/contextcrawler.ts` and the marked
   block in `~/.pi/agent/AGENTS.md` exist with the expected content.
4. Launch `pi -p "run git status"` (or interactive), trigger the bash
   tool, and confirm via `contextcrawler gain` against the same HOME's
   tracking DB that the rewritten command was recorded.

## Out of scope

- Factoring a shared TypeScript rewrite module between
  `hooks/opencode/rtk.ts` and `hooks/pi/rtk-extension.ts`. ~30 lines
  duplicated; revisit if a third TS-extension harness lands.
- Shipping a Pi package (`pi install npm:contextcrawler-pi`) — the
  drop-in extension file is sufficient; npm publication is a follow-up.
- Project-scope-vs-global decision parity beyond what `--global` already
  controls — Pi loads AGENTS.md from cwd anyway, so a project-local
  `contextcrawler init --agent pidev` (no `-g`) is a natural follow-on.

## Open questions

None blocking. Two notes for the implementation pass:

- The extension's bash tool is registered with `process.cwd()` at module
  load time, but Pi's `spawnHook` is called per-invocation with the
  *current* `cwd` — use the parameter, not the closure capture, to
  honour cwd changes mid-session.
- The exclusion list and chain-aware rewrite logic should be ported
  verbatim from `hooks/opencode/rtk.ts`; do not re-derive — that file
  has already been hardened against the cases ContextCrawler shouldn't
  prefix.
