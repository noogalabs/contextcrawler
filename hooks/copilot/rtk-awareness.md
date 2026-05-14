# ContextCrawler — Copilot Integration (VS Code Copilot Chat + Copilot CLI)

**Usage**: Token-optimized CLI proxy (60-90% savings on dev operations).
Downstream of [rtk-ai/rtk](https://github.com/rtk-ai/rtk).

## What's automatic

The `.github/copilot-instructions.md` file is loaded at session start by both
Copilot CLI and VS Code Copilot Chat. It instructs Copilot to prefix commands
with `contextcrawler` automatically.

The `.github/hooks/rtk-rewrite.json` hook adds a `PreToolUse` safety net via
`contextcrawler hook` — a cross-platform Rust binary that intercepts raw bash
tool calls and rewrites them. No shell scripts, no `jq` dependency, works on
Windows natively. (Filename kept as `rtk-rewrite.json` for upstream-rebase
compatibility.)

## Meta commands (always use directly)

```bash
contextcrawler gain              # Token savings dashboard for this session
contextcrawler gain --history    # Per-command history with savings %
contextcrawler discover          # Scan session history for missed opportunities
contextcrawler proxy <cmd>       # Run raw (no filtering) but still track it
contextcrawler security          # Tirith defense-in-depth gate (if installed)
```

## Installation verification

```bash
contextcrawler --version
contextcrawler gain
which contextcrawler
```

## How the hook works

`contextcrawler hook copilot` reads `PreToolUse` JSON from stdin, detects the
agent format, and responds appropriately:

**VS Code Copilot Chat** (supports `updatedInput` — transparent rewrite, no denial):
1. Agent runs `git status` → `contextcrawler hook` intercepts via `PreToolUse`
2. Hook detects VS Code format (`tool_name`/`tool_input` keys)
3. Returns `hookSpecificOutput.updatedInput.command = "contextcrawler git status"`
4. Agent runs the rewritten command silently — no denial, no retry

**GitHub Copilot CLI** (deny-with-suggestion — CLI ignores `updatedInput` today, see [issue #2013](https://github.com/github/copilot-cli/issues/2013)):
1. Agent runs `git status` → `contextcrawler hook` intercepts via `PreToolUse`
2. Hook detects Copilot CLI format (`toolName`/`toolArgs` keys)
3. Returns `permissionDecision: deny` with reason: `"Token savings: use 'contextcrawler git status' instead"`
4. Copilot reads the reason and re-runs `contextcrawler git status`

When Copilot CLI adds `updatedInput` support, only the hook needs updating — no config changes.

## Integration comparison

| Tool                  | Mechanism                               | Hook output              | File                               |
|-----------------------|-----------------------------------------|--------------------------|------------------------------------|
| Claude Code           | `PreToolUse` hook with `updatedInput`   | Transparent rewrite      | `hooks/rtk-rewrite.sh`             |
| VS Code Copilot Chat  | `PreToolUse` hook with `updatedInput`   | Transparent rewrite      | `.github/hooks/rtk-rewrite.json`   |
| GitHub Copilot CLI    | `PreToolUse` deny-with-suggestion       | Denial + retry           | `.github/hooks/rtk-rewrite.json`   |
| OpenCode              | Plugin `tool.execute.before`            | Transparent rewrite      | `hooks/opencode-rtk.ts`            |
| (any)                 | Custom instructions                     | Prompt-level guidance    | `.github/copilot-instructions.md`  |
