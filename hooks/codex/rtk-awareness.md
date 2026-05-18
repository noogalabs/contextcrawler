# ContextCrawler (Codex CLI)

**Token-optimized CLI proxy for shell commands.** Downstream of [rtk-ai/rtk](https://github.com/rtk-ai/rtk). Reduces token cost 60–90% on read-heavy commands.

## REQUIRED RULE — shell-command prefix

You MUST prefix every shell tool invocation with `contextcrawler `. This is mandatory, not advisory.

- WRONG: `git status`           RIGHT: `contextcrawler git status`
- WRONG: `git log -3 --oneline` RIGHT: `contextcrawler git log -3 --oneline`
- WRONG: `grep -r foo src/`     RIGHT: `contextcrawler grep -r foo src/`
- WRONG: `cat README.md`        RIGHT: `contextcrawler read README.md`
- WRONG: `ls -la`               RIGHT: `contextcrawler ls -la`
- WRONG: `find . -name '*.ts'`  RIGHT: `contextcrawler find . -name '*.ts'`

Applies to: git, gh, glab, grep, find, ls, tree, cat (use `contextcrawler read`), head, tail, cargo, npm, pnpm, pytest, jest, vitest, tsc, docker, kubectl, aws, psql, dotnet, wget, wc, diff, log — every shell command.

Escape hatch only when contextcrawler genuinely cannot handle the command: `contextcrawler proxy <raw-command>`. Do not fall back to bare commands.

Before issuing any shell call, check: does it start with `contextcrawler `? If no, rewrite it.

## Meta commands

```bash
contextcrawler gain            # Token savings analytics
contextcrawler gain --history  # Recent command savings history
contextcrawler proxy <cmd>     # Run raw command without filtering
contextcrawler security        # Tirith defense-in-depth gate (if installed)
```

## Verification

```bash
contextcrawler --version
contextcrawler gain
which contextcrawler
```
