# ContextCrawler (Codex CLI)

**Usage**: Token-optimized CLI proxy for shell commands. Downstream of
[rtk-ai/rtk](https://github.com/rtk-ai/rtk).

## Rule

Always prefix shell commands with `contextcrawler`.

```bash
contextcrawler git status
contextcrawler cargo test
contextcrawler npm run build
contextcrawler pytest -q
```

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
