# ContextCrawler (Kilo Code)

**Usage**: Token-optimized CLI proxy for shell commands. Downstream of
[rtk-ai/rtk](https://github.com/rtk-ai/rtk).

## Rule

Always prefix shell commands with `contextcrawler` to minimize token consumption.

Examples:

```bash
contextcrawler git status
contextcrawler cargo test
contextcrawler ls src/
contextcrawler grep "pattern" src/
contextcrawler find "*.rs" .
contextcrawler docker ps
contextcrawler gh pr list
```

## Meta commands

```bash
contextcrawler gain              # Show token savings
contextcrawler gain --history    # Command history with savings
contextcrawler discover          # Find missed proxy opportunities
contextcrawler proxy <cmd>       # Run raw (no filtering, for debugging)
contextcrawler security          # Tirith defense-in-depth gate (if installed)
```

## Why

ContextCrawler filters and compresses command output before it reaches the
LLM context, saving 60-90% tokens on common operations.
