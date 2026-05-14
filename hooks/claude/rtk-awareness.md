# ContextCrawler

**Usage**: Token-optimized CLI proxy (60-90% savings on dev operations).
Downstream of [rtk-ai/rtk](https://github.com/rtk-ai/rtk) with the
contextzip session compactor + stacktrace compressor + HTML extractor
folded in, plus an opt-in Tirith defense-in-depth gate.

## Meta commands (always use contextcrawler directly)

```bash
contextcrawler gain              # Token savings analytics
contextcrawler gain --history    # Command history with savings
contextcrawler discover          # Find missed rtk opportunities in session history
contextcrawler proxy <cmd>       # Run raw command without filtering
contextcrawler security          # Tirith gate dashboard (if installed)
contextcrawler security log      # Recent gate downgrade events
```

## Installation verification

```bash
contextcrawler --version
contextcrawler gain              # Should show stats, not "command not found"
which contextcrawler
```

## Hook-based usage

All other commands are rewritten automatically by the Claude Code hook.
Example: `git status` → `contextcrawler git status` (transparent, 0 tokens overhead).
