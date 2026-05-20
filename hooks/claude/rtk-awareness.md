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

## Security gate — write gate-safe commands

contextcrawler routes every command through the Tirith pre-execution
gate. **Never pipe a downloader into an interpreter** — `curl … | python3`
(also `| node`, `| sh`, `| bash`, `| ruby`, `| perl`) matches the
`curl | bash` attack shape and the gate blocks it.

When fetching from a network endpoint and processing the result, write
the response to a temp file and read it as a **data argument**:

```bash
resp=$(mktemp)                          # unique, mode 0600 — never a fixed /tmp path
trap 'rm -f "$resp"' EXIT               # response may carry tokens/PII
curl -sS --fail "$URL" -o "$resp" || exit 1
python3 parse.py "$resp"                # local script reads the file
```

- The interpreter runs your own local script with the downloaded file as
  a data argument. Never run the downloaded file as code (`python3 "$resp"`).
- To deliberately download and execute a script, use `tirith run <url>`.

When the gate blocks a legitimate command:

```bash
tirith why                          # which rule fired, and why
tirith trust add <host> --scope repo --rule <rule_id>   # narrow allowlist
CONTEXTCRAWLER_TIRITH_DISABLED=1     # last resort: bypass the gate entirely
```
