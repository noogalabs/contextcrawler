<!--
  CANONICAL ContextCrawler agent guidance — single source of truth.

  Every harness (Claude, Codex, Cursor, Windsurf, Cline, Kilocode,
  Antigravity, Gemini, Copilot, Hermes, OpenCode) renders its rules file
  from THIS file via `agent_guidance()` in src/hooks/init.rs. The per-agent
  title and "How commands are rewritten" paragraph are prepended there —
  do not add them here.

  Edit this file only. Never hand-edit a per-harness copy: the drift-guard
  test (init.rs) fails the build if a harness ships content that diverges
  from this source.
-->
**Token-optimised CLI proxy.** ContextCrawler wraps common shell commands
and filters their output before it reaches the model — cutting roughly
50-90% of the tokens on read-heavy operations (tests, builds, `git`,
search, package managers). Downstream of
[rtk-ai/rtk](https://github.com/rtk-ai/rtk) with the contextzip session
compactor, stacktrace compressor and HTML extractor folded in, plus an
opt-in Tirith defence-in-depth gate.

Savings vary by command: test and build filters reach 80-99%, `git`/search
and read-heavy commands 50-75%, and commands with already-compact output
pass through unchanged. Run `contextcrawler gain` for the measured figure
on your own usage.

## Meta commands (always invoke `contextcrawler` directly)

```bash
contextcrawler gain                 # Token savings analytics
contextcrawler gain --history       # Per-command savings history
contextcrawler gain --weak-filters  # Rank tools by leaked tokens (where filters underperform)
contextcrawler discover             # Find missed opportunities in session history
contextcrawler proxy <cmd>          # Run a raw command without filtering (for debugging)
contextcrawler security             # Tirith gate dashboard (if installed)
contextcrawler security log         # Recent gate downgrade events
```

## Installation verification

```bash
contextcrawler --version
contextcrawler gain                 # Should show stats, not "command not found"
which contextcrawler
```

## Security gate — write gate-safe commands

ContextCrawler routes every command through the Tirith pre-execution
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
