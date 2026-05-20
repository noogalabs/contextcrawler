# ContextCrawler (Codex CLI)

**Token-optimized CLI proxy for shell commands.** Downstream of [rtk-ai/rtk](https://github.com/rtk-ai/rtk). Reduces token cost 60–90% on read-heavy commands.

## REQUIRED RULE — shell-command prefix

You MUST prefix every shell tool invocation with `contextcrawler `. This is mandatory, not advisory.

- WRONG: `git status`                   RIGHT: `contextcrawler git status`
- WRONG: `git log -3 --oneline`         RIGHT: `contextcrawler git log -3 --oneline`
- WRONG: `git -C /path/to/repo status`  RIGHT: `contextcrawler git -C /path/to/repo status`
- WRONG: `grep -r foo src/`             RIGHT: `contextcrawler grep -r foo src/`
- WRONG: `rg -n foo src/`               RIGHT: `contextcrawler rg -n foo src/`
- WRONG: `cat README.md`                RIGHT: `contextcrawler read README.md`
- WRONG: `nl -ba src/main.rs`           RIGHT: `contextcrawler read -n src/main.rs`
- WRONG: `nl -ba file \| sed -n '10,40p'` RIGHT: `contextcrawler read -n --max-lines 40 src/main.rs` *(or `contextcrawler proxy sh -c 'nl -ba file | sed -n "10,40p"'` if you genuinely need a multi-range slice)*
- WRONG: `ls -la`                       RIGHT: `contextcrawler ls -la`
- WRONG: `find . -name '*.ts'`          RIGHT: `contextcrawler find . -name '*.ts'`

The `git -C <dir>`, `rg -n`, and `nl … | sed -n` patterns are common gaps — they look "different enough" that you might not register them as wrappable. They are. All three accept the `contextcrawler ` prefix.

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

## Security gate — write gate-safe commands

contextcrawler routes every command through the Tirith pre-execution gate. **Never pipe a downloader into an interpreter** — `curl … | python3` (also `| node`, `| sh`, `| bash`, `| ruby`, `| perl`) matches the `curl | bash` attack shape and the gate blocks it.

When fetching from a network endpoint and processing the result, write the response to a temp file and read it as a **data argument**:

```bash
resp=$(mktemp)                          # unique, mode 0600 — never a fixed /tmp path
trap 'rm -f "$resp"' EXIT               # response may carry tokens/PII
curl -sS --fail "$URL" -o "$resp" || exit 1
python3 parse.py "$resp"                # local script reads the file
```

- The interpreter runs your own local script with the downloaded file as a data argument. Never run the downloaded file as code (`python3 "$resp"`).
- To deliberately download and execute a script, use `tirith run <url>`.

When the gate blocks a legitimate command: `tirith why` (which rule fired), `tirith trust add <host> --scope repo --rule <rule_id>` (narrow allowlist), or `CONTEXTCRAWLER_TIRITH_DISABLED=1` (last resort: bypass the gate).
