#!/usr/bin/env bash
# rtk-hook-version: 3
# ContextCrawler Claude Code hook — rewrites commands to use contextcrawler for token savings.
# Requires: contextcrawler >= 0.23.0, jq
#
# This is a thin delegating hook: all rewrite logic lives in `contextcrawler rewrite`,
# which is the single source of truth (src/discover/registry.rs).
# To add or change rewrite rules, edit the Rust registry — not this file.
#
# Exit code protocol for `contextcrawler rewrite`:
#   0 + stdout  Rewrite found, no deny/ask rule matched → auto-allow
#   1           No RTK equivalent → pass through unchanged
#   2           Deny rule matched → pass through (Claude Code native deny handles it)
#   3 + stdout  Ask rule matched → rewrite but let Claude Code prompt the user

if ! command -v jq &>/dev/null; then
  echo "[contextcrawler] WARNING: jq is not installed. Hook cannot rewrite commands. Install jq: https://jqlang.github.io/jq/download/" >&2
  exit 0
fi

if ! command -v contextcrawler &>/dev/null; then
  echo "[contextcrawler] WARNING: contextcrawler is not installed or not in PATH. Hook cannot rewrite commands. Install: https://github.com/thehoff/contextcrawler#install" >&2
  exit 0
fi

# Version guard: contextcrawler rewrite was added in 0.23.0.
# Older binaries: warn once and exit cleanly (no silent failure).
# Cache the version check to avoid spawning multiple processes on every hook call.
CACHE_DIR=${XDG_CACHE_HOME:-$HOME/.cache}
# ContextCrawler downstream: dropped the upstream version guard.
# Upstream's logic parsed `rtk <ver>` output to enforce rtk >= 0.23.0; our
# --version banner format doesn't match that shape, and ContextCrawler
# always ships against a recent rtk core. The hook simply requires the
# binary to be present; the binary itself enforces its own minimums.
:

INPUT=$(cat)
CMD=$(jq -r '.tool_input.command // empty' <<<"$INPUT")

if [ -z "$CMD" ]; then
  exit 0
fi

# Delegate all rewrite + permission logic to the Rust binary.
REWRITTEN=$(contextcrawler rewrite "$CMD" 2>/dev/null)
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    # Rewrite found, no permission rules matched — safe to auto-allow.
    # If the output is identical, the command was already using RTK.
    [ "$CMD" = "$REWRITTEN" ] && exit 0
    ;;
  1)
    # No RTK equivalent — pass through unchanged.
    exit 0
    ;;
  2)
    # Deny rule matched — let Claude Code's native deny rule handle it.
    exit 0
    ;;
  3)
    # Ask rule matched — rewrite the command but do NOT auto-allow so that
    # Claude Code prompts the user for confirmation.
    ;;
  *)
    exit 0
    ;;
esac

if [ "$EXIT_CODE" -eq 3 ]; then
  # Ask: rewrite the command, omit permissionDecision so Claude Code prompts.
  jq -c --arg cmd "$REWRITTEN" \
    '.tool_input.command = $cmd | {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": .tool_input
      }
    }' <<<"$INPUT"
else
  # Allow: rewrite the command and auto-allow.
  jq -c --arg cmd "$REWRITTEN" \
    '.tool_input.command = $cmd | {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "ContextCrawler auto-rewrite",
        "updatedInput": .tool_input
      }
    }' <<<"$INPUT"
fi
