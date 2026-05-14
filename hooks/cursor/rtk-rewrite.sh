#!/usr/bin/env bash
# rtk-hook-version: 1
# ContextCrawler Cursor Agent hook — rewrites shell commands to use contextcrawler for token savings.
# Works with both Cursor editor and cursor-cli (they share ~/.cursor/hooks.json).
# Cursor preToolUse hook format: receives JSON on stdin, returns JSON on stdout.
# Requires: contextcrawler >= 0.23.0, jq
#
# This is a thin delegating hook: all rewrite logic lives in `contextcrawler rewrite`,
# which is the single source of truth (src/discover/registry.rs).
# To add or change rewrite rules, edit the Rust registry — not this file.

if ! command -v jq &>/dev/null; then
  echo "[contextcrawler] WARNING: jq is not installed. Hook cannot rewrite commands. Install jq: https://jqlang.github.io/jq/download/" >&2
  exit 0
fi

if ! command -v contextcrawler &>/dev/null; then
  echo "[contextcrawler] WARNING: contextcrawler is not installed or not in PATH. Hook cannot rewrite commands. Install: https://github.com/thehoff/contextcrawler#install" >&2
  exit 0
fi

# ContextCrawler downstream: dropped the upstream version guard.
# (See hooks/claude/rtk-rewrite.sh for the rationale.)

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$CMD" ]; then
  echo '{}'
  exit 0
fi

# Delegate all rewrite logic to the Rust binary.
# contextcrawler rewrite exits 1 when there's no rewrite — hook passes through silently.
REWRITTEN=$(contextcrawler rewrite "$CMD" 2>/dev/null) || { echo '{}'; exit 0; }

# No change — nothing to do.
if [ "$CMD" = "$REWRITTEN" ]; then
  echo '{}'
  exit 0
fi

jq -n --arg cmd "$REWRITTEN" '{
  "permission": "allow",
  "updated_input": { "command": $cmd }
}'
