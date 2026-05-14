#!/usr/bin/env bash
# Bumps every ContextCrawler version reference in the repo. Run before
# `chore(release): vX.Y.Z` so the README install instructions, the
# CONTEXTCRAWLER_VERSION constant, and any other versioned surface move
# together.
#
# Usage: scripts/bump-version.sh 0.1.5

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <new-version>   (e.g. $0 0.1.5)" >&2
    exit 2
fi
NEW="$1"
# Strip leading 'v' if user typed v0.1.5.
NEW="${NEW#v}"

if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$ ]]; then
    echo "error: '$NEW' doesn't look like a semver version" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Pull the current version out of src/main.rs so we know what to replace.
OLD=$(grep -oE 'ContextCrawler [0-9]+\.[0-9]+\.[0-9]+' src/main.rs | head -1 | awk '{print $2}')
if [[ -z "$OLD" ]]; then
    echo "error: could not find current version in src/main.rs" >&2
    exit 1
fi
echo "bumping ${OLD} -> ${NEW}"

# 1. CONTEXTCRAWLER_VERSION in src/main.rs
sed -i.bak "s|ContextCrawler ${OLD}|ContextCrawler ${NEW}|" src/main.rs

# 2. README install lines: --tag vX.Y.Z and `git checkout vX.Y.Z`
sed -i.bak "s|--tag v${OLD}|--tag v${NEW}|g" README.md
sed -i.bak "s|git checkout v${OLD}|git checkout v${NEW}|g" README.md

# Clean up sed backups.
find . -maxdepth 2 -name '*.bak' -delete

# Sanity: confirm we left no stale references in tracked surfaces.
STALE=$(grep -nE "v${OLD}([^0-9]|$)|ContextCrawler ${OLD}" \
    src/main.rs README.md 2>/dev/null || true)
if [[ -n "$STALE" ]]; then
    echo "warning: stale ${OLD} references remain:" >&2
    echo "$STALE" >&2
    echo "(may be intentional history references — review by hand)" >&2
fi

echo "done. next steps:"
echo "  1. edit CHANGELOG.md — prepend a [${NEW}] section"
echo "  2. git add -p ; git commit -m 'chore(release): v${NEW}'"
echo "  3. git tag -a v${NEW} -m 'v${NEW}'"
echo "  4. git push contextcrawler develop v${NEW}"
