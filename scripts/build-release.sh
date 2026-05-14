#!/usr/bin/env bash
# Builds a release binary with absolute build paths stripped so the produced
# binary does not embed the builder's $HOME / $CARGO_HOME / workspace path.
#
# Without this, panic backtrace metadata embeds strings like:
#   /Users/<builder>/.cargo/registry/src/.../serde-1.0.228/src/private/de.rs
# which leak the build host's username and directory layout.
#
# Usage:
#   scripts/build-release.sh                # builds, leaves binary at target/release/contextcrawler
#   scripts/build-release.sh --install      # additionally copies to ~/.local/bin/contextcrawler
#   scripts/build-release.sh --verify       # additionally asserts no build paths leaked
#
# CI calls this with --verify before publishing a release artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

INSTALL=0
VERIFY=0
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        --verify)  VERIFY=1 ;;
        --help|-h)
            sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# Resolve CARGO_HOME the same way cargo itself does — env override or default.
CARGO_HOME_REAL="${CARGO_HOME:-$HOME/.cargo}"
WORKSPACE_REAL="$REPO_ROOT"

# Stable rustc flag. Format: --remap-path-prefix=FROM=TO.
# - $CARGO_HOME → /cargo so dependency source paths become /cargo/registry/...
# - $WORKSPACE  → /src so panic file:line refs in our own code become /src/...
# Order matters: longer/more-specific prefixes first.
export RUSTFLAGS="${RUSTFLAGS:-} \
    --remap-path-prefix=${CARGO_HOME_REAL}=/cargo \
    --remap-path-prefix=${WORKSPACE_REAL}=/src"

echo "[build-release] CARGO_HOME=${CARGO_HOME_REAL} -> /cargo"
echo "[build-release] WORKSPACE =${WORKSPACE_REAL} -> /src"

# Single source of truth: cargo build --release respects RUSTFLAGS.
cargo build --release

BIN="target/release/contextcrawler"

if [[ $VERIFY -eq 1 ]]; then
    echo "[build-release] verifying no builder paths leaked..."
    # Allow strings under /Users/dev/... which are test fixture data baked into
    # the binary (CompileSwift / etc test fixture strings) — those are not from
    # the build environment.
    # grep returns 1 when no matches, which combined with set -e/pipefail would
    # abort the success path. Run inside a subshell that swallows the exit code.
    LEAK_COUNT=$( (strings "$BIN" \
        | grep -E "${HOME}|${CARGO_HOME_REAL}|${WORKSPACE_REAL}" \
        | grep -vE '/Users/dev/' \
        | wc -l \
        | tr -d ' ') || true )
    LEAK_COUNT="${LEAK_COUNT:-0}"
    if [[ "$LEAK_COUNT" -ne 0 ]]; then
        echo "[build-release] FAIL: ${LEAK_COUNT} builder paths still embedded:" >&2
        strings "$BIN" \
            | grep -E "${HOME}|${CARGO_HOME_REAL}|${WORKSPACE_REAL}" \
            | grep -vE '/Users/dev/' \
            | head -10 >&2
        exit 1
    fi
    echo "[build-release] ok — no builder paths in binary"
fi

if [[ $INSTALL -eq 1 ]]; then
    mkdir -p "$HOME/.local/bin"
    cp "$BIN" "$HOME/.local/bin/contextcrawler"
    echo "[build-release] installed to ~/.local/bin/contextcrawler"
fi

echo "[build-release] done -> $BIN"
