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

# Reject path values that would break RUSTFLAGS tokenisation (rustflags is a
# whitespace-delimited string; a path with spaces or shell-sensitive chars
# could inject extra rustc args). This is paranoid but cheap.
for v in "$HOME" "$CARGO_HOME_REAL" "$WORKSPACE_REAL"; do
    if [[ "$v" =~ [[:space:]\"\$\`\\] ]]; then
        echo "error: path '$v' contains whitespace or shell-special characters;" >&2
        echo "       refusing to build (would break RUSTFLAGS tokenisation)." >&2
        exit 1
    fi
done

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
    if [[ ! -f "$BIN" ]]; then
        echo "error: $BIN does not exist (cargo build above must have failed?)" >&2
        exit 1
    fi
    if ! command -v strings >/dev/null 2>&1; then
        echo "error: 'strings' binary not found; cannot run leak verification" >&2
        exit 1
    fi

    # Build fixed-string match files. grep -F treats every line as a literal,
    # so path metacharacters (., -, +, brackets) don't matter.
    PREFIXES_FILE=$(mktemp)
    FIXTURE_TOKENS_FILE=$(mktemp)
    trap 'rm -f "$PREFIXES_FILE" "$FIXTURE_TOKENS_FILE"' EXIT
    printf '%s\n' "$HOME" "$CARGO_HOME_REAL" "$WORKSPACE_REAL" > "$PREFIXES_FILE"
    # Test-fixture strings that contain /Users/dev/ as part of literal data
    # embedded by src/filters/xcodebuild.toml (CompileSwift / CodeSign /
    # ViewController.swift / App.swift / etc.) and src/cmds/dotnet/binlog.rs
    # (.binlog Microsoft.Build paths). These tokens are highly specific —
    # they won't appear in actual build-host metadata, so a real leak from a
    # builder whose $HOME happens to be /Users/dev/ would still be flagged.
    cat > "$FIXTURE_TOKENS_FILE" <<'EOF'
CompileSwift
CodeSign
ViewController.swift
AppDelegate.swift
Model.swift
Main.swift
Tests.swift
Microsoft.Build
.binlog
EOF

    # Count leaks: strings | (matches a real builder prefix) | (NOT matching a
    # known fixture token). pipefail off locally so grep's exit-1 (no matches)
    # doesn't kill the script — exit-2+ (real error) still surfaces because
    # we re-check via `set -e` outside the block.
    set +o pipefail
    LEAK_COUNT=$(strings "$BIN" \
        | grep -F -f "$PREFIXES_FILE" \
        | grep -vF -f "$FIXTURE_TOKENS_FILE" \
        | wc -l \
        | tr -d ' ')
    PIPELINE_STATUS=${PIPESTATUS[0]:-0}
    set -o pipefail

    if [[ "$PIPELINE_STATUS" -ne 0 ]]; then
        echo "error: 'strings $BIN' failed with exit $PIPELINE_STATUS" >&2
        exit 1
    fi
    LEAK_COUNT="${LEAK_COUNT:-0}"

    if [[ "$LEAK_COUNT" -ne 0 ]]; then
        echo "[build-release] FAIL: ${LEAK_COUNT} builder paths still embedded:" >&2
        strings "$BIN" \
            | grep -F -f "$PREFIXES_FILE" \
            | grep -vF -f "$FIXTURE_TOKENS_FILE" \
            | head -10 >&2
        exit 1
    fi
    echo "[build-release] ok — no builder paths in binary"
fi

if [[ $INSTALL -eq 1 ]]; then
    DEST="$HOME/.local/bin/contextcrawler"
    mkdir -p "$HOME/.local/bin"
    cp "$BIN" "$DEST"

    # macOS Apple Silicon: a plain `cp` of an ad-hoc-linker-signed binary
    # produces a destination that AMFI rejects at exec with
    # `load code signature error 2` / `ASP: Security policy would not allow
    # process`, killing the process with SIGKILL (exit 137). Re-applying the
    # ad-hoc signature on the copied file fixes it. `cargo install` does this
    # itself; our `cp` does not, so we do it here.
    #
    # This is a no-op on Linux (no codesign binary, no AMFI). The macOS
    # check is conservative — codesign exists on every modern macOS install,
    # so we only need to gate on uname.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if command -v codesign >/dev/null 2>&1; then
            codesign --force --sign - "$DEST" 2>&1 | sed 's/^/[build-release] codesign: /'
        else
            echo "[build-release] warning: codesign not found, install may fail AMFI on launch" >&2
        fi
    fi
    echo "[build-release] installed to ~/.local/bin/contextcrawler"
fi

echo "[build-release] done -> $BIN"
