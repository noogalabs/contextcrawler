# Copilot Instructions for ContextCrawler

**ContextCrawler** is a CLI proxy that filters and compresses command outputs
before they reach an LLM context, saving 60-90% of tokens. It wraps common
tools (`git`, `cargo`, `grep`, `pnpm`, `go`, etc.) and outputs condensed
summaries instead of raw output. Downstream of
[rtk-ai/rtk](https://github.com/rtk-ai/rtk).

## Using ContextCrawler in this session

**Always prefix commands with `contextcrawler` when running shell commands** —
this reduces token consumption for every operation you perform.

```bash
# Instead of:              Use:
git status                 contextcrawler git status
git log -10                contextcrawler git log -10
cargo test                 contextcrawler cargo test
cargo clippy --all-targets contextcrawler cargo clippy --all-targets
grep -r "pattern" src/     contextcrawler grep -r "pattern" src/
```

**Meta-commands** (always use these directly, no prefix needed):
```bash
contextcrawler gain              # Token savings analytics
contextcrawler gain --history    # Per-command history with savings
contextcrawler discover          # Scan session history for missed opportunities
contextcrawler proxy <cmd>       # Run a command raw (no filtering) but still track it
contextcrawler security          # Tirith defense-in-depth gate (if installed)
```

**Verify ContextCrawler is installed before starting:**
```bash
contextcrawler --version
contextcrawler gain
```

## Build, Test & Lint

```bash
cargo build                    # Development build
cargo test                     # All tests
cargo test test_name           # Single test
cargo test -- --nocapture      # With stdout

# Pre-commit gate
cargo fmt --all --check && cargo clippy --all-targets && cargo test
```

PRs target the **`develop`** branch.

## Architecture

ContextCrawler routes CLI commands via a Clap `Commands` enum in `main.rs`
to specialized filter modules in `src/cmds/*/`, each executing the underlying
command and compressing output. Token savings are tracked in SQLite via
`src/core/tracking.rs`. Downstream additions (Tirith gate, supply-chain gate,
session compactor, stacktrace compressor, web extractor) live in
`src/hooks/` and `src/analytics/` behind `// ===== contextzip-downstream =====`
sentinel-block markers.

Module responsibilities are documented in each folder's `README.md` and each
file's `//!` doc header.

## Key Conventions

- **Error handling**: `anyhow::Result` with `.context("description")?` — no bare `?`, no `unwrap()` in production. Filters must fall back to raw command on error.
- **Regex**: Always `lazy_static!`, never compile inside a function body.
- **Testing**: Unit tests inside modules (`#[cfg(test)] mod tests`). Fixtures in `tests/fixtures/`. Token savings assertions with `count_tokens()`.
- **Exit codes**: Preserve the underlying command's exit code via `std::process::exit(code)`.
- **Performance**: Startup <10ms (no async runtime), binary <5MB stripped.
- **Downstream patches**: All ContextCrawler-specific edits to upstream rtk source files live inside `// ===== contextzip-downstream =====` sentinel-block pairs so upstream rebases stay confined to predictable lines.
