<p align="center">
  <img src="docs/assets/logo.png" alt="ContextCrawler — Princess Donut says: Dammit Claude!" width="480">
</p>

# ContextCrawler

> [!WARNING]
> **Active development. Might work, might not. Use at your own risk.**
>
> This is a fast-moving downstream fork by one person. Before depending on
> it: build it yourself, test it against your own workflow, read the diff
> on top of upstream rtk, and run the code through your favourite LLM for
> a second opinion (why not). **Don't trust me — verify.** Bug reports
> welcome; expectations of stability shouldn't be.

A downstream distribution of [rtk-ai/rtk](https://github.com/rtk-ai/rtk)
that brings the [jee599/contextzip](https://github.com/jee599/contextzip)
feature set forward to current rtk and stitches in
[Tirith](https://tirith.sh) for defense-in-depth on the auto-allow path.

One binary, one name: **`contextcrawler`**.

## Goal

Make AI coding agents both **cheaper** and **safer** without changing how
you work:

- **Cheaper** — compress noisy command output before it eats your LLM
  context window. Inherits rtk's 60+ command filters, adds session-log
  compaction, HTML extraction, multi-language stacktrace compression.
- **Safer** — when an agent proposes a shell command, run it past two
  optional gates before auto-approving: shell-syntax inspection (Tirith)
  and pre-install supply-chain checks (package age + OSV CVE lookup).
  Neither is mandatory; both are opt-in.

If you were using `jee599/contextzip` and want the same features but on
**current rtk**, this is the migration path.
[`MIGRATING_FROM_CONTEXTZIP.md`](MIGRATING_FROM_CONTEXTZIP.md) walks
you through it.

## Features at a glance

| Command | Purpose |
|---|---|
| `contextcrawler <git / cargo / npm / ...>` | Drop-in for everyday rtk-style filtering — 60+ command filters inherited from upstream. |
| `contextcrawler web <url>` | Fetch a URL and strip HTML chrome (nav, ads, scripts). ~86% byte savings on typical landing pages. |
| `contextcrawler sessions compact <id>` / `apply` / `expand` | Compact / promote / rollback Claude Code session-JSONL logs. Sidecar-based; never touches the original. |
| `contextcrawler security` | Tirith integration dashboard — audit stats, gate mode, shell-hook status, top detection rules. |
| `contextcrawler security log` | Merged gate-activity log (Tirith downgrades + supply-chain events), human-readable. `--json` for tooling. |
| `contextcrawler supply-chain check '<cmd>'` | Inspect an install command for recent uploads + known CVEs. Opt-in via config. |
| `contextcrawler hook claude` / `cursor` / `copilot` / `gemini` | Built-in agent-hook entrypoints. Configured by `contextcrawler init -g`. |
| `contextcrawler gain` | Token-savings stats. Preserves your existing `contextzip` SQLite DB. |
| `contextcrawler init -g` | Register with Claude Code (and other agents via `--agent`). |
| Multi-language stacktrace compression | Wired into the runner pipeline. Detects framework frames in Node / Python / Rust / Go / Java tracebacks and drops them. Automatic. |
| Tirith pre-execution gate | Optional. When Tirith is installed, auto-allow rewrites are routed through `tirith check` first. Block-level findings downgrade to *Ask*. Fail-open by default. |
| Supply-chain pre-install gate | Optional. Refuses to auto-allow `npm install foo` or `pip install foo` when the resolved version is younger than a configurable cooldown (default 3d) or carries OSV-known CVEs. Honors pinned versions. |

## Diagrams

Click each section to expand. All diagrams are top-to-bottom Mermaid;
GitHub renders them inline.

<details>
<summary><strong>1. Project lineage — where each piece comes from</strong></summary>

```mermaid
flowchart TB
    RTK["rtk-ai/rtk<br/>(Apache-2.0 / MIT)<br/>v0.39.0 core<br/>+ 60+ command filters"]
    CZIP["jee599/contextzip<br/>(MIT)<br/>session compactor<br/>error_cmd, web_cmd"]
    TIRITH["sheeki03/tirith<br/>(AGPL-3.0)<br/>shell-command<br/>security gate"]

    FORK["rtk fork branch:<br/>contextzip-downstream<br/>sentinel-blocked patches"]
    PATCHES["Downstream modules:<br/>supply_chain_gate<br/>tirith_gate<br/>security_cmd<br/>session_compact_cmd<br/>web_cmd · error_cmd"]
    BIN["<code>contextcrawler</code><br/>single Rust binary"]
    USERS["You / Claude / Cursor /<br/>Copilot / Gemini / OpenCode"]

    RTK -- "git rebase" --> FORK
    CZIP -- "ported MIT source<br/>(SPDX headers)" --> PATCHES
    FORK --> BIN
    PATCHES --> BIN
    TIRITH -. "subprocess only<br/>(no AGPL link)" .-> BIN
    BIN --> USERS

    classDef upstream fill:#1a1a2e,stroke:#888,color:#ddd
    classDef ours fill:#2a0a2e,stroke:#e83e8c,color:#fff
    class RTK,CZIP,TIRITH upstream
    class FORK,PATCHES,BIN ours
```

</details>

<details>
<summary><strong>2. Runtime flow — what happens when an agent proposes a command</strong></summary>

```mermaid
flowchart TB
    AGENT["Claude / Cursor /<br/>Copilot / Gemini"]
    AGENT -- "Bash tool call" --> HOOK["contextcrawler hook &lt;agent&gt;"]

    HOOK --> RW{"rtk-style<br/>rewrite available?"}
    RW -- "no" --> PASS["pass through<br/>(agent's normal prompt)"]
    RW -- "yes" --> VERDICT{"user's<br/>allow / ask / deny<br/>rules"}

    VERDICT -- "deny" --> DENY["Claude Code<br/>native deny prompt"]
    VERDICT -- "ask / default" --> ASK["rewrite + ask<br/>(user reviews)"]
    VERDICT -- "allow" --> TIRITH_GATE{"Tirith gate<br/>(if installed)"}

    TIRITH_GATE -- "block" --> ASK
    TIRITH_GATE -- "allow / unavailable" --> SC_GATE{"Supply-chain gate<br/>(if enabled +<br/>install detected)"}

    SC_GATE -- "block<br/>(age / CVE)" --> ASK
    SC_GATE -- "allow / skip" --> AUTO["auto-allow<br/>permissionDecision: allow"]

    AUTO --> RUN["command runs<br/>through rtk's filters"]
    RUN --> OUTPUT["compressed output<br/>back to agent"]

    classDef gate fill:#2a0a2e,stroke:#e83e8c,color:#fff
    classDef terminal fill:#1a1a2e,stroke:#888,color:#ddd
    class TIRITH_GATE,SC_GATE gate
    class DENY,ASK,AUTO terminal
```

</details>

## Install

```sh
git clone https://github.com/thehoff/contextcrawler.git contextzip
cd contextzip
cargo build --release --manifest-path rtk-fork/Cargo.toml
cp rtk-fork/target/release/contextcrawler ~/.local/bin/contextcrawler

# Hook into Claude Code (and other agents — see `contextcrawler init --help`)
contextcrawler init -g

# Optional: defense-in-depth gate
# ContextCrawler shells out to `tirith` directly, so the binary on PATH
# is all the gate needs — no shell hook required.
cargo install tirith

# Optional separately: have Tirith also vet your own typed commands.
# eval "$(tirith init --shell zsh)"   # or bash / fish
```

Migrating from jee599/contextzip? See [`MIGRATING_FROM_CONTEXTZIP.md`](MIGRATING_FROM_CONTEXTZIP.md).

## Layout

```
contextZip/
├── rtk-fork/             # git clone of rtk-ai/rtk on branch contextzip-downstream
│                         #   atop v0.39.0. Carries small downstream patches.
├── notes/                # design notes + decision logs
├── CHANGELOG.md
├── MIGRATING_FROM_CONTEXTZIP.md
└── README.md             # this file
```

The rtk-fork uses a plain rebase model — every downstream commit lands
inside `// ===== contextzip-downstream =====` sentinel-block pairs in
`main.rs`, `runner.rs`, `rewrite_cmd.rs`, `hook_cmd.rs`, and a few hook
scripts, so upstream rebases stay confined to predictable lines.

## Track upstream

```sh
cd rtk-fork
git fetch origin
git rebase v0.40.0 contextzip-downstream   # resolve any sentinel conflicts
cargo build --release && cargo test --release
```

`git rerere` is enabled to auto-replay repeated conflict resolutions
across rebases.

## Defense-in-depth gate (optional Tirith pairing)

| | ContextCrawler | Tirith |
|---|---|---|
| Purpose | Shrink command output | Inspect commands |
| When | Post-execution filter | Pre-execution gate |
| Latency | ms–seconds | < 2 ms |

The gate calls `tirith check --format json` on any rewrite that would
auto-approve. When Tirith returns `action="block"`, the verdict is
downgraded to *Ask* so the user reviews the original command. The gate is
subprocess-only — no statically linked AGPL code.

```sh
contextcrawler security                  # human format
contextcrawler security --format json    # parseable
contextcrawler security --log            # tail recent gate downgrades
```

**Env knobs:**

| Variable | Effect |
|---|---|
| (default) | fail-open: if Tirith isn't installed, no gate, original rtk verdict stands |
| `CONTEXTCRAWLER_TIRITH_REQUIRED=1` | fail-closed: refuse auto-allow without a working Tirith verdict |
| `CONTEXTCRAWLER_TIRITH_DISABLED=1` | bypass the gate entirely (debug only) |

## License

The downstream parts of this repository are MIT.

- Upstream rtk-fork content remains under its original license terms (see
  `rtk-fork/LICENSE`). Note that upstream rtk's repo is internally
  inconsistent (`LICENSE` says Apache-2.0; `Cargo.toml` says MIT). We
  preserve those upstream files as-is.
- Source files we add or carry over carry per-file SPDX-License-Identifier
  headers citing their origin (jee599/contextzip MIT for ported modules;
  ContextCrawler contributors MIT for new additions).
- Tirith is AGPL-3.0 and is **only invoked via subprocess**; no statically
  linked AGPL code in this distribution.

## Attribution

- [rtk-ai/rtk](https://github.com/rtk-ai/rtk) — upstream base. Active,
  47K stars, current release v0.39.0. ContextCrawler tracks their tagged
  releases.
- [jee599/contextzip](https://github.com/jee599/contextzip) — source of the
  session compactor, stacktrace compressor, and HTML extractor. Each
  carried-over file has a per-file SPDX header citing this upstream.
- [sheeki03/tirith](https://github.com/sheeki03/tirith) — invoked via
  subprocess for the optional defense-in-depth gate.

## Status

v0.1.0 — first community release. See [`CHANGELOG.md`](CHANGELOG.md).
