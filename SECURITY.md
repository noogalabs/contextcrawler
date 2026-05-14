# Security Policy

## Reporting a Vulnerability in ContextCrawler

If you discover a security vulnerability in ContextCrawler, please report it
**privately** — do not file a public issue.

### Preferred channel: GitHub Security Advisories

Open a private security advisory at:

**<https://github.com/thehoff/contextcrawler/security/advisories/new>**

GitHub will route the report directly to the maintainer and start a private
collaboration thread.

### Fallback channel: email

If you can't use GitHub's advisory flow, email:

**contextcrawler@thehoff.id.au**

Please include:

- A clear description of the issue and its impact
- Reproduction steps (a minimal PoC if possible)
- The affected version(s) — `contextcrawler --version`
- Your preferred attribution name / handle for the eventual public advisory

### What to expect

- **Acknowledgment**: within 72 hours (often faster).
- **Triage**: a few business days after acknowledgment. I'll let you know
  whether the report is in scope, what the severity looks like, and the
  rough fix timeline.
- **Coordinated disclosure**: 90-day embargo by default. I'll work with
  you on a public advisory and credit you (with permission) once a fix is
  available.

### Please do NOT

- Open a public GitHub issue describing the vulnerability.
- Disclose the issue on social media, forums, or a public blog before a
  coordinated disclosure has happened.
- Run automated scans or pentest tools against third parties' deployments
  of ContextCrawler without explicit permission.

---

## Upstream vulnerabilities

ContextCrawler is a downstream distribution of
[`rtk-ai/rtk`](https://github.com/rtk-ai/rtk). If a vulnerability looks
like it lives in upstream rtk's code (anywhere outside the
`// ===== contextzip-downstream =====` sentinel blocks), please **also**
report it to upstream's security channel — that fix benefits the broader
rtk ecosystem and ContextCrawler will inherit it on the next rebase.

Upstream contact details are in
[`docs/upstream/RTK_README.md`](docs/upstream/RTK_README.md) and the
upstream repo's own `SECURITY.md`.

---

## Tirith integration

ContextCrawler ships an optional pre-execution gate that calls
[`tirith`](https://github.com/sheeki03/tirith) as a subprocess. Tirith's
own security disclosures are handled by the Tirith project; if your
report concerns Tirith specifically, please route to upstream tirith.

If the issue is in *how ContextCrawler integrates with Tirith* (e.g., a
way to bypass our gate), that's in scope here — report via the channels
above.

---

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |
| < 0.1   | ❌ (pre-release; do not use) |

---

## Scope

In scope:

- The `contextcrawler` binary and any of its subcommands
- Hook scripts under `hooks/`
- Build / install / update paths
- The Tirith pre-execution gate logic (anything inside the
  `// ===== contextzip-downstream =====` sentinel blocks)
- Dependencies pinned by `Cargo.toml` / `Cargo.lock`

Out of scope:

- Issues in upstream rtk that aren't materially worsened by our
  downstream additions (please report those to rtk-ai/rtk).
- Issues in Tirith itself (report to sheeki03/tirith).
- Configuration mistakes a user makes in their own Claude Code /
  agent settings.
- DoS via running ContextCrawler with extremely large inputs locally —
  it's a single-user CLI.

---

## Trust boundary for command-string subcommands

`contextcrawler err`, `contextcrawler test`, and `contextcrawler summary`
accept a free-form command string (`trailing_var_arg`). By default this
string is **parsed as argv and executed without a shell**:

- Shell metacharacters (`|`, `;`, `&`, `<`, `>`, backtick, `$`, newline)
  cause the command to be rejected outright.
- The first token must not be:
  - a shell binary — `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`,
    `tcsh`, `csh`, `ash`, with their `.exe` Windows variants; `cmd`,
    `cmd.exe`, `powershell`, `powershell.exe`, `pwsh`, `pwsh.exe`; or
    multi-tool shells `busybox`, `toybox`;
  - an exec wrapper that replaces the process image with `arg[1+]` —
    `env`, `nice`, `nohup`, `time`, `timeout`, `gtimeout`, `ionice`,
    `chroot`, `setpriv`, `unshare`, `taskset`, `stdbuf`, `script`,
    `xargs`, `watch`, `sudo`, `doas`. Without this, an agent could
    bypass the shell guard via `env sh -c '<payload>'`.

  Match is basename-only and case-insensitive (so `/usr/bin/bash` and
  `BASH.EXE` both trip). Tradeoff: a legitimate binary coincidentally
  named `sh` / `bash` / `env` / etc. cannot be invoked through these
  subcommands in argv mode. Use `--shell` if you have such a case;
  document it in your project's setup.

This guards against a prompt-injection → shell-injection chain where an
agent rewrites a user's `cargo test` into something like
`cargo test; <payload>`. In the default mode that string never reaches
`sh -c` and the agent gets a clear error instead of a silently widened
command.

Users who want pipes, redirects, or chained commands must pass
`--shell` explicitly. That opt-in restores the original `sh -c`
semantics and is the documented trust boundary: agent-rewritten input
should not carry `--shell`.

Tracked by [GHSA-3mmh-86cm-g6w4](https://github.com/thehoff/contextcrawler/security/advisories/GHSA-3mmh-86cm-g6w4).

---

## Acknowledgements

We will credit security researchers in the published advisory and the
project changelog, with their permission.
