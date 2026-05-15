# Draft CHANGELOG entry — v0.1.6

Copy this into `CHANGELOG.md` (above the `[0.1.5]` section) when cutting
the v0.1.6 release. Bumped to a draft doc because the actual `CHANGELOG.md`
lives on `develop` and would conflict with the in-flight branches; this
keeps the narrative ready without forcing premature merges.

The narrative is intentionally framed as a **security-and-maintenance
release**: it follows directly on v0.1.5's three GHSAs by closing the
remaining surface from the 2026-05-15 audit. No new user-facing
features.

---

```markdown
## [0.1.6] — YYYY-MM-DD

Security and maintenance release. Closes 12 audit findings from the
2026-05-15 review (extending the three GHSAs from v0.1.5 plus
downstream-only findings on the web command, supply-chain integration,
filter trust model, and tirith gate). Adds the long-term-maintenance
framework: threat model, release runbook, upstream-rebase strategy,
quality baselines, three per-module security audits, and a roadmap.

### Security

- **Build-host metadata stripped from release binaries.** Previously
  the release binary embedded ~284 `/Users/<builder>/.cargo/registry/...`
  paths used by Rust's panic-backtrace metadata, leaking the builder's
  username and directory layout. `scripts/build-release.sh` now sets
  `--remap-path-prefix` for `$CARGO_HOME` and the workspace; `--verify`
  mode asserts zero builder paths in the produced binary.

- **`strip_ansi` extended + raw-emit sweep.** `strip_ansi` already
  covered CSI; v0.1.5 added OSC / OSC 8 hyperlinks / DCS / SOS / PM /
  APC / private DEC modes. v0.1.6 sweeps 58 raw `eprint!`/`println!`
  sites across 9 files (`cmds/git/`, `cmds/cloud/`, `cmds/js/`,
  `cmds/python/`, `cmds/dotnet/`, `cmds/system/grep_cmd.rs`,
  `cmds/go/`, `core/runner.rs`) so failure-path tool output goes
  through the sanitiser before reaching the agent.

- **Global TOML filter trust gate (H-3).** `~/.config/rtk/filters.toml`
  was previously loaded with no integrity check while the project-local
  `.rtk/filters.toml` was SHA-256-pinned. Closed: same trust store,
  same content-change-revokes semantics. New CLI: `contextcrawler
  trust --global` / `untrust --global`. Plus a TOCTOU fix
  (`check_trust_bytes` works on the already-read buffer instead of
  re-opening the path between hash and parse).

- **CI trust-override now requires platform-injected token (H-2).**
  `RTK_TRUST_PROJECT_FILTERS=1` previously trusted any env that set
  `CI=true` (settable by a hostile Makefile). Tightened to also require
  a platform-injected token (`GITHUB_TOKEN`, `CI_JOB_TOKEN`,
  `BUILDKITE_AGENT_ACCESS_TOKEN`, `JENKINS_NODE_COOKIE`/`BUILD_TAG`,
  `CIRCLE_TOKEN`/`CIRCLE_BUILD_NUM`, `DRONE_BUILD_NUMBER`). An in-repo
  Makefile can't fake these.

- **Tirith subprocess hardening (F-01 / F-02 / F-04 / F-05).**
  - `wait_timeout(8s)` so a hung `tirith check` no longer freezes the
    agent's PreToolUse hook (was indefinite).
  - 4 MiB stdout cap.
  - `Stdio::null()` on stdin and stderr — the stderr pipe was never
    drained, so a noisy tirith could fill the 64 KiB kernel buffer
    and stall the wait_timeout until it fired.
  - JSON re-canonicalisation in `log_downgrade` before embedding in
    `downgrades.jsonl` — closes a log-injection vector where a
    hostile tirith could emit literal newlines to forge a top-level
    log record. Sentinel-on-parse-failure keeps the line valid JSON.
  - Same subprocess pattern applied to the `security_cmd` dashboard
    (`fetch_audit_stats`, `fetch_doctor_status`).
  - New dep: `wait-timeout = "0.2"`.

- **Web command hardening (F-01 / F-02 / F-03 / F-04 / F-07).**
  `contextcrawler web` now:
  - parses the URL with the `url` crate, rejects non-http(s)
    schemes (closes `file:///etc/passwd` local-read);
  - resolves the host and refuses if any resolved IP is in a blocked
    range (loopback / link-local / RFC1918 / ULA / CGN / multicast /
    unspecified / 0.0.0.0/8 / 198.18/15 benchmark / 240/4 future-use,
    plus IPv4-mapped-private-in-IPv6, plus Azure metadata
    168.63.129.16, plus AWS metadata 169.254.169.254 via link-local);
  - pins the validated IPs into curl via `--resolve` so curl can't
    independently re-resolve to a private IP between our check and
    the fetch (DNS-rebinding defence);
  - caps curl at `--max-time 30`, `--max-filesize 64 MiB`,
    `--max-redirs 10`;
  - uses `--` to terminate flag parsing before the URL;
  - wraps stderr in `strip_ansi`.
  - New dep: `url = "2"`.
  - Residual: multi-host-redirect (`other.example` after a redirect
    re-resolves DNS) tracked for v0.2.0.

### Process & docs

- **Threat model**: new `docs/security/THREAT_MODEL.md`. Documents
  assets, attack surfaces, threat actors, mitigations matrix,
  accepted limitations.

- **Module audits**: per-file security audits for `supply_chain_gate.rs`
  (6 findings, no High/Critical), `tirith_gate.rs` (5 findings,
  closed), `Commands::Web` dispatch + `web_cmd.rs` (6 findings,
  closed), and combined `jsonl_rewriter` + `session_compact_cmd`
  + `security_cmd` (3 Mediums, 6 LOW/INFO). Subprocess-timeout
  class-audit conclusion in `AUDIT_subprocess_timeout_class.md`.

- **Quality baselines**: `docs/quality/BASELINE.md` snapshots test
  count, clippy state, `cargo audit` result, unsafe blocks, unwrap
  distribution. `deny.toml` covers advisories, licenses, bans,
  sources (passes `cargo deny check`).

- **Release & rebase docs**: `docs/contributing/RELEASING.md`
  (end-to-end runbook) + `docs/contributing/UPSTREAM_REBASE.md`
  (rtk-ai/rtk tracking strategy, what-to-take-vs-skip matrix,
  conflict resolution for hardened paths).

- **Roadmap**: `docs/ROADMAP.md` — v0.1.x line, v0.2.0 candidates
  organised into security/process/capability buckets, tracking
  model.

- **Session record**: `docs/sessions/2026-05-15-overnight.md` —
  branch-by-branch summary with Codex round results and merge order.

### Build & infrastructure

- `rust-version = "1.80"` MSRV declared in Cargo.toml (covers
  `Ipv6Addr::to_ipv4_mapped` used by the SSRF block check).
- New scripts: `scripts/build-release.sh` (with `--verify` and
  `--install` modes), `scripts/bump-version.sh`.
- Proposed CI jobs documented in `docs/quality/CI_JOBS_PROPOSED.md`
  (release-leak gate + `cargo deny check`). Wire in when the
  `.github/` gitignore situation is resolved.

### Tests

1845+ passed across the merged tree (was 1828 at v0.1.5). 32 new
regression tests for argv-mode guard / OSC stripping / scrub /
SSRF block / CI trust check / JSONL canonicalisation.

### Acknowledgements

Three rounds of Codex peer review on each fix branch. Every
finding tracked, every fix verified. Methodology lessons in
`feedback_verify_code_not_subjects.md` (project memory).
```

---

## Notes for the release maintainer

- **Don't forget the README bump**. `scripts/bump-version.sh 0.1.6`
  handles `src/main.rs::CONTEXTCRAWLER_VERSION` and the README
  install lines.

- **Codex round outcomes** to mention in the release tweet / PR if
  publishing publicly: 17 distinct review-pass dispatches across
  12 branches; 4 placeholder returns required re-dispatch; every
  fix branch reached Codex-clean status before merge.

- **GHSA publication**: the three existing draft advisories
  (GHSA-3mmh-86cm-g6w4, GHSA-wjx4-ffxm-fxxp, GHSA-2cwv-rr7c-2p4c)
  cover most of this. The new branches don't currently have GHSAs —
  decide whether to amend the existing three or file new ones for
  the additional findings (H-3, H-2, tirith F-01/F-04, web F-01/F-02,
  build-path leak, analytics F-01).

- **One follow-up after merge**: the THREAT_MODEL.md "accepted
  limitations" section still lists H-2 and H-3 as accepted; they're
  now closed in code. Update the doc when the merge train lands.
