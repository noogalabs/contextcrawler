# Zero-Trust Wrapped-CLI Hardening

Status: living document. Tracks the generalized primitive added in issue #39
(parent: per-tool hardens #34/#35/#36/#37/#38, prior art: PR #33 / issue #32).

## Threat model

> An LLM-driven shell-call layer where the LLM might make mistakes, hostile
> env may be inherited from upstream processes, but we're not defending
> against an active local attacker who already has shell.

That framing scopes the work. We are NOT trying to sandbox a CLI against a
local attacker who can already `cp /bin/sh /tmp/rg` -- they have already
won. We ARE trying to:

1. Prevent an LLM that emits a plausibly-shaped command from accidentally
   reaching for a flag that performs per-file script execution, archive
   reads, or arbitrary process spawning under the agent's identity.
2. Prevent a hostile environment (e.g. a parent process that set
   `LD_PRELOAD=/tmp/evil.so` or `RIPGREP_CONFIG_PATH=/tmp/ripgreprc-with-pre`)
   from converting any wrapped CLI call into RCE under the agent.

Both threats are "shell-call layer" weaknesses, not bugs in the underlying
binaries. The defense lives in the wrapper.

## Defense-in-depth

Each wrapped CLI gets three independent layers. None of them is sufficient
alone; together they remove the practical exploit surface for the LLM /
hostile-env threat model above.

1. **Per-tool `secure_*_command()` helper** -- the canonical worked example
   is [`secure_rg_command`](../../src/core/utils.rs) (PR #33). It strips
   tool-specific env hijacks like `RIPGREP_CONFIG_PATH`.
2. **Universal env-strip list** -- `UNIVERSAL_ENV_STRIP` in
   `src/core/utils.rs` plus dynamic `BASH_FUNC_*` / `DYLD_*` filtering.
   Applied to every command spawned via `secure_command_with_policy`.
   Covers loader hijacks, pager/editor invocation, per-language loader
   injection, and shell metaprogramming.
3. **Per-tool arg deny-list** -- a `ToolPolicy` with `arg_deny_exact`,
   `arg_deny_prefix`, and `arg_deny_short_letters_in_bundle`. The
   short-bundle scan is the codex-P1 catch from PR #33: without it, `-cz`
   slips past an exact `-z` deny.

The wrapper still ships an escape hatch: `contextcrawler proxy <tool>
<args>` runs the binary raw, no env strip, no arg filter. That's the
documented release valve for users who genuinely need a denied flag.

## Registering a new tool

```rust
use crate::core::utils::{ToolPolicy, secure_command_with_policy, check_args_with_policy};

const MY_TOOL_POLICY: ToolPolicy = ToolPolicy {
    name: "mytool",
    env_strip: &["MYTOOL_CONFIG_PATH", "MYTOOL_PLUGIN_DIR"],
    arg_deny_exact: &["--exec", "--plugin"],
    arg_deny_prefix: &["--exec=", "--plugin="],
    arg_deny_short_letters_in_bundle: &[],
};

// At the spawn site:
check_args_with_policy(&MY_TOOL_POLICY, &user_args)
    .map_err(|msg| anyhow::anyhow!(msg))?;
let mut cmd = secure_command_with_policy(&MY_TOOL_POLICY);
cmd.args(&user_args);
```

Checklist when adding a tool:

- [ ] Read the tool's man page for env vars that load config / scripts / plugins.
- [ ] Read the tool's man page for flags that exec scripts, read archives,
      or spawn helper processes.
- [ ] Add a `ToolPolicy` const next to the spawn site (or in a dedicated
      registry module if multiple call sites share it).
- [ ] Write a unit test asserting the deny list rejects the dangerous flags
      and the env strip removes the dangerous vars (see
      `policy_registry_tests` in `src/core/utils.rs` for the template).
- [ ] Document the policy in this file under "Registered tools".

## Registered tools

| Tool | Policy const | Source | Notes |
|------|--------------|--------|-------|
| (none yet) | -- | -- | Per-tool helpers `secure_rg_command` etc. will be refactored to use `ToolPolicy` in a follow-up to #39 once the in-flight per-tool hardens #34-#38 land. |

The existing per-tool helper `secure_rg_command` (PR #33) remains the
canonical prior-art reference until that refactor.

## References

- Issue #32 -- verified `RIPGREP_CONFIG_PATH` RCE PoC that motivated PR #33.
- PR #33 -- per-tool `secure_rg_command` + `check_forbidden_rg_args`.
- Issues #34/#35/#36/#37/#38 -- in-flight per-tool hardens for additional CLIs.
- Issue #39 -- this generalized primitive + universal env-strip list.
