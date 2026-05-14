# Proposed CI jobs

These two jobs are not yet wired into `.github/workflows/ci.yml` because
`.github/` is gitignored on this fork. Paste into the workflow when the
CI plumbing path is decided.

## release-build — block path leaks before release

```yaml
release-build:
  name: release-build (no leaked paths)
  needs: clippy
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    # scripts/build-release.sh sets --remap-path-prefix and then asserts
    # the produced binary contains no builder $HOME / $CARGO_HOME /
    # workspace strings. Fails the build if any leaked path survives.
    - run: ./scripts/build-release.sh --verify
```

## deny — advisories + licenses + bans + sources

```yaml
deny:
  name: cargo deny (advisories + licenses + bans + sources)
  needs: clippy
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: EmbarkStudios/cargo-deny-action@v2
      with:
        command: check advisories licenses bans sources
```

`deny.toml` at the repo root drives the policy. The single allowed
advisory ignore is `RUSTSEC-2025-0057` (fxhash unmaintained, transitive
via scraper) — documented in `docs/quality/BASELINE.md` and in the
`[advisories.ignore]` section's inline comments.
