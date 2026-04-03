# Paint Alpha Release Boundary

This document defines the first Paint alpha as a repo-local go/no-go decision, not a vague milestone.

It ties together the current public commitments for:

- backend identity and emitted artifact shape
- CI/report stability
- signing and trust defaults
- first-success install/build/verify/fix expectations
- witness-family and remediation language
- DTCG 2025.10 review status
- release packaging and verification gates

## Alpha scope

The alpha is intentionally narrow.

Included in the alpha commitment:

- the `paint` CLI for `build`, `compose`, `verify`, `verify-compose`, `sign`, `annotate-report`, and `explain`
- the canonical backend ids documented in [`docs/backend_contract.md`](backend_contract.md)
- the schema-backed report artifacts and exit-code behavior documented in [`docs/ci_contract.md`](ci_contract.md)
- the signing defaults documented in [`docs/trust_policy.md`](trust_policy.md)
- the first-success user contract documented in [`docs/first_success_ux.md`](first_success_ux.md)
- the user-facing finding taxonomy documented in [`docs/witness_taxonomy.md`](witness_taxonomy.md)
- the source-install and release-tarball path documented in [`docs/releasing.md`](releasing.md)
- the DTCG 2025.10 review documented in [`docs/dtcg_2025_10_review.md`](dtcg_2025_10_review.md)

Not included in the alpha commitment:

- package-manager distribution beyond source install and repo-built tarballs
- plugin/extensibility infrastructure for third-party backends
- design-tool authoring UX
- framework or component-library generation inside Paint core
- full `$extensions` round-tripping or `$description`-to-comment emission

## Alpha commitments

For alpha consumers, Paint commits to:

- targeting the DTCG 2025.10 Format, Resolver, and Color modules as its supported standards surface
- rejecting unknown reserved `$...` properties for DTCG 2025.10 inputs by default
- emitting canonical backend ids in manifests and reports:
  - `web-css-vars`
  - `swift-tokens`
  - `android-compose-tokens`
  - `web-tokens-ts`
- keeping `backendArtifacts` as the primary machine-readable backend contract
- treating `nativeApiVersions` only as a compatibility projection
- keeping backend artifact paths relative to the owning output root
- keeping signing optional by default unless callers opt into stricter verification flags

## Open issues that block alpha

There are currently no open conformance blocker issues from the reviewed DTCG 2025.10 surface.

These accepted alpha-era decisions still need to stay explicit in docs and release notes:

- Resolver input case sensitivity (`tbp-32f`)
  - alpha decision: keep exact-match resolver input behavior for now and document it explicitly in user docs and release notes
- Unknown future reserved `$properties` (`tbp-1qa`)
  - alpha decision: stay version-strict to DTCG 2025.10 by default, reject unknown reserved `$...` properties, and add future-property support only through an explicit versioning decision

## Go/No-Go gates

The alpha is a `go` only if every required gate below is satisfied.

| Gate | Evidence | Alpha rule |
| --- | --- | --- |
| Release docs are coherent | `docs/releasing.md`, `docs/backend_contract.md`, `docs/ci_contract.md`, `docs/trust_policy.md`, `docs/dtcg_2025_10_review.md` | all are present, current, and consistent with the public Paint surface |
| First-success UX contract is explicit | [`docs/first_success_ux.md`](first_success_ux.md), `README.md` | install/build/verify/explain/fix expectations are documented and do not depend on contributor-only setup knowledge |
| Witness taxonomy is explicit | [`docs/witness_taxonomy.md`](witness_taxonomy.md), `README.md` | user-facing family labels, severity defaults, and remediation posture are documented separately from technical witness kinds |
| DTCG review is current | [`docs/dtcg_2025_10_review.md`](dtcg_2025_10_review.md) | hard gaps have tracker coverage or are fixed |
| Hard conformance blockers are closed | `docs/dtcg_2025_10_review.md`, tracker state | no open `gap` items remain from the reviewed DTCG 2025.10 surface |
| SHOULD-level resolver input behavior is decided | `tbp-32f` resolution, release notes, and README | exact-match behavior is either replaced or explicitly documented as an accepted alpha deviation |
| Reserved-property versioning behavior is decided | `tbp-1qa` resolution, release notes, and README | unknown reserved `$...` properties are either version-gated explicitly or documented as rejected for the supported DTCG 2025.10 surface |
| Backend contract is frozen for alpha | [`docs/backend_contract.md`](backend_contract.md), [`tests/backend_contract.rs`](../tests/backend_contract.rs), [`tests/report_schema.rs`](../tests/report_schema.rs) | no unreviewed contract changes since the last alpha decision |
| CI contract is frozen for alpha | [`docs/ci_contract.md`](ci_contract.md) and its referenced tests | exit-code and JSON/report behavior match the documented contract |
| Core verification passes | `cargo test --workspace` | must pass on the candidate release commit |
| Upstream spec-watch is clean | `python3 scripts/spec_watch.py check --targets spec-watch/targets.json --lock spec-watch/lock.json --artifact-dir spec-watch-artifacts` | must pass without drift unless the lock refresh is part of the release |
| Install path works | `cargo install --locked --path . --root "$(mktemp -d)"` | must produce a usable `paint` binary |
| Tarball packaging works | `./scripts/package_release.sh --out-dir "$(mktemp -d)"` | must produce a versioned tarball and `.sha256` sidecar |
| Changelog is ready | `CHANGELOG.md` | must include the alpha release entry and explicitly call out any accepted deviations |

## Alpha decision procedure

1. Confirm the candidate commit is on canonical `main`.
2. Confirm the blocking issues are closed.
3. Run the required verification and packaging commands.
4. Re-read the DTCG review and confirm no new material gaps have appeared since it was written.
5. Decide whether any remaining SHOULD-level deviations are acceptable for alpha.
6. Record the decision in the release notes/changelog.

If any required gate fails, the decision is `no-go`.

## Deferred beyond alpha

The following are intentionally post-alpha unless re-scoped by new tracker work:

- package-manager installs beyond Cargo source install
- richer translation-tool metadata handling for `$extensions`
- description propagation into generated code comments
- backend/plugin SDK work
- framework/component-library generation above the backend layer

## Related docs

- [`docs/releasing.md`](releasing.md)
- [`docs/backend_contract.md`](backend_contract.md)
- [`docs/ci_contract.md`](ci_contract.md)
- [`docs/first_success_ux.md`](first_success_ux.md)
- [`docs/witness_taxonomy.md`](witness_taxonomy.md)
- [`docs/trust_policy.md`](trust_policy.md)
- [`docs/dtcg_2025_10_review.md`](dtcg_2025_10_review.md)
