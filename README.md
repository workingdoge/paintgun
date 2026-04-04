# Paintgun

Paintgun is a Rust toolchain for DTCG 2025.10 resolution, verification, and composition:

- **Spec-compliant resolution** for DTCG 2025.10 Resolver Module (`resolutionOrder` + last-write-wins).
- A **typed, target-agnostic IR** (`ResolvedToken { type, value }`) — *no CSS strings in core*.
- **Composability certificate** (CTC):
  - Kan completion diagnostics (`Val⊥`)
  - Beck–Chevalley witnesses (order-dependence)
  - Orthogonality overlaps
- **Target emission** via `Emitter` trait (CSS emitter included).

## Install

The supported public install path is tarball-first and does not require Cargo, `./premath`, or a repo checkout.

Quick install:

```bash
curl -fsSL https://raw.githubusercontent.com/workingdoge/paintgun/main/scripts/install_paint.sh -o install_paint.sh
bash install_paint.sh
paint --version
```

Pinned install:

```bash
bash install_paint.sh --version 0.1.0
```

Manual release-tarball install and contributor source-build notes live in [`docs/install.md`](docs/install.md).

## Build & run

The examples below assume you installed the public `paint` binary. If you are working from a source checkout instead, prefix the same commands with `cargo run --`.

```bash
paint build \
  examples/charter-steel/charter-steel.resolver.json \
  --contracts examples/charter-steel/component-contracts.json \
  --out dist \
  --target web-css-vars \
  --kcir-wire-format-id kcir.wire.legacy-fixed32.v1 \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic \
  --contexts full-only \
  --format text
```

Other targets:

```bash
# Swift (runtime-friendly token map)
paint build examples/charter-steel/charter-steel.resolver.json --out dist --target swift-tokens

# Android Compose tokens
paint build examples/charter-steel/charter-steel.resolver.json --out dist --target android-compose-tokens

# Typed web token package
paint build examples/charter-steel/charter-steel.resolver.json --out dist --target web-tokens-ts

# Compatibility alias during the alpha transition
paint build examples/charter-steel/charter-steel.resolver.json --out dist --target kotlin
```

Canonical backend ids are `web-css-vars`, `swift-tokens`, `android-compose-tokens`, and `web-tokens-ts`. The legacy names `css`, `swift`, and `kotlin` remain accepted as compatibility aliases through alpha.

Maintainers can also build a target-specific release tarball with `./scripts/package_release.sh`.
The supported public install path is documented in [`docs/install.md`](docs/install.md).
The 10-minute first-success walkthrough is documented in [`docs/quickstart.md`](docs/quickstart.md).
The artifact shape, packaging policy, and maintainer checklist are documented in [`docs/releasing.md`](docs/releasing.md).
The canonical new-user success path is documented in [`docs/first_success_ux.md`](docs/first_success_ux.md).
The target-backend and system-package architecture is documented in [`docs/target_backends.md`](docs/target_backends.md).
The alpha-stable backend artifact contract is documented in [`docs/backend_contract.md`](docs/backend_contract.md).
The incremental build/cache foundation is documented in [`docs/incremental_builds.md`](docs/incremental_builds.md).
The user-facing finding families and remediation model are documented in [`docs/witness_taxonomy.md`](docs/witness_taxonomy.md).
The DTCG 2025.10 design/conformance review is documented in [`docs/dtcg_2025_10_review.md`](docs/dtcg_2025_10_review.md).
The alpha release boundary and go/no-go checklist are documented in [`docs/alpha_release.md`](docs/alpha_release.md).
The minimal TypeScript consumer path for `web-tokens-ts` is documented in
[`examples/web-tokens-consumer/README.md`](examples/web-tokens-consumer/README.md).

`build` supports two KCIR manifest wire formats via `--kcir-wire-format-id`:
- `kcir.wire.legacy-fixed32.v1` (default)
- `kcir.wire.lenprefixed-ref.v1`

Outputs:

- `dist/tokens.css` — compatibility CSS bundle for `--target web-css-vars` (raw token vars + component-package stylesheet)
- `dist/tokens.vars.css` — raw CSS custom-property token backend output for the CSS compatibility target
- `dist/components.css` — component-contract stylesheet that references Paintgun CSS custom properties
- `dist/tokens.d.ts` — component-contract TypeScript declarations for the CSS compatibility target
- `dist/tokens.swift` — emitted Swift token map (when `--target swift-tokens`)
- `dist/tokens.kt` — emitted Android Compose token map (when `--target android-compose-tokens` or the `kotlin` compatibility alias)
  - Native API markers are embedded as `PaintgunEmitterAPI.swiftVersion` (Swift) and `PAINTGUN_EMITTER_API_VERSION` (Android Compose).
- `dist/tokens.ts` — emitted typed web token package source (when `--target web-tokens-ts`)
  - Exports `contexts`, `valuesByContext`, and typed token aliases for JS/TS consumers.
- `dist/swift/` — Swift Package scaffold (`Package.swift`, module source, tests) when `--target swift-tokens`
- `dist/android/` — Android Gradle module scaffold (`settings.gradle.kts`, `build.gradle.kts`, source, tests) when `--target android-compose-tokens` or the `kotlin` compatibility alias
- `dist/web/` — web token package scaffold (`package.json`, `tsconfig.json`, source, test) when `--target web-tokens-ts`
  - See [`examples/web-tokens-consumer/README.md`](examples/web-tokens-consumer/README.md) for
    a minimal Bun/TypeScript consumer that imports that generated package by name.
- `dist/resolved.json` — platform-neutral resolved IR (structured values)
- `dist/ctc.witnesses.json` — composability witnesses (Kan/BC/orthogonality) including `conflictMode`, `policyDigest`, and `normalizerVersion` metadata
  - Includes `witnessSchema` version marker (currently `1`).
  - Witness lists are canonically ordered for deterministic diffs/CI runs.
- `dist/ctc.manifest.json` — binds inputs/outputs/semantics to the witnesses hash
  - Includes `packIdentity` (`packId`, `packVersion`, `contentHash`) pinned to resolved content.
  - Includes `backendArtifacts` entries for emitted backend files, with backend id, artifact kind, hash/size, and optional API version.
  - Preserves optional `nativeApiVersions` as a compatibility projection for Swift/Kotlin outputs.
- `dist/validation.json` — machine-readable diagnostics when `--format json` (schema: `schemas/report.schema.json`)
- `dist/diagnostics.pack.json` — editor-facing diagnostics projection generated for pack outputs (schema: `schemas/diagnostics.schema.json`)
- `dist/manifest.json` — SHA-256 hashes of referenced token files (legacy, optional)
- `dist/inputs/` — staged resolver + referenced token documents copied into a self-contained verification bundle
- `dist/.paint/cache/` — hidden stage cache metadata for repeated `build` and `compose` runs against
  the same output root

Repeated identical `build` and `compose` invocations can now reuse existing outputs when the input
fingerprint and expected artifact set match. The cache boundary and invalidation rules are
documented in [`docs/incremental_builds.md`](docs/incremental_builds.md).

## Validation failures

`build` validates resolver, contracts, policy, and output-path inputs before writing artifacts. Malformed input files fail with a regular CLI error instead of a Rust panic backtrace.

For machine-readable verification failures, use `verify` or `verify-compose` with `--format json`; those JSON reports preserve stable `errorDetails` entries where documented.
For the supported external CI surface, including report schema/version expectations and exit-code behavior, see [`docs/ci_contract.md`](docs/ci_contract.md).

## Artifact cleanup

Generated output folders (`dist*`) are ignored by git.

```bash
# Preview what will be removed
./scripts/clean_dist.sh --dry-run

# Remove all dist* directories in repo root
./scripts/clean_dist.sh
```

## Contributor source setup

This section is contributor-facing. Repo-local Cargo builds from a source checkout still expect the extracted Premath code home to be projected at `./premath`.

Canonical local layout:

```bash
./scripts/link_premath_checkout.sh
cargo test --workspace
```

If `./premath` is missing, Cargo commands in this repo will fail because the extracted `premath-*` crates are external dependencies now.

Useful contributor references:

- [`docs/premath_standalone_prep.md`](docs/premath_standalone_prep.md)
- [`docs/premath_code_home.md`](docs/premath_code_home.md)
- [`docs/premath_extraction_contract.md`](docs/premath_extraction_contract.md)
- `./scripts/premath_workspace_ci.sh`

## External Adoption Example

`examples/adoption-starter/README.md` shows the supported clean-clone flow for:
- building two packs
- verifying and signing each pack
- composing them into a portable sibling bundle
- strictly verifying the signed compose manifest and signed pack manifests

## Web Runtime Prototype

`examples/web-runtime-prototype/README.md` shows the first narrow design-system consumer path above
Paint backend outputs:

- authored `system.schema.json`
- authored `system.web.config.json`
- derived `generated/system.web.json`
- derived `generated/system.catalog.json`
- generated `src/generated/system-web.ts`
- generated `src/generated/system-catalog.ts`
- one pure custom-element consumer
- one real Storybook workspace and docs consumer
- one static browser host at `demo/index.html`

It is intentionally a prototype package, not a new Paint core feature.

The contract for what future live consumers may depend on is documented in
[`docs/live_consumer_contract.md`](docs/live_consumer_contract.md).
The editor-facing diagnostics projection is documented in
[`docs/diagnostics_projection.md`](docs/diagnostics_projection.md).
The design-tool-neutral catalog IR is documented in
[`docs/catalog_ir.md`](docs/catalog_ir.md).
The next editor/design-tool adapter seams are documented in
[`docs/editor_design_tool_seam.md`](docs/editor_design_tool_seam.md).

## VS Code Diagnostics Prototype

`examples/vscode-diagnostics-prototype/README.md` shows the first read-only editor consumer path
above generated `diagnostics.pack.json` outputs.

## Design-Tool Bridge Prototype

`examples/design-tool-bridge-prototype/README.md` shows the first read-only design-tool consumer
path above generated `system.catalog.json`, diagnostics projections, and the generated web token
package output.

## Fixture tooling

KCIR/NF conformance vectors can be built with:

```bash
# Varint list helper (for mapWtoU, etc.)
./scripts/kcir_fixture_builder.py list-u32 --items 1,0

# MorNF hash helper
./scripts/kcir_fixture_builder.py hash-mor \
  --env-sig 0000000000000000000000000000000000000000000000000000000000000000 \
  --uid 1111111111111111111111111111111111111111111111111111111111111111 \
  --mor-bytes 113333333333333333333333333333333333333333333333333333333333333333

# KCIR node encode + certId
./scripts/kcir_fixture_builder.py encode-node \
  --env-sig 0000000000000000000000000000000000000000000000000000000000000000 \
  --uid 1111111111111111111111111111111111111111111111111111111111111111 \
  --sort 4 --opcode 16 \
  --out 0000000000000000000000000000000000000000000000000000000000000000 \
  --args aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaec824d4aaf7aaefa4a2edca8ccf4024d8ba8e6bd42238dfe6f4cbfee3e75445001 \
  --deps ''
```

## Verify

```bash
# Verify hashes + witnesses binding
paint verify dist/ctc.manifest.json

# Require detached signature + signed trust metadata
paint verify dist/ctc.manifest.json --require-signed

# Verify semantics binding too (policyDigest + conflictMode)
paint verify dist/ctc.manifest.json \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic

# CI gate: require no gaps/conflicts/BC violations
paint verify dist/ctc.manifest.json --require-composable

# CI gate with explicit tie-break acknowledgements
paint verify dist/ctc.manifest.json \
  --require-composable \
  --allowlist ci/allowlist.json

# Generate a reviewable allowlist stub from current witnesses
paint fix-allowlist dist/ctc.manifest.json --out ci/allowlist.json

# Generate selector-based entries for a subset of current witnesses
paint fix-allowlist dist/ctc.manifest.json \
  --matcher selector \
  --witness-id conflict-1234abcd5678ef90 \
  --witness-id bc-1234abcd5678ef90

# Full profile: enforce Gate witness hash binding + Gate acceptance
paint verify dist/ctc.manifest.json --profile full
```

Allowlist format (strict, versioned):

```json
{
  "version": 1,
  "conflicts": [
    {
      "witnessId": "conflict-1234abcd5678ef90",
      "reason": "Known tie-break; tracked in TICKET-42"
    }
  ],
  "bcViolations": [
    {
      "selector": {
        "tokenPath": "color.surface.bg",
        "axisA": "density",
        "valueA": "compact",
        "axisB": "theme",
        "valueB": "dark"
      },
      "reason": "Intentional rollout exception"
    }
  ]
}
```

Rules:
- Each allowlist entry must include exactly one matcher: `witnessId` or `selector`.
- `reason` is required and must be non-empty.
- Stale allowlist entries fail verify with a deterministic error.
- `paint fix-allowlist` emits reviewable stubs, not approvals. The default reason is a TODO placeholder; replace it with the reviewed policy justification before using `verify --allowlist`.
- `paint fix-allowlist` defaults to `witnessId` matchers for an exact snapshot of current findings. Use `--matcher selector` when you want a more semantic, reviewable policy entry.

## Verify compose meta-cert

```bash
paint verify-compose dist-compose/compose.manifest.json

# Require signed compose manifest (and signed pack manifests)
paint verify-compose dist-compose/compose.manifest.json \
  --require-signed \
  --require-packs-signed

# Optional semantics check for compose manifest
paint verify-compose dist-compose/compose.manifest.json \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic

# Enforce full-profile verification for each referenced pack
paint verify-compose dist-compose/compose.manifest.json \
  --verify-packs \
  --pack-profile full

# Machine-readable output (includes verify.errorDetails with stable error codes)
paint verify-compose dist-compose/compose.manifest.json \
  --format json
```

When using `--policy` in verify commands, pass the same policy file used to produce the manifest.
Public v1 policy: signing is optional by default. `verify` and `verify-compose` accept unsigned artifacts unless the caller opts into `--require-signed` and/or `--require-packs-signed`; if a manifest advertises `trust.status = "signed"`, `paint` always validates the detached signature. See `docs/trust_policy.md`.
Paintgun treats the output directory as a portable pack bundle: consistent with the Resolver Module's non-normative bundling guidance, `build` stages the resolver and referenced token docs into `dist/inputs/`, and `verify` checks those copied inputs instead of reaching back into the original source tree.
For supply-chain safety, verify commands require root-bound canonicalized manifest paths; absolute paths and traversal that escapes the trust root are rejected.
Supported pack flow: move or archive the whole pack directory and verify `ctc.manifest.json` in place.
`verify` also enforces `packIdentity.contentHash == outputs.resolvedJson.sha256`.
Both `verify` and `verify-compose` enforce the current witness schema version marker.

## Sign manifest

```bash
# Sign a per-pack or compose manifest (writes detached *.sig.json + updates trust metadata)
paint sign dist/ctc.manifest.json --signer ci@example
paint sign dist-compose/compose.manifest.json --signer ci@example

# Optional explicit detached signature output path
paint sign dist/ctc.manifest.json --out dist/ctc.signature.json
```

Signed manifests record:
- `trust.status = "signed"`
- `trust.signatureScheme = "paintgun-detached-sha256-v1"`
- `trust.signatureFile`
- `trust.claimsSha256`

Detailed trust/scheme behavior is documented in `SIGNING.md`, and the public verifier policy is documented in `docs/trust_policy.md`.

## Explain witness

```bash
# Search defaults: dist/ctc.witnesses.json and dist-compose/compose.witnesses.json
paint explain conflict-1234abcd5678ef90

# Explicit witness file(s)
paint explain conflict-1234abcd5678ef90 \
  --witnesses dist/ctc.witnesses.json
```

`explain` prints:
- user-facing finding family plus technical witness type
- severity and fixability
- primary source file path and JSON Pointer
- high-level cause summary
- next action guidance

## GitHub Annotations

```bash
# Convert report JSON into GitHub Actions annotation commands
paint annotate-report dist/validation.json \
  --file-root examples/charter-steel \
  --max 200

paint annotate-report dist-compose/compose.report.json --max 200
```

`annotate-report` consumes the schema-backed report artifacts (`validation.json` / `compose.report.json`) and prints GitHub Actions annotation lines plus a final `paintgun/report` summary notice. See [`docs/ci_contract.md`](docs/ci_contract.md) for the supported CI contract.

## Multi-pack composition

Assuming you have already built two packs into `packs/core/dist` and `packs/brand/dist`:

```bash
paint compose \
  packs/core/dist \
  packs/brand/dist \
  --out dist-compose \
  --target web-css-vars \
  --contracts examples/charter-steel/component-contracts.json \
  --conflict-mode semantic \
  --contexts from-contracts \
  --format text \
  --require-composable
```

`--conflict-mode` accepts:
- `semantic` (default): compare structured resolved intent.
- `normalized`: compare after applying policy normalization (observable output-oriented).

`--contexts` accepts:
- `full-only`: evaluate only full intersection contexts (default for `build`).
- `partial`: evaluate the full partial lattice (default for `compose`).
- `from-contracts`: evaluate contract-bounded layered contexts (base + single-axis + pairwise) and contract token paths; requires `--contracts`.

`--planner-trace` (with `--format json`) adds a `plannerTrace` section to `validation.json` / `compose.report.json` with:
- included contexts (rule/source),
- resolver-support contexts (rule/source),
- excluded contexts (rule/source),
- counts and truncation metadata.

Resolver input matching is currently case-sensitive across Paint's resolver-facing surfaces. Modifier names and context values must match the resolver document's declared casing exactly. This is an explicit alpha-era deviation from the DTCG Resolver 2025.10 SHOULD-level guidance that tools treat inputs case-insensitively.

Paint is version-strict to DTCG 2025.10. Unknown reserved `$...` properties are rejected instead of ignored, and there is no permissive compatibility mode in alpha. Supporting newer reserved properties requires an explicit Paint versioning decision rather than best-effort parsing.

Compose bundles are trust-root relative rather than absolute: `compose.manifest.json` records each referenced pack directory relative to the compose output directory. Supported compose flow: archive `dist-compose/` together with the referenced pack directories under the same parent root before running `verify-compose`.

## Spec watch

The repo ships two upstream spec checks:
- `.github/workflows/spec-watch.yml` watches the canonical Design Tokens 2025.10 TR + schema endpoints listed in `spec-watch/targets.json` and compares them against the pinned digests in `spec-watch/lock.json`.
- `.github/workflows/spec-release-discovery.yml` watches trusted upstream index pages in `spec-watch/discovery.json` and fails when they report a newer stable DTCG release than Paint currently targets.

Run the pinned digest watch locally with:

```bash
python3 scripts/spec_watch.py check \
  --targets spec-watch/targets.json \
  --lock spec-watch/lock.json \
  --artifact-dir spec-watch-artifacts
```

If drift is intentional and Paintgun should adopt it, update code/docs as needed, then refresh the lock:

```bash
python3 scripts/spec_watch.py refresh \
  --targets spec-watch/targets.json \
  --lock spec-watch/lock.json
```

Run the release discovery watch locally with:

```bash
python3 scripts/spec_watch.py discover-check \
  --discovery spec-watch/discovery.json \
  --artifact-dir spec-release-discovery-artifacts
```

Triage details live in `docs/spec_watch.md` and `docs/spec_release_watch.md`.
Context-scaling metrics fixture:

```bash
python3 scripts/context_metrics.py
```

This runs `build` across all context modes using `examples/perf-lattice/*` and writes:
- `perf-metrics/context-metrics.json`
- `perf-metrics/context-metrics.md`

CI enforces the following pass/fail gates from this fixture:
- ordering invariant: `partial > full-only > from-contracts` on `resolvedContexts`
- reduction gate: `(full-only - from-contracts) / full-only >= 0.20`
- expansion gate: `partial / full-only >= 1.10`

These thresholds are defined in `scripts/context_metrics.py` and emitted in `perf-metrics/context-metrics.json` under `thresholds` and `derived`.

Large compose/planner benchmark fixture:

```bash
python3 scripts/compose_scale_metrics.py
```

This generates a 24-pack corpus from `examples/compose-scale/*`, builds those packs in `partial`
mode, then composes the graph in `full-only`, `partial`, and `from-contracts` modes. It writes:

- `dist-compose-scale/` — generated resolver corpus plus built pack/compose outputs
- `perf-metrics/compose-scale-metrics.json`
- `perf-metrics/compose-scale-metrics.md`

The committed fixture description lives in `examples/compose-scale/README.md`.
Interpretation note: on large graphs, `from-contracts` should be read as a bounded planning view,
not as a replacement for full org-wide compose conflict review.

Outputs:

- `dist-compose/resolved.json` — composed resolved IR
- `dist-compose/tokens.css` (or `tokens.swift` / `tokens.kt` / `tokens.ts`) — emitted target artifact
- `dist-compose/swift/`, `dist-compose/android/`, or `dist-compose/web/` — target package/module scaffold when using those targets
- `dist-compose/compose.witnesses.json` — cross-pack conflicts (order dependence) with `inheritedFrom` links plus `conflictMode`/`policyDigest`/`normalizerVersion` metadata
  - Includes `witnessSchema` version marker (currently `1`).
  - Conflict witnesses and source lists are canonically ordered for deterministic diffs/CI runs.
- `dist-compose/compose.manifest.json` — meta-certificate binding packs + semantics to witnesses
  - Each compose pack entry includes pinned `packIdentity`.
  - Includes `backendArtifacts` entries for emitted backend files, with backend id, artifact kind, hash/size, and optional API version.
  - Preserves optional `nativeApiVersions` as a compatibility projection for Swift/Kotlin outputs.
- `dist-compose/compose.report.txt` — human readable summary, including large-graph planner/witness guardrails, rollups, and capped detail when witness sets get large
- `dist-compose/compose.report.json` — machine-readable diagnostics when `--format json` (schema: `schemas/report.schema.json`)
  - Includes `guardrails` and `rollups` for large-compose review.
  - Includes `plannerTrace` when `--planner-trace` is requested.

## Key refactor vs TS prototype

- `ResolvedToken.value` is **structured** (`DtcgValue`), not a pre-rendered string.
- Kan/BC analysis compares values by **structural equality**, not `===` on CSS.
- Emission happens **last** via `CssEmitter` (or other targets).
- Provenance pack identity is canonicalized across naming variants (`@version`, `+/# sha`, `__sha256_`).
- CI runs native integration checks for emitted Swift/Android packages (`swift test`, Gradle test),
  including the standard `charter-steel` fixture and a native alpha-color edge-case fixture.
