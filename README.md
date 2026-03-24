# tbp-rs

A Rust refactor of the **Token Bridge Project (TBP)** prototype:

- **Spec-compliant resolution** for DTCG 2025.10 Resolver Module (`resolutionOrder` + last-write-wins).
- A **typed, target-agnostic IR** (`ResolvedToken { type, value }`) — *no CSS strings in core*.
- **Composability certificate** (CTC):
  - Kan completion diagnostics (`Val⊥`)
  - Beck–Chevalley witnesses (order-dependence)
  - Orthogonality overlaps
- **Target emission** via `Emitter` trait (CSS emitter included).

## Build & run

```bash
cargo run -- build \
  examples/charter-steel/charter-steel.resolver.json \
  --contracts examples/charter-steel/component-contracts.json \
  --out dist \
  --target css \
  --kcir-wire-format-id kcir.wire.legacy-fixed32.v1 \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic \
  --contexts full-only \
  --format text
```

Other targets:

```bash
# Swift (runtime-friendly token map)
cargo run -- build examples/charter-steel/charter-steel.resolver.json --out dist --target swift

# Kotlin (Jetpack Compose-friendly token map)
cargo run -- build examples/charter-steel/charter-steel.resolver.json --out dist --target kotlin
```

`build` supports two KCIR manifest wire formats via `--kcir-wire-format-id`:
- `kcir.wire.legacy-fixed32.v1` (default)
- `kcir.wire.lenprefixed-ref.v1`

Outputs:

- `dist/tokens.css` — emitted CSS
- `dist/tokens.swift` — emitted Swift token map (when `--target swift`)
- `dist/tokens.kt` — emitted Kotlin token map (when `--target kotlin`)
  - Native API markers are embedded as `TBPEmitterAPI.swiftVersion` (Swift) and `TBP_EMITTER_API_VERSION` (Kotlin).
- `dist/swift/` — Swift Package scaffold (`Package.swift`, module source, tests) when `--target swift`
- `dist/kotlin/` — Kotlin Gradle module scaffold (`build.gradle.kts`, source, tests) when `--target kotlin`
- `dist/resolved.json` — platform-neutral resolved IR (structured values)
- `dist/ctc.witnesses.json` — composability witnesses (Kan/BC/orthogonality) including `conflictMode`, `policyDigest`, and `normalizerVersion` metadata
  - Includes `witnessSchema` version marker (currently `1`).
  - Witness lists are canonically ordered for deterministic diffs/CI runs.
- `dist/ctc.manifest.json` — binds inputs/outputs/semantics to the witnesses hash
  - Includes `packIdentity` (`packId`, `packVersion`, `contentHash`) pinned to resolved content.
  - Includes optional `nativeApiVersions` (e.g. Swift/Kotlin emitter API versions) when native targets are emitted.
- `dist/validation.json` — machine-readable diagnostics when `--format json` (schema: `schemas/report.schema.json`)
- `dist/manifest.json` — SHA-256 hashes of referenced token files (legacy, optional)

## Validation failures

`build` validates resolver, contracts, policy, and output-path inputs before writing artifacts. Malformed input files fail with a regular CLI error instead of a Rust panic backtrace.

For machine-readable verification failures, use `verify` or `verify-compose` with `--format json`; those JSON reports preserve stable `errorDetails` entries where documented.

## Artifact cleanup

Generated output folders (`dist*`) are ignored by git.

```bash
# Preview what will be removed
./scripts/clean_dist.sh --dry-run

# Remove all dist* directories in repo root
./scripts/clean_dist.sh
```

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
cargo run -- verify dist/ctc.manifest.json

# Require detached signature + signed trust metadata
cargo run -- verify dist/ctc.manifest.json --require-signed

# Verify semantics binding too (policyDigest + conflictMode)
cargo run -- verify dist/ctc.manifest.json \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic

# CI gate: require no gaps/conflicts/BC violations
cargo run -- verify dist/ctc.manifest.json --require-composable

# CI gate with explicit tie-break acknowledgements
cargo run -- verify dist/ctc.manifest.json \
  --require-composable \
  --allowlist ci/allowlist.json

# Full profile: enforce Gate witness hash binding + Gate acceptance
cargo run -- verify dist/ctc.manifest.json --profile full
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

## Verify compose meta-cert

```bash
cargo run -- verify-compose dist-compose/compose.manifest.json

# Require signed compose manifest (and signed pack manifests)
cargo run -- verify-compose dist-compose/compose.manifest.json \
  --require-signed \
  --require-packs-signed

# Optional semantics check for compose manifest
cargo run -- verify-compose dist-compose/compose.manifest.json \
  --policy examples/charter-steel/policy.json \
  --conflict-mode semantic

# Enforce full-profile verification for each referenced pack
cargo run -- verify-compose dist-compose/compose.manifest.json \
  --verify-packs \
  --pack-profile full

# Machine-readable output (includes verify.errorDetails with stable error codes)
cargo run -- verify-compose dist-compose/compose.manifest.json \
  --format json
```

When using `--policy` in verify commands, pass the same policy file used to produce the manifest.
For supply-chain safety, verify commands require root-bound canonicalized manifest paths; absolute paths and traversal that escapes the trust root are rejected.
`verify` also enforces `packIdentity.contentHash == outputs.resolvedJson.sha256`.
Both `verify` and `verify-compose` enforce the current witness schema version marker.

## Sign manifest

```bash
# Sign a per-pack or compose manifest (writes detached *.sig.json + updates trust metadata)
cargo run -- sign dist/ctc.manifest.json --signer ci@example
cargo run -- sign dist-compose/compose.manifest.json --signer ci@example

# Optional explicit detached signature output path
cargo run -- sign dist/ctc.manifest.json --out dist/ctc.signature.json
```

Signed manifests record:
- `trust.status = "signed"`
- `trust.signatureScheme = "tbp-detached-sha256-v1"`
- `trust.signatureFile`
- `trust.claimsSha256`

Detailed trust/scheme behavior is documented in `SIGNING.md`.

## Explain witness

```bash
# Search defaults: dist/ctc.witnesses.json and dist-compose/compose.witnesses.json
cargo run -- explain conflict-1234abcd5678ef90

# Explicit witness file(s)
cargo run -- explain conflict-1234abcd5678ef90 \
  --witnesses dist/ctc.witnesses.json
```

`explain` prints:
- witness type + summary
- primary source file path and JSON Pointer
- shortest fix recipe

## GitHub Annotations

```bash
# Convert report JSON into GitHub Actions annotation commands
cargo run -- annotate-report dist/validation.json \
  --file-root examples/charter-steel \
  --max 200

cargo run -- annotate-report dist-compose/compose.report.json --max 200
```

## Multi-pack composition

Assuming you have already built two packs into `packs/core/dist` and `packs/brand/dist`:

```bash
cargo run -- compose \
  packs/core/dist \
  packs/brand/dist \
  --out dist-compose \
  --target css \
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

Outputs:

- `dist-compose/resolved.json` — composed resolved IR
- `dist-compose/tokens.css` (or `tokens.swift` / `tokens.kt`) — emitted target artifact
- `dist-compose/swift/` or `dist-compose/kotlin/` — native package/module scaffold when using those targets
- `dist-compose/compose.witnesses.json` — cross-pack conflicts (order dependence) with `inheritedFrom` links plus `conflictMode`/`policyDigest`/`normalizerVersion` metadata
  - Includes `witnessSchema` version marker (currently `1`).
  - Conflict witnesses and source lists are canonically ordered for deterministic diffs/CI runs.
- `dist-compose/compose.manifest.json` — meta-certificate binding packs + semantics to witnesses
  - Each compose pack entry includes pinned `packIdentity`.
  - Includes optional `nativeApiVersions` when composing native targets.
- `dist-compose/compose.report.txt` — human readable summary
- `dist-compose/compose.report.json` — machine-readable diagnostics when `--format json` (schema: `schemas/report.schema.json`)

## Key refactor vs TS prototype

- `ResolvedToken.value` is **structured** (`DtcgValue`), not a pre-rendered string.
- Kan/BC analysis compares values by **structural equality**, not `===` on CSS.
- Emission happens **last** via `CssEmitter` (or other targets).
- Provenance pack identity is canonicalized across naming variants (`@version`, `+/# sha`, `__sha256_`).
- CI runs native integration checks for emitted Swift/Kotlin packages (`swift test`, Gradle test).
