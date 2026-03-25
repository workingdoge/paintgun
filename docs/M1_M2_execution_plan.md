# Paintgun Execution Plan: M1-M7

Date: 2026-02-15
Scope: Convert Milestones 1-7 into issue-sized implementation tickets with CI-ready acceptance criteria.

## Current Status (2026-02-15)
- Done:
  - M1-T1, M1-T2, M1-T3, M1-T4, M1-T5, M1-T6
  - M1-T7 (conformance CI job wired in `.github/workflows/ci.yml`)
  - M2-T1 (schema + validator test), M2-T2, M2-T3, M2-T5
  - M2-T9 baseline: witness payloads include explicit `witnessSchema` markers; verify/compose-verify enforce expected schema version
  - M1-T4 baseline: whole-value aliases now enforce strict mixed-type rejection with deterministic `invalid_type` diagnostics including source/target type identities
  - M1-T2 baseline: conformance matrix now covers `$extends` linear + diamond precedence, nested/object merge, array+scalar replacement, `$root` chain merge, cycle/missing/invalid-target diagnostics
  - M1-T5 baseline: token-tree conformance now covers `$root`, mixed object/array leaf trees, and deterministic rejected-shape diagnostics; `known_unsupported.json` is currently empty
  - M1 resolver/reference strictness baseline: resolver now requires 2025.10 `resolutionOrder` object entries (legacy string entries rejected with explicit parse diagnostics), supports inline `set`/`modifier` entries and spec-shaped modifier context arrays, enforces deterministic invalid resolver ref/input diagnostics (no silent drop), supports source-local `#/sets/<name>` refs with shallow local overrides, and `$extends` now supports JSON Pointer targets (including escaped segments and brace-wrapped pointer literals)
  - M1 guardrail baseline: repo-level resolver doc/fixture scan (`tests/resolution_order_guardrail.rs`) fails CI if legacy string-form `resolutionOrder` entries reappear outside the deliberate negative fixture
  - M1 full-profile admissibility witness baseline: conformance fixtures now support `mode = "admissibility-witness"` and validate `tests/conformance/fixtures/gate/{golden,adversarial}` payloads against `schemas/admissibility_witness.schema.json`, including deterministic failure ordering checks
  - M1 gate behavioral baseline: conformance fixtures now support `mode = "gate-analysis"` to derive Gate failures from resolver/composability analysis with deterministic class/lawRef mapping across `GATE-3.1`..`GATE-3.5`; `GATE-3.1` is now emitted from explicit composition-path disagreement witnesses (not generic ambiguity)
  - Runtime full-profile admissibility baseline: `build --profile full` now emits `admissibility.witnesses.json`; `verify --profile full` requires valid admissibility witness payloads and rejects with class/law + file/pointer diagnostics when admissibility failures are present
  - M1 core-kernel conformance baseline: runner now supports `mode = "kcir-node"`, `mode = "nf-obj"`, `mode = "nf-mor"`, `mode = "dsl-unique"`, `mode = "opcode-obj"`, and `mode = "opcode-mor"` with golden/adversarial vectors for KCIR wire/hash checks, NF hash-bound parsing, and opcode contracts for OBJ (`O_UNIT`/`O_PRIM`/`O_MKTENSOR`) and MOR (`M_ID`/`M_MKTENSOR`/`M_MKCOMP`)
  - M1 KCIR parse/hash strictness baseline: conformance now adds explicit `kcir-node` adversarial vectors for `depsLen` overrun and trailing-byte rejection, plus `core-verify` cert-id integrity vectors for root-key and dep-key mismatch rejection
  - M1 core verifier diagnostics baseline: conformance now includes deterministic unsupported-operation vectors for unknown KCIR sort, unknown MAP/COVER/OBJ/MOR opcodes, and unsupported `O_PULL`/`M_PULL` step tags
  - M1 PullAtom profile guard baseline: `M_PULL` now deterministically rejects step tags `0x04`/`0x07` (`FUSE_PULLATOM`/`WRAP`) while `MorNF PullAtom` (`tag 0x16`) remains unadopted, with both opcode and core-verify adversarial vectors
  - M1 NF hardening baseline: NF conformance now covers malformed trailing/truncated payload rejection, explicit `MorNF` PullAtom (`tag 0x16`) profile rejection, opt-in canonicality checks via `enforceCanonical` (fixture modes) / `baseApi.enforceCanonicalNf` (core-verify harness parsing), store-backed canonicality vectors for nested spine/comp-part violations, core-verify adversarial vectors that fail in `O_PULL`/`M_PULL` prelude classification when non-canonical NF entries are encountered, deeper core-verify non-prelude MOR-path failures (`M_MKTENSOR` endpoint check, `M_MKCOMP` canonicalization, `M_PULL.GLUE` local-dep validation, `M_PULL.BC_SWAP` inner-pull parse/store validation, and `M_PULL.COMP`/`M_PULL.TENSOR` part-dep store requirements), and positive core-verify DAG vectors for non-prelude `M_PULL.COMP`/`M_PULL.TENSOR`/`M_PULL.BC_SWAP` branches
  - M1 PullAtom mixed-chain canonicality baseline: conformance now includes store-backed acceptance vectors for `PullAtom(PushAtom(...))` and `PushAtom(PullAtom(...))` under `enforceCanonicalNf` across `nf-mor`, `opcode-mor` (`M_PULL.FUSE_PULLATOM`/`M_PULL.WRAP`), and `core-verify`
  - M1 PullAtom compose-id collapse hardening baseline: conformance now includes adversarial vectors that reject non-collapsed `M_PULL.FUSE_PULLATOM` outputs when `composeMaps` resolves to an id map (`opcode-mor` + `core-verify`)
  - M1 identity-map canonicality interaction baseline: conformance now includes positive vectors proving `isIdMap(pId)` short-circuits `O_PULL`/`M_PULL` prelude classification at `stepTag=0x00` under `enforceCanonicalNf`, even when referenced store entries are deliberately non-canonical (`opcode` + `core-verify`)
  - M1 MAP/COVER strictness baseline: `M_BC_FPRIME`/`M_BC_GPRIME` now require `BaseApi.bcSquare` witnesses, `C_LITERAL` now requires `BaseApi.validateCover`, and `C_PULLCOVER` now requires both `BaseApi.coverLen` and `BaseApi.pullCover`; `C_PULLCOVER` node meta now carries `pId` + `uSig` + `wSig` (plus compatibility `coverSig`)
  - M1 DSL conformance expansion: runner now supports `mode = "dsl-bag"` and `mode = "dsl-multibag"` with deterministic vectors for BagSpec ordered/unordered matching, MultiBag exact-slot partition ambiguity rejection, and binding-derived `expectedKeysFromBinding` resolution
  - M1 pull-role baseline: opcode verifiers now support dependency-role checks for BC branches (`O_PULL.BC_PUSH`, `M_PULL.BC_SWAP`) and tensor/comp pull branches (`O_PULL.TENSOR`, `M_PULL.TENSOR`, `M_PULL.COMP`) using DSL role matching over `depRecords`, with store-backed expected key derivation (`objStore`/`morStore`) and baseline branch output-hash checks
  - M1 core DAG verifier baseline: conformance runner now supports `mode = "core-verify"` with recursive cert-store verification (`verify_core_dag`) enforcing certId/envSig/Uid invariants and dispatching supported COVER/MAP/OBJ/MOR opcode slices over NF stores
  - M1 pull prelude + hooks baseline: `O_PULL`/`M_PULL` now perform prelude step classification checks when input NF is available, added `O_PULL.WRAP` + `M_PULL.IDMOR` contracts, and core verifier uses Base API hook tables (`bcSquares`, `pullCovers`, `coverLens`, `validCovers`, `composeMaps`, identity maps) for semantic MAP/COVER checks
  - M1 core strictness baseline: core verifier now performs hash-bound NF store reads when store data is consulted and enforces BC branch dependency consistency (`O_PULL.BC_PUSH` / `M_PULL.BC_SWAP`) against push-input semantics plus required Base API BC witnesses
  - M1 core MOR strictness regression baseline: core-verify vectors now include MOR `M_MKCOMP` positive chain acceptance, canonicalization acceptance (flatten nested `Comp` + drop `Id`), and adversarial endpoint/chain plus canonical-zero (`srcH != tgtH`) mismatch rejection through recursive DAG verification; opcode vectors include matching canonical-zero rejection coverage
  - M1 COVER strictness baseline: `C_PULLCOVER` now enforces required Base API `coverLen(uSig)` range checks (`mapWtoU[k] < coverLen(uSig)`) with deterministic missing-length and out-of-range diagnostics in core verifier mode
  - M1 MOR canonicalization baseline: `M_MKCOMP` now canonicalizes parts by flattening store-backed `Comp` components and dropping store-backed `Id` components before 0/1/N normalization, with conformance vectors for canonical-output acceptance and uncanonical hash rejection
  - M1 MOR comp endpoint strictness baseline: `M_MKCOMP` now enforces canonical part chain composability plus `srcH`/`tgtH` agreement with composed part endpoints when canonical part NF entries are available in `morStore`
  - M1 MOR pull-comp canonicalization baseline: `M_PULL.COMP` now canonicalizes pulled part lists (flatten store-backed `Comp`, drop store-backed `Id`) before mk/out checks, with a deterministic non-identity fallback to avoid invalid zero-part collapse
  - M1 MOR tensor endpoint strictness baseline: `M_MKTENSOR` now enforces `srcH`/`tgtH` consistency against tensorized part endpoints when referenced part NF entries are available in `morStore`
  - M2 witness enrichment: `gaps`/`conflicts`/`inherited` now include rich blame payloads
  - Compose witness schema + fallback provenance for missing `authored.json`
  - M2-T6 linkage policy: compose candidates now include `inheritedFrom` refs to matching per-pack `ctc.witnesses` (`inherited`/`conflict`) entries
  - Strict policy parsing only (legacy policy keys removed/rejected)
  - M3-T5 baseline: witness JSON outputs now carry `conflictMode` + `policyDigest` + `normalizerVersion`
  - M5-T1 baseline: `--format json` emits `validation.json` and `compose.report.json` with schema `schemas/report.schema.json`
  - M5-T2 baseline: witness payloads now use canonical ordering with deterministic ID/order stability checks; legacy provenance alias fields dropped (`pack`/`file`)
  - M5-T3 baseline: `verify --allowlist <json>` supports explicit conflict/BC acknowledgements by `witnessId` or selector with required reason; stale entries fail deterministically
  - M5-T4 baseline: `explain <witness-id>` resolves CTC/compose witnesses and prints deterministic source location (`filePath` + `jsonPointer`) with a fix recipe
  - M5-T5 baseline: `annotate-report` maps `validation.json` / `compose.report.json` findings to GitHub Actions annotations; CI workflow emits pack + compose annotation streams
  - Pack identity canonicalization baseline: shared parser normalizes vendored naming variants (`@version`, `+/# hash`, `__sha256_`) so provenance emits canonical `packId`/`packVersion`/`packHash`
  - M3-T1/T2/T3 baseline: `--conflict-mode semantic|normalized` wired through build/compose analysis with semantics metadata
  - M3-T4 baseline: `verify` / `verify-compose` enforce optional `policyDigest` + `conflictMode` expectations via CLI flags
  - M4-T1 baseline: `build`/`compose` now expose `--contexts full-only|partial|from-contracts`
  - M4-T2 baseline: shared context planner implemented with contract-bounded layered evaluation (`base` + single-axis + pairwise) and contract-token filtering
  - M4-T3 baseline: resolver precompute now consumes planned context inputs (`build_token_store_for_inputs`) so `build --contexts` reduces resolved context materialization work
  - M4-T4 baseline: perf fixture + CI metrics capture added (`examples/perf-lattice`, `scripts/context_metrics.py`, `context-scaling-metrics` workflow artifact) with enforced gates (`partial > full-only > from-contracts`, min reduction `0.20`, min expansion `1.10`)
  - M4-T5 baseline: optional `--planner-trace` embeds planner inclusion/exclusion evidence in JSON reports with schema coverage
  - M2-T4 complete: defining-leaf precision now includes escaped JSON Pointer segments, `$root`, nested alias chains, and alias-through-`$extends` chains
  - M6-T1 baseline: `swift-tokens` emits importable Swift Package scaffold in `dist/swift` / `dist-compose/swift` with module + tests
  - M6-T2 baseline: `android-compose-tokens` emits a Gradle module scaffold in `dist/android` / `dist-compose/android` with source + tests
  - M6-T3 baseline: native emitters now publish explicit API versions in generated code and `nativeApiVersions` manifest metadata for pack + compose artifacts
  - M6-T4 baseline: CI now exercises generated Swift/Kotlin artifacts with native toolchain tests (`swift test` and Gradle test) for both pack and compose outputs
  - M7-T1 baseline: `ctc.manifest.json` now pins `packIdentity` (`packId` + `packVersion` + `contentHash`) and verify/compose-verify enforce identity consistency against referenced cert content
  - M7-T2 baseline: resolver/verify flows enforce root-bound canonicalization for source refs and manifest file entries, rejecting absolute paths and traversal that escapes trust roots
  - M7-T3 baseline: manifests now carry `trust` metadata (`unsigned`/`signed`), `sign` command writes detached signatures, and verify/verify-compose can enforce signed artifacts via flags
  - M7-T4 baseline: CI includes dedicated `security` job covering path safety, pack identity pinning, and signing trust-flow regression tests
  - KCIR v2 core verifier migration baseline: `verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors` now runs a native Ref-recursive traversal (`CoreVerifyCtxRef`) and uses `WireCodec::decode_node_refs` at the node boundary; MAP/COVER and OBJ non-pull (`O_UNIT`/`O_PRIM`/`O_MKTENSOR`) checks are v2-native, MOR non-pull (`M_ID`/`M_MKTENSOR`/`M_MKCOMP`) dispatch is ref-native via `verify_mor_opcode_contract_ref_non_pull`, and pull paths (`O_PULL`/`M_PULL`) dispatch through parts-based pull helpers (`verify_*_pull_opcode_contract_parts`) that no longer synthesize `KcirNode` wrappers in `kcir`/`kcir_v2`
  - KCIR v2 wire-format generalization baseline: added `LenPrefixedRefWireCodec` (`kcir.wire.lenprefixed-ref.v1`) with length-prefixed `outRef`/`depRef` node decoding, strict trailing-byte/length diagnostics, and bridge projection for legacy 32-byte contract keys; integration tests now verify MAP literal contracts over non-fixed-width node ref encodings
  - KCIR v2 conformance baseline: conformance runner now supports `mode = "kcir-v2-node"` with wire-format keyed vectors (`wireFormatId`) and golden/adversarial fixtures for `kcir.wire.lenprefixed-ref.v1` (roundtrip decode/encode + trailing-byte rejection)
  - KCIR v2 core conformance baseline: conformance runner now supports `mode = "core-verify-v2"` exercising `verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors` over wire-format keyed fixtures; vectors now cover `kcir.wire.lenprefixed-ref.v1` success and deterministic bridge rejection on short non-projectable refs
  - KCIR v2 Merkle conformance baseline: `core-verify-v2` now supports fixture-provided store evidence (`certEvidence`/`objEvidence`/`morEvidence`) and verifier anchors (`anchors.rootCommitment`/`anchors.treeEpoch`), with vectors covering valid Merkle verification plus deterministic anchor-mismatch and malformed-evidence rejection
  - KCIR v2 cross-profile rejection baseline: `core-verify-v2` vectors now enforce explicit mismatch rejection for hash refs under Merkle verification and Merkle evidence under hash verification
  - Spec linkage baseline: `raw/CONFORMANCE-V2` now cites canonical fixture IDs for cross-profile rejection vectors, binding normative matrix text to concrete repository tests
  - KCIR wire-format manifest selection baseline: `build` now accepts `--kcir-wire-format-id` (`kcir.wire.legacy-fixed32.v1` / `kcir.wire.lenprefixed-ref.v1`), emits matching profile bindings in `ctc.manifest.json`, and verifier profile-binding checks accept any supported wire format while still enforcing scheme/params/version/evidence invariants
  - KCIR v2 bridge-reduction baseline: core verifier no longer materializes legacy `[u8;32]` dep records for MAP/COVER nodes (projection now happens only on OBJ/MOR contract paths and explicit MAP/COVER hook points), reducing non-essential bridge failures on ref-native traversal
  - KCIR v2 MAP/COVER ref-hook baseline: added `RefMapCoverBackend` adapter so MAP/COVER verification logic uses ref-typed hook entrypoints (`bcSquare`, `validateCover`, `coverLen`, `pullCover`) while encapsulating contract-key projection/lift at the boundary
  - KCIR v2 dep-record migration baseline: introduced `DepRecordRef { out: Ref }` (recursive traversal) plus localized `DepRecordKey { out: [u8;32] }` contract adapters, reducing legacy coupling at call boundaries
  - KCIR v2 OBJ/MOR contract migration complete: `O_PULL`/`M_PULL` and MOR non-pull contract checks now run through local ref-native cores in `kcir_v2` (no calls to `kcir::verify_obj_pull_opcode_contract_parts`, `kcir::verify_mor_pull_opcode_contract_parts`, or `kcir::verify_mor_opcode_contract_with_store`)
  - M8-T1 baseline: typed full-profile pipeline API (`src/pipeline.rs`) is wired through build flow (`resolve -> bidir -> admissibility`) with deterministic integration coverage
  - M8-T2 baseline: `ctc.manifest.json` now supports explicit `requiredArtifacts` bindings (`ctcWitnesses`, `admissibilityWitnesses`), `verify --profile full` resolves artifact paths from those bindings (not filename convention), and compose-verify validates referenced pack required-artifact contracts even before deep pack verification
  - M8-T3 baseline: admissibility law-evaluation core now lives in the extracted Premath workspace at `premath/crates/premath-gate` (`evaluate_admissibility` + typed input contract), while `src/gate.rs` is a Paintgun adapter from analysis/cert witnesses to premath inputs; boundary test `tests/gate_boundary.rs` enforces this split
  - M8-T3 baseline: context-poset admissibility kernels now live in `premath/crates/premath-admissibility` (`kan_diag`, `bc_violations`, `stability_failures`, `locality_failures`, `orthogonality_overlaps`); `src/analysis.rs` is now an adapter layer with type-specialized wrappers and boundary coverage in `tests/admissibility_boundary.rs`
  - M8-T3 baseline: generic composability witness data model now lives in `premath/crates/premath-composability` (`ConflictMode`, `AnalysisSummary`, `AnalysisWitnesses`, `Analysis`, witness record types); `src/cert.rs` aliases these as Paintgun CTC types and boundary coverage lives in `tests/composability_boundary.rs`
  - M8-T3 baseline: composability witness assembly kernel now lives in `premath/crates/premath-composability` (`analyze_assignments`), while `src/cert.rs` reduces to assignment/context preparation + adapter closures (`conflict_candidate_from_authored`, resolver-value lookup)
  - M8-T3 baseline: cross-pack conflict witness assembly kernel now lives in `premath/crates/premath-compose` (`assemble_conflicts`), while `src/compose.rs` handles pack-specific value/provenance extraction and manifest/IO concerns; boundary coverage in `tests/compose_boundary.rs`
  - M8-T3 baseline: compose witness data model now lives in `premath/crates/premath-compose` (`ComposeInheritedRef`, `ComposeConflictCandidate`, `ComposeConflictWitness`, `ComposeWitnesses`) with explicit serde bounds preserving compact `inheritedFrom` encoding and deterministic schema validation via Paintgun type aliases in `src/compose.rs`
  - M8-T3 baseline: `premath/crates/premath-compose` now stops at the product-neutral compose kernel (`ComposeSummary`, `summarize_pack_paths`, witness schema/types, and `assemble_conflicts`), while `src/compose.rs` owns the Paintgun compose manifest/report/verify contracts
  - M8-T3 baseline: Paintgun-branded compose reporting now lives in `src/compose.rs` (`render_compose_report_text`, `build_compose_report_json_value`) instead of `premath/crates/premath-compose`, so the kernel crate carries no product report text or manifest schema
  - M8-T3 baseline: compose verification preflight and pack-binding helpers now live in `src/compose.rs` (`check_required_signed`, `check_pack_identity_match`, `validate_witnesses_payload`, `check_manifest_entry_binding`, `fold_pack_verify_outcome`, `prefix_pack_diagnostics`) because those error namespaces and bindings are part of the Paintgun adapter, not the generic kernel
  - M8-T3 baseline: per-pack compose verification callback wiring now lives in `src/compose.rs::verify_pack_with_callbacks`, leaving `premath/crates/premath-compose` focused on deterministic conflict assembly instead of pack manifest/signature orchestration
  - M8-T3 baseline: DTCG domain types now live in `crates/paintgun-dtcg` (`DtcgType`, `TypedValue`, `DtcgValue`, `JValue`); `src/dtcg.rs` is a compatibility re-export so `paintgun::dtcg::*` call sites remain stable
  - M8-T3 baseline: normalization policy domain now lives in `crates/paintgun-policy` (`Policy`, `KcirPolicy`, `CssColorPolicy`, `normalize_value`, `policy_digest`); `src/policy.rs` is a compatibility re-export so existing `paintgun::policy::*` call sites remain stable
  - M8-T3 baseline: emission kernel now lives in `crates/paintgun-emit` (`Emitter`, `CssEmitter`, layer planning, CSS/native emission kernels); `src/emit.rs` is now an adapter layer for resolver/store-specific orchestration and compatibility exports
  - M8-T3 baseline: resolver document/store model now lives in `crates/paintgun-resolver-model` (`ResolverDoc`, `ResolverSource`, `TokenStore`, `context_key`, `parse_context_key`, `axes_from_doc`, input-selection/dedup utilities + typed selection errors); `src/resolver.rs` re-exports/adapts the model while retaining resolver IO/orchestration logic
  - M8-T3 baseline: resolver tree/algebra kernels now live in `crates/paintgun-resolver-kernel` (`deep_merge`, `parse_json_pointer`, source-load/flatten core + typed load/flatten errors, axis-relevance planning, `$extends` core, alias-resolution core + typed kernel errors, materialization, explicit-token path/definition collection, token canonicalization + typed kernel errors); `src/resolver_io.rs` owns filesystem/path callback wiring (`ResolverIo`, `FsResolverIo`), `src/resolver_runtime.rs` owns token-store stage orchestration via direct kernel+io calls, and `src/resolver.rs` is now a compatibility facade/adaptation layer
  - M8-T3 baseline: verify profile-binding/anchor checks are now isolated in `src/verify/profile_binding.rs` (spec-normative logic), while `src/verify.rs` remains artifact/signing/report orchestration
  - M8-T3 baseline: KCIR wire/verification kernel moved to `premath/crates/premath-kcir-kernel` (`kcir_kernel.rs` + hash utilities), while `premath/crates/premath-kcir` now focuses on v2/profile/ref orchestration through the compat seam
  - M8-T4 baseline: typed identifier wrappers now live in `crates/paintgun-ids` (`ContextId`, `TokenPathId`, `WitnessId`, `RefId`, `PackId`), with `src/ids.rs` as a compatibility re-export; the full-profile pipeline boundary accepts typed contract-token sets (`Option<&BTreeSet<TokenPathId>>`) instead of raw strings
  - M8-T4 baseline: report/explain boundaries now consume typed ids (`ReportFinding.witness_id/token_path` and `explain` witness lookup input), while preserving JSON wire compatibility through serde-transparent wrappers
  - M8-T4 baseline: allowlist selector/matcher paths now consume typed ids (`witnessId: WitnessId`, `tokenPath: TokenPathId`) and verify-side allowlist indexing is keyed by `WitnessId` while preserving legacy JSON shape
  - M8-T4 baseline: compose witness records now use typed ids (`ComposeConflictWitness.witness_id/token_path`, `ComposeInheritedRef.witness_id`) with deterministic ordering and report/explain compatibility preserved
- In progress:
  - M8-T3 (crate boundary split by semantics)

## Premath Code Home
- The current code-home and packaging recommendation is documented in `docs/premath_code_home.md`.
- Short version: keep `/Users/arj/dev/fish/sites/premath` as the site/spec/governance surface, keep the extracted Premath crates in `/Users/arj/dev/fish/tools/premath`, and consume them from Paint through the repo-local `./premath` projection.

## Local Notes
- Swift package tests can fail on this workstation due CommandLineTools `PackageDescription` linker mismatch; CI remains the source-of-truth for Swift integration checks.

## Plan Changes To Make (Based on Implementation)
- Update ticket wording to match implemented files and field names (done below).
- Expand Gate behavior vectors for richer composition/cover scenarios and explicit composition-law traces.
- Defer legacy compatibility work; prefer strict structured policy input for this phase.

## Milestone 1: Spec Conformance Harness

Goal: verify all DTCG features this toolchain depends on, with explicit support boundaries.

### M1-T1: Conformance harness scaffolding
- Outcome: table-driven fixture runner for parser/resolver/compose outputs.
- Changes:
  - Add `tests/conformance.rs` fixture runner and utilities.
  - Add fixture layout:
    - `tests/conformance/fixtures/<case-id>/input.json`
    - `tests/conformance/fixtures/<case-id>/expected.json`
    - `tests/conformance/fixtures/<case-id>/meta.toml`
  - Add snapshot update flag (env var), defaulting to strict compare.
- Acceptance:
  - `cargo test conformance_` discovers and executes fixture cases.
  - Failure output includes fixture id and JSON pointer of first mismatch.

### M1-T2: $extends graph semantics coverage
- Outcome: complete tests for extends depth/cycle/merge precedence.
- Cases:
  - linear chain (depth 1..N)
  - diamond graph precedence
  - cycle detection with deterministic error
  - missing ancestor reference
- Acceptance:
  - Deterministic cycle error code and path trace.
  - Merge precedence behavior documented and tested.

### M1-T3: Alias syntax and resolution variants
- Outcome: resolver supports and tests all alias syntaxes used in practice.
- Cases:
  - JSON Pointer refs
  - token-path refs
  - escaped segments (`~0`, `~1`) where applicable
  - nested alias-to-alias chains
  - broken pointer/path diagnostics
- Acceptance:
  - All supported alias forms pass goldens.
  - Unsupported forms fail with explicit "unsupported alias form" diagnostics (no silent fallback).

### M1-T4: $type inheritance/override rules
- Outcome: deterministic behavior for type propagation and mixed aliasing.
- Cases:
  - inherited type from group/token ancestors
  - leaf override of inherited type
  - mixed-type aliasing policy (allow/reject with reason)
- Acceptance:
  - Behavior is stable and captured in `CONFORMANCE.md`.
  - Error payload includes both source/target type identities on mismatch.

### M1-T5: Edge token-tree structures
- Outcome: parser/resolver behavior for non-trivial value trees is explicit.
- Cases:
  - `$root` handling
  - object value leaves
  - array value leaves
  - mixed map + token siblings
- Acceptance:
  - Goldens cover accepted and rejected structures.
  - Rejected structures report pointer-level diagnostics.

### M1-T6: Support matrix and unsupported inventory
- Outcome: published conformance boundary.
- Changes:
  - Add `CONFORMANCE.md` with feature matrix.
  - Add `known_unsupported.json` with reason + tracking ticket.
- Acceptance:
  - Every failing conformance fixture maps to a known unsupported item or an open bug.
  - CI job uploads conformance summary artifact.

### M1-T7: CI gate for conformance
- Outcome: no regressions in supported behavior.
- Changes:
  - Add GitHub Actions job: `conformance`.
  - Ensure deterministic locale/timezone for snapshot stability.
- Acceptance:
  - PR fails on supported fixture regression.
  - Optional/manual snapshot update path is documented.

## Milestone 2: Provenance Completion

Goal: all witnesses provide actionable blame metadata in direct and composed certs.

### M2-T1: Witness schema v1 and validator
- Outcome: single schema for witness records across outputs.
- Required fields:
  - `witnessId`
  - `resolutionLayerId`, `resolutionRank`
  - `packId`, `packHash` (`packVersion` optional)
  - `filePath`, `fileHash`, `jsonPointer`
  - `source_context`, `source_id`, `value_json`, `value_digest` (where applicable)
- Changes:
  - Add schema file: `schemas/witness.schema.json`.
  - Add validation in test harness.
- Acceptance:
  - All emitted witnesses validate against schema.

### M2-T2: Pack identity propagation
- Outcome: pack metadata available at every conflict emission site.
- Changes:
  - Thread pack identity through parse -> resolve -> compose pipelines.
  - Include metadata in `ctc.witnesses.json` and meta-cert witnesses.
- Acceptance:
  - Spot-check tests verify correct pack identity on multi-pack conflicts.

### M2-T3: File hashing + stable relative paths
- Outcome: source files referenced reproducibly.
- Changes:
  - Compute source file hash at ingest.
  - Normalize and store workspace-relative source path.
- Acceptance:
  - Same input yields identical file hashes and paths across runs.
  - No absolute machine-local paths in outputs.

### M2-T4: JSON pointer precision at defining leaf
- Outcome: witness points to exact authoring leaf.
- Changes:
  - Ensure pointer survives alias/extends traversal.
  - Track defining leaf separately from resolved leaf when needed.
- Acceptance:
  - For alias-derived conflicts, witness includes defining leaf pointer.
  - Pointer remains stable after composition/normalization passes.

### M2-T5: Resolution-order provenance
- Outcome: include layer/rank where winner/loser chosen.
- Changes:
  - Persist `resolution.layerId` and `resolution.rank` at compare step.
  - Add to conflicts and tie-break witnesses.
- Acceptance:
  - Tie-break witness always contains rank/layer for each candidate.

### M2-T6: Meta-cert provenance retention
- Outcome: composed outputs keep original blame data (no lossy flattening).
- Changes:
  - Preserve source witness references in meta-cert assembly.
  - Add optional `inheritedFrom` links for transitive composition.
- Acceptance:
  - Meta-cert witness can be traced to original pack leaf without ambiguity.

### M2-T7: Provenance regression fixtures
- Outcome: locked-in behavior for witness completeness.
- Changes:
  - Add `tests/provenance/*` fixture sets with expected witness records.
- Acceptance:
  - Missing provenance field fails test with clear field name.
  - Multi-pack conflict fixture verifies both sides fully attributed.

### M2-T8: CI enforcement for witness completeness
- Outcome: provenance cannot regress silently.
- Changes:
  - Add CI checks running witness schema validation + provenance fixtures.
  - Add compose witness schema validation check.
  - Emit machine-readable failure report for PR annotation.
- Acceptance:
  - CI fails on schema mismatch or missing required fields.

### M2-T9: Strict Schema Versioning
- Outcome: explicit schema version markers and strict witness validation.
- Changes:
  - Add schema version marker in per-pack and compose witness outputs.
  - Make schema validators enforce expected version.
  - Keep verify paths strict for current-format artifacts.
- Acceptance:
  - New outputs validate under strict schema.
  - Version mismatch fails with deterministic diagnostics.

## Milestone 3: Conflict Modes + Policy Digest

Goal: let CI choose strict semantic governance or pragmatic observable behavior checks.

### M3-T1: CLI conflict mode surface
- Outcome: user-selectable conflict comparator mode.
- Changes:
  - Add `--conflict-mode semantic|normalized` to build/verify paths.
  - Default mode explicitly documented.
- Acceptance:
  - CLI help and README document both modes and intended use.
  - Invalid mode values produce deterministic CLI error.

### M3-T2: Semantic comparator path
- Outcome: strict conflict detection on structured resolved intent.
- Changes:
  - Route semantic mode through pre-normalization `Res` compare.
  - Ensure typed mismatch diagnostics preserve type context.
- Acceptance:
  - Fixtures prove semantic conflict catches cases normalized mode may hide.

### M3-T3: Normalized comparator path
- Outcome: observable conflict detection after target/policy normalization.
- Changes:
  - Route normalized mode through policy normalizer and target-specific emit shape.
  - Emit normalization trace markers in witness evidence.
- Acceptance:
  - Fixtures prove normalized mode can pass where semantic mode fails.

### M3-T4: Policy digest capture in cert artifacts
- Outcome: certs bind to the exact policy used to adjudicate conflicts.
- Changes:
  - Add deterministic digest of policy payload and normalizer version.
  - Write fields to `ctc.manifest.json` and related cert summaries.
- Acceptance:
  - Same policy yields same digest; modified policy changes digest.
  - Verify step fails on digest mismatch when digest is required.

### M3-T5: Mode-aware report fields
- Outcome: reports include enough metadata for governance decisions.
- Changes:
  - Include `conflictMode`, `policyDigest`, `normalizerVersion` in machine-readable outputs.
- Acceptance:
  - Report schema validates with new fields in both modes.

## Milestone 4: Contract-Bounded Evaluation

Goal: runtime scales with shipped contexts, not theoretical cartesian product.

### M4-T1: Context selection modes
- Outcome: explicit evaluation strategy options.
- Changes:
  - Add `--contexts full-only|partial|from-contracts`.
  - Define precedence if both contract file and mode are provided.
- Acceptance:
  - CLI behavior is deterministic and validated by mode fixtures.

### M4-T2: Context planner implementation
- Outcome: minimal context set computed from contract references.
- Changes:
  - Build planner that resolves required full and partial contexts per component set.
  - Keep planner output introspectable for diagnostics.
- Acceptance:
  - Planner output snapshot tests pass for representative contract sets.

### M4-T3: Partial-context layering correctness
- Outcome: bounded evaluation does not break layering/precedence semantics.
- Changes:
  - Ensure tie-break and inheritance still compute correctly on subset contexts.
- Acceptance:
  - Subset mode results match full mode for covered components and selected contexts.

### M4-T4: Performance benchmark harness
- Outcome: measurable and enforceable scale improvements.
- Changes:
  - Add benchmark fixtures (`small`, `medium`, `large` axes).
  - Capture wall-time and context-count metrics.
- Acceptance:
  - `from-contracts` shows reduced evaluated contexts on medium/large fixtures.
  - CI regression threshold alerts on >X% slowdown (threshold documented).

### M4-T5: Explainability of bounded evaluation
- Outcome: developers can see why a context was included.
- Changes:
  - Add trace report of included/excluded contexts with rule/source.
- Acceptance:
  - `--format json` includes planner trace section when requested.

## Milestone 5: UX + CI Polish

Goal: reports are machine-actionable and directly fix-oriented for PR workflows.

### M5-T1: JSON report format and schema
- Outcome: stable machine-readable reports.
- Changes:
  - Add `--format json` output for build/verify diagnostics.
  - Publish `schemas/report.schema.json`.
- Acceptance:
  - JSON schema validation runs in CI.
  - Required fields include witness ids and file/pointer locations.

### M5-T2: Stable/minimal witness shape
- Outcome: deterministic outputs with low noise.
- Changes:
  - Canonical ordering for witnesses and deterministic witness-id generation.
  - Remove redundant fields from witness payload.
- Acceptance:
  - Re-running on same input yields identical witness IDs/order.

### M5-T3: Allowlist support for known tie-breaks
- Outcome: explicit governance for accepted BC conflicts.
- Changes:
  - Add `--allowlist <bc.json>` support in verify.
  - Annotate which findings were allowlisted and why.
- Acceptance:
  - Allowlisted entries suppress failure only for exact matching witness IDs or selectors.
  - Missing/stale allowlist entries fail with clear reason.

### M5-T4: `paint explain <witness-id>`
- Outcome: shortest fix path from witness to source.
- Changes:
  - Add explain subcommand resolving witness -> source location -> remediation text.
- Acceptance:
  - Explain output includes exact file path and JSON pointer.
  - Unknown witness id returns deterministic not-found error.

### M5-T5: GitHub Actions annotation integration
- Outcome: CI comments pin failures to exact files/pointers in PRs.
- Changes:
  - Add annotation mapper from JSON report to GH Actions format.
- Acceptance:
  - Sample PR run produces inline annotations for at least one fixture failure.

## Milestone 6: Packaging + Integration

Goal: emitted native artifacts are consumable by real app toolchains.

### M6-T1: Swift emitter package scaffold
- Outcome: generated Swift Package is directly importable.
- Changes:
  - Emit `Package.swift`, module sources, and test target in `dist/swift`.
- Acceptance:
  - `swift test` passes in generated package fixture.

### M6-T2: Android Compose emitter package scaffold
- Outcome: generated Android Compose module/resources are directly consumable.
- Changes:
  - Emit Gradle module or resource package in `dist/android`.
  - Emit typed wrappers for Compose consumption.
- Acceptance:
  - `./gradlew test` passes in generated fixture module.

### M6-T3: Versioned emitter API surface
- Outcome: stable integration contract for consumers.
- Changes:
  - Add explicit emitter output version markers.
  - Document naming/enums/access patterns.
- Acceptance:
  - Breaking output changes require version bump and changelog entry.

### M6-T4: Integration demo apps/tests
- Outcome: end-to-end confidence on native consumers.
- Changes:
  - Add minimal Swift and Kotlin demo integrations (or integration tests) that import emitted artifacts.
- Acceptance:
  - CI executes demo/integration checks successfully.

## Milestone 7: Supply-Chain Hygiene

Goal: cert and pack artifacts are safe and verifiable in automated pipelines.

### M7-T1: Pack identity pinning
- Outcome: certs explicitly bind pack identity and content.
- Changes:
  - Enforce `name + version + contentHash` checks during verify.
- Acceptance:
  - Tampered payload or mismatched identity deterministically fails verify.

### M7-T2: Safe file IO hardening
- Outcome: archive/path handling is traversal-safe.
- Changes:
  - Enforce path canonicalization and root-bound checks for ingest/output.
  - Add rejection for unsafe path segments.
- Acceptance:
  - Security fixtures for traversal attempts fail safely.

### M7-T3: Manifest/cert signing design + optional command
- Outcome: clear path to Sigstore/cosign adoption.
- Changes:
  - Add `SIGNING.md` design doc and optional signing command interface.
  - Include unsigned/signed status in manifest metadata.
- Acceptance:
  - Verification flow handles unsigned policy explicitly and validates signatures when present.

### M7-T4: Security CI checks
- Outcome: trust regressions are blocked before merge.
- Changes:
  - Add CI job for security fixtures + identity checks.
- Acceptance:
  - CI fails on path safety regressions or trust-policy violations.

## Work Sequence (recommended)
1. M1-T1
2. M1-T2, M1-T3, M1-T4, M1-T5 (parallelizable)
3. M1-T6
4. M1-T7
5. M2-T1
6. M2-T2, M2-T3, M2-T4, M2-T5 (parallelizable)
7. M2-T6
8. M2-T7
9. M2-T8
10. M2-T9
11. M3-T1, M3-T2, M3-T3
12. M3-T4, M3-T5
13. M4-T1, M4-T2
14. M4-T3, M4-T4, M4-T5
15. M5-T1, M5-T2
16. M5-T3, M5-T4, M5-T5
17. M6-T1, M6-T2
18. M6-T3, M6-T4
19. M7-T1, M7-T2
20. M7-T3, M7-T4

## Definition of Done for this program phase
- Conformance:
  - Supported feature set is executable as tests and gated in CI.
  - Unsupported features are explicitly listed and surfaced via deterministic diagnostics.
- Provenance:
  - Every witness in direct and meta outputs has pack/file/pointer/resolution metadata.
  - Witness schema validation is part of CI required checks.
- Conflict governance:
  - Semantic and normalized modes are both test-covered and policy-bound.
- Scale:
  - Contract-bounded evaluation is available and benchmarked in CI.
- Developer UX:
  - JSON reports, explain workflow, and PR annotations are operational.
- Integration:
  - Swift/Kotlin emitted artifacts are validated by integration tests.
- Supply chain:
  - Identity checks and path safety checks are enforced in CI.

## Risk Register (M1-M7)
- R1: Ambiguous DTCG interpretation for edge cases.
  - Mitigation: document interpretation in `CONFORMANCE.md` + fixture references.
- R2: Pointer drift after normalization/composition.
  - Mitigation: track authoring pointer as immutable provenance field.
- R3: Snapshot brittleness.
  - Mitigation: canonical JSON ordering and deterministic runtime settings in CI.
- R4: Mode confusion between semantic and normalized conflict checks.
  - Mitigation: include mode + policy digest in all reports and cert artifacts.
- R5: Planner correctness regressions under context subsetting.
  - Mitigation: equivalence tests against full evaluation for covered components.
- R6: Consumer breakage from emitter output churn.
  - Mitigation: versioned emitter surface and integration tests.
- R7: Trust model drift in unsigned pipelines.
  - Mitigation: explicit trust policy states and signature verification path.

## Suggested ticket labels
- `spec-conformance`
- `provenance`
- `ci`
- `diagnostics`
- `good-first-fixture`
- `performance`
- `native-emitter`
- `supply-chain`

## Milestone 8: Architecture Consolidation (Long-Range)

Goal: make full-profile verification a single typed pipeline with strict crate boundaries and no bypass paths.

### M8-T1: Typed core pipeline API (start here)
- Outcome: first-class stage API for `resolve -> bidir -> admissibility`.
- Changes:
  - Add `src/pipeline.rs` with explicit stage structs and a `run_full_profile_pipeline(...)` entrypoint.
  - Keep behavior equivalent to existing build/verify paths while centralizing stage boundaries.
- Acceptance:
  - Unit/integration test proves deterministic stage outputs and admissibility result on a known fixture.
  - Existing CLI behavior remains unchanged.

### M8-T2: Manifest-required artifact contract
- Outcome: full profile is validated by declared required artifacts, not filename convention.
- Changes:
  - Extend manifest contract with explicit required artifacts list for profile `full`.
  - Enforce in verify/compose-verify.
- Acceptance:
  - Missing or mismatched full-profile artifact bindings deterministically reject with stable codes.

### M8-T3: Crate boundary split by semantics
- Outcome: stable architecture boundaries.
- Changes:
  - Introduce/finish crate separation: `paintgun-dtcg`, `premath-bidir`, `premath-admissibility`, `premath-kcir`, `paintgun-emit`, `paintgun`.
  - Remove cross-layer type leakage (no DTCG types in premath crates; no crypto/wire details outside kcir).
- Acceptance:
  - `cargo tree` and module references show no forbidden cross-layer imports.

### M8-T4: Strongly typed identifiers
- Outcome: reduce stringly-typed mismatches in internal APIs.
- Changes:
  - Introduce typed wrappers (`ContextId`, `TokenPathId`, `WitnessId`, `RefId`, `PackId`) at pipeline boundaries.
- Acceptance:
  - Stage APIs no longer accept raw `String` where typed IDs exist.

### M8-T5: Stage-level deterministic cache keys
- Outcome: reproducible and efficient incremental runs.
- Changes:
  - Add cache-key derivation per stage from content hash + profile + policy digest + wire/profile ids.
- Acceptance:
  - Repeated runs hit cache deterministically; invalidation behaves correctly on input/profile/policy changes.

### M8-T6: Backend capability declaration contract
- Outcome: pluggable commitment backends with explicit capability surfaces.
- Changes:
  - Add a capability descriptor for `VerifierProfile` / `WireCodec` pairs.
  - Keep admissibility backend-agnostic.
- Acceptance:
  - Cross-profile mismatch failures remain deterministic and test-covered.

### M8-T7: Unified witness engine package
- Outcome: one source of truth for witness IDs, ordering, classes, and explain recipes.
- Changes:
  - Consolidate witness construction/validation/order logic shared by conformance/runtime/CLI explain.
- Acceptance:
  - Determinism checks pass from a single implementation path.

### Recommended execution order
1. M8-T1
2. M8-T2
3. M8-T3
4. M8-T4
5. M8-T5
6. M8-T6
7. M8-T7
