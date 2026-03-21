# Conformance Fixtures Layout

This tree supports profile-based conformance vectors.

- `core/golden` and `core/adversarial` contain active v2 kernel vectors
  (`kcir-v2-node`, `core-verify-v2`, and DSL modes).
- `gate/golden` and `gate/adversarial` contain full-profile GATE vectors.
- `bidir/golden` and `bidir/adversarial` contain full-profile
  bidirectional/descent conformance vectors (mode discipline + Gate-class
  mapping expectations).

Legacy archived-v1 KCIR fixture modes (`kcir-node`, `core-verify`, `nf-obj`,
`nf-mor`, `opcode-obj`, `opcode-mor`) were moved to
`tests/conformance/fixtures_archive_v1/`.
The active runner treats those modes as archived and rejects them if they
appear under `tests/conformance/fixtures/`.

Fixture runners identify a case directory by the presence of `meta.toml`.

Admissibility witness fixtures use `mode = "admissibility-witness"` and validate `input.json`
against `schemas/admissibility_witness.schema.json`.

Gate behavioral fixtures use `mode = "gate-analysis"` with an inline
`resolver` object in `input.json`; the runner executes resolver + composability
analysis and maps resulting diagnostics to Gate failure classes/law refs
(`GATE-3.1` through `GATE-3.5`). `GATE-3.1` is derived from explicit
composition-path disagreement evidence.

Bidirectional/descent fixtures use `mode = "bidir-analysis"` and enforce
authored-only synthesis, derived-context checking, discharge success, and
deterministic Gate-class mapping on discharge failure.

KCIR v2 wire-format fixtures use `mode = "kcir-v2-node"` and validate
codec decode/roundtrip with profile metadata (`wireFormatId`, `schemeId`,
`paramsHash`).

KCIR v2 DAG fixtures use `mode = "core-verify-v2"` and validate recursive
verification over Ref-keyed stores with profile binding/evidence/anchors.

Core DSL fixtures:
- `mode = "dsl-unique"` validates UniqueSpec matching semantics over dependency
  shape slices (`first`/`last`/`index`/`anywhere` + optional handling).
- `mode = "dsl-bag"` validates BagSpec key matching semantics (`ordered` /
  `unordered`, slice vs `anywhere` behavior, ambiguity rejection, and
  `expectedKeysFromBinding` resolution).
- `mode = "dsl-multibag"` validates MultiBagSpec partitioning semantics
  (exact slot matching, ambiguity rejection, `consumeAll` handling, and
  binding-derived expected key expansion).
