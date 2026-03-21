# Premath Capability Vector Status

Scope: `adoptPullAtomMor` from `specs/premath/raw/CAPABILITY-VECTORS.md`.

## Current state (this repo)

- [x] unclaimed: `nf-mor` tag `0x16` reject
  - `tests/conformance/fixtures/core/adversarial/nf_mor_pull_atom_tag_unadopted`
- [x] unclaimed: `opcode-mor` step `0x04` reject
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_unadopted`
- [x] unclaimed: `opcode-mor` step `0x07` reject
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_wrap_unadopted`
- [x] unclaimed: `core-verify` step `0x04` reject
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_unadopted`
- [x] unclaimed: `core-verify` step `0x07` reject
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_wrap_unadopted`

- [x] claimed: `nf-mor` tag `0x16` accept
  - `tests/conformance/fixtures/core/golden/nf_mor_pull_atom_hashcheck_adopted`
- [x] claimed: `opcode-mor` step `0x04` accept
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_fuse_pullatom_adopted`
- [x] claimed: `opcode-mor` step `0x07` accept
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_wrap_adopted`
- [x] claimed: `core-verify` step `0x04` accept
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_fuse_pullatom_adopted`
- [x] claimed: `core-verify` step `0x07` accept
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_wrap_adopted`
- [x] claimed adversarial: `opcode-mor` step `0x04` bad-out reject
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_adopted_bad_out`
- [x] claimed adversarial: `opcode-mor` step `0x07` bad-out reject
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_wrap_adopted_bad_out`
- [x] claimed adversarial: `core-verify` step `0x04` contract failure reject
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_adopted_bad_out`
- [x] claimed adversarial: `core-verify` step `0x07` contract failure reject
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_wrap_adopted_bad_out`

## Next vectors to add

- none currently (coverage set is complete for the current `adoptPullAtomMor` hardening scope)

## Hardening additions (2026-02-16)

- [x] claimed fusion edge: `composeMaps` missing rejection (opcode + core-verify)
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_adopted_missing_compose_map`
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_adopted_missing_compose_map`
- [x] claimed fusion edge: composed id-map collapse acceptance (opcode)
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_fuse_pullatom_adopted_compose_id_collapse`
- [x] claimed prelude mismatch: expected `0x04` vs provided `0x07`
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_adopted_step_mismatch_wrap`
- [x] claimed prelude mismatch: expected `0x07` vs provided `0x04`
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_wrap_adopted_step_mismatch_fuse`
- [x] claimed canonicality: nested PullAtom rejection under `enforceCanonicalNf` (NF + opcode prelude)
  - `tests/conformance/fixtures/core/adversarial/nf_mor_pull_atom_nested_pullatom_noncanonical_store`
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_adopted_noncanonical_prelude`
- [x] claimed fusion edge: composed id-map collapse acceptance (core-verify)
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_fuse_pullatom_adopted_compose_id_collapse`
- [x] claimed prelude mismatch: expected `0x04` vs provided `0x07` (core-verify)
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_adopted_step_mismatch_wrap`
- [x] claimed prelude mismatch: expected `0x07` vs provided `0x04` (core-verify)
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_wrap_adopted_step_mismatch_fuse`
- [x] claimed canonicality: nested PushAtom rejection under `enforceCanonicalNf` (NF + opcode/core prelude)
  - `tests/conformance/fixtures/core/adversarial/nf_mor_push_atom_nested_pushatom_noncanonical_store`
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_wrap_adopted_noncanonical_prelude_push_chain`
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_wrap_adopted_noncanonical_prelude_push_chain`
- [x] claimed canonicality: nested PullAtom rejection under `enforceCanonicalNf` (core-verify prelude)
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_adopted_noncanonical_prelude`
- [x] claimed identity-map mode: adopted `stepTag=0x00` for PullAtom/PushAtom (opcode + core-verify)
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_id_adopted_idmap_pullatom`
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_id_adopted_idmap_pushatom`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_id_adopted_idmap_pullatom`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_id_adopted_idmap_pushatom`
- [x] claimed BC-vs-WRAP boundary: explicit `bcAllowedPairs` step classification (opcode + core-verify)
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_wrap_adopted_bc_allowed_pair_step_mismatch`
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_bc_swap_adopted_no_bc_allowed_step_mismatch`
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_wrap_adopted_bc_allowed_pair_step_mismatch`
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_bc_swap_adopted_no_bc_allowed_step_mismatch`
- [x] claimed BC boundary positive: explicit `bcAllowedPairs` acceptance with full `M_PULL.BC_SWAP` role deps (opcode + core-verify)
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_bc_swap_adopted_bc_allowed_pair_roles`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_bc_swap_adopted_bc_allowed_pair_chain`
- [x] Obj pull identity-map parity: `O_PULL stepTag=0x00` acceptance on spine inputs (opcode + core-verify)
  - `tests/conformance/fixtures/core/golden/opcode_obj_pull_id_idmap_pullspine`
  - `tests/conformance/fixtures/core/golden/opcode_obj_pull_id_idmap_pushspine`
  - `tests/conformance/fixtures/core/golden/core_verify_obj_pull_id_idmap_pullspine`
  - `tests/conformance/fixtures/core/golden/core_verify_obj_pull_id_idmap_pushspine`
- [x] identity-map + canonicality interaction: `stepTag=0x00` bypasses prelude canonical parsing when `isIdMap(pId)` is true, even with non-canonical store entries present (opcode + core-verify)
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_id_idmap_noncanonical_prelude_bypass`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_id_idmap_noncanonical_prelude_bypass`
  - `tests/conformance/fixtures/core/golden/opcode_obj_pull_id_idmap_noncanonical_prelude_bypass`
  - `tests/conformance/fixtures/core/golden/core_verify_obj_pull_id_idmap_noncanonical_prelude_bypass`
- [x] partial-store canonicality: nested atoms accepted when inner entries are absent (NF + opcode/core prelude)
  - `tests/conformance/fixtures/core/golden/nf_mor_pull_atom_nested_partial_store_canonical`
  - `tests/conformance/fixtures/core/golden/nf_mor_push_atom_nested_partial_store_canonical`
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_wrap_adopted_partial_store_canonical`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_wrap_adopted_partial_store_canonical`
- [x] mixed-chain canonicality: `PullAtom(PushAtom(...))` and `PushAtom(PullAtom(...))` accepted when inner entries are present (NF + opcode/core prelude)
  - `tests/conformance/fixtures/core/golden/nf_mor_pull_atom_nested_pushatom_store_canonical`
  - `tests/conformance/fixtures/core/golden/nf_mor_push_atom_nested_pullatom_store_canonical`
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_fuse_pullatom_adopted_mixed_nested_canonical`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_fuse_pullatom_adopted_mixed_nested_canonical`
  - `tests/conformance/fixtures/core/golden/opcode_mor_pull_wrap_adopted_mixed_nested_canonical`
  - `tests/conformance/fixtures/core/golden/core_verify_mor_pull_wrap_adopted_mixed_nested_canonical`
- [x] compose-id collapse hardening: `M_PULL.FUSE_PULLATOM` rejects non-collapsed out when `composeMaps` resolves to an id map (opcode + core-verify)
  - `tests/conformance/fixtures/core/adversarial/opcode_mor_pull_fuse_pullatom_adopted_compose_id_collapse_noncollapsed_out`
  - `tests/conformance/fixtures/core/adversarial/core_verify_mor_pull_fuse_pullatom_adopted_compose_id_collapse_noncollapsed_out`

## Notes

- Current implementation supports both unclaimed and claimed behavior for
  `adoptPullAtomMor` through `baseApi.adoptPullAtomMor`.
