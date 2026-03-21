# JJ Parallel Workspaces

This repo now has 3 `jj` workspaces sharing one history:

- `default`: `tbp_rs/`
- `resolver`: `tbp_rs_ws_resolver/`
- `protocol`: `tbp_rs_ws_protocol/`

Use this layout for true parallel work without branch collisions.

## Operating Model

1. One workspace = one scope.
2. Keep commits small and scope-specific.
3. Export to git only when a workspace checkpoint is ready.
4. Rebase/merge through `jj`, then verify with `cargo fmt --check && cargo test -q`.

## Track A: Resolver Layering Completion (`resolver` workspace)

Objective:
- Finish `M8-T3` resolver layering cleanup.

Scope:
- Keep `src/resolver.rs` as compatibility facade.
- Keep `src/resolver_runtime.rs` as orchestration.
- Keep `src/resolver_io.rs` as host IO seam.
- Move any remaining adapter/error-mapping glue out of facade where feasible.

Definition of done:
- No runtime dependency on facade helper functions.
- Boundary tests cover facade/runtime/io split.
- Full tests pass.

Suggested commands:

```bash
cd /Users/arj/dev/workingdoge/archive/tbp_rs_multipack_meta_ci_unzipped/tbp_rs_ws_resolver
jj status
cargo fmt --check
cargo test -q
jj describe -m "m8-t3: finalize resolver facade/runtime/io split"
jj git export
```

## Track B: PCP Protocol Drafting (`protocol` workspace)

Objective:
- Draft the Premath Compose Protocol (PCP) interfaces and layering.

Scope:
- Define crate boundaries and trait contracts:
  - `premath-core`
  - `premath-protocol`
  - `premath-policy`
  - adapter traits (`RepoAdapter`, `IdentityAdapter`, `TransportAdapter`)
- Keep this pass documentation-first unless explicitly implementing crates.

Definition of done:
- Concrete trait signatures and data model drafts exist in-repo.
- Determinism + canonicalization + attestation envelope requirements are explicit.
- Clear migration map from current `tbp_*` crates to PCP layering.

Suggested commands:

```bash
cd /Users/arj/dev/workingdoge/archive/tbp_rs_multipack_meta_ci_unzipped/tbp_rs_ws_protocol
jj status
jj describe -m "pcp: draft protocol layering and adapter traits"
jj git export
```

## Coordination Checklist

Before starting a session:
- `jj workspace list`
- `jj status`

Before handoff/merge:
- `cargo fmt --check`
- `cargo test -q`
- `jj log -r @:: -n 5`
- `jj git export`

## Important Constraint

The agent running in one terminal cannot directly control another Codex instance.
Parallelism is achieved by:

1. Separate `jj` workspaces
2. Explicit scope contracts
3. Deterministic checkpoints and handoff notes

