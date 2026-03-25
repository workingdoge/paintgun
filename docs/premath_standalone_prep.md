# Premath Standalone Workspace Prep

This document defines the standalone ownership boundary for the in-tree `premath-*` crates while they still live in the Paint workspace.

## Scope

The standalone subset is:

- `premath-admissibility`
- `premath-composability`
- `premath-compose`
- `premath-dsl`
- `premath-gate`
- `premath-kcir-kernel`
- `premath-kcir`

These crates are the first extraction wave named in `docs/premath_extraction_contract.md`.

## Ownership boundary

These crates are treated as reusable Premath kernels, not Paint product crates.

The current boundary is:

- no `premath-*` crate depends on `paintgun-*`
- no `premath-*` crate exposes Paintgun-branded public types
- product CLI, target emitters, manifests, reports, and trust flows remain in Paint

Generic artifact vocabulary such as `pack`, `manifest`, `context`, or `witness` remains acceptable where it describes kernel behavior rather than Paint-specific runtime contracts.

## Standalone entrypoint

The Premath-only build/test entrypoint is:

```bash
./scripts/premath_workspace_ci.sh
```

Supported modes:

```bash
./scripts/premath_workspace_ci.sh check
./scripts/premath_workspace_ci.sh test
./scripts/premath_workspace_ci.sh clippy
./scripts/premath_workspace_ci.sh fmt
```

This entrypoint intentionally excludes the Paint CLI and product integration tests.

## Metadata contract

Current standalone metadata for the `premath-*` crates:

- lockstep `0.1.0`
- `publish = false`
- documented MSRV: Rust `1.89`
- package descriptions present in each crate manifest

Workspace-level discovery metadata is recorded in `Cargo.toml` under `workspace.metadata.premath`.

## Remaining blockers

There are no remaining direct Paint-code dependencies inside the `premath-*` crates.

The remaining extraction blockers are repo-level concerns:

- creating the dedicated Premath code repo/workspace
- physically moving the crate sources
- rewiring Paint to consume the extracted workspace

Those blockers are handled by `tbp-e3k.3`, `tbp-e3k.4`, and `tbp-e3k.5`.
