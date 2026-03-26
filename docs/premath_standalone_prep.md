# Premath Standalone Workspace Prep

This document is intentionally narrow. It defines the Paint-side consumer
boundary for the extracted `premath-*` crates that Paint consumes from the
sibling Premath repo.

The cross-repo ownership split and archive-porting boundary are canonical in:

- `/Users/arj/dev/fish/tools/premath/docs/migration_boundary.md`

## Scope

The standalone subset is:

- `premath-admissibility`
- `premath-composability`
- `premath-compose`
- `premath-dsl`
- `premath-gate`
- `premath-kcir-kernel`
- `premath-kcir`

These crates are the first extraction wave named in `docs/premath_extraction_contract.md`, and they now live in `/Users/arj/dev/fish/tools/premath`.

## Paint-side boundary

These crates are treated as reusable Premath kernels, not Paint product crates.

From the Paint side, the boundary is:

- no `premath-*` crate depends on `paintgun-*`
- no `premath-*` crate exposes Paintgun-branded public types
- product CLI, target emitters, manifests, reports, and trust flows remain in Paint

Generic artifact vocabulary such as `pack`, `manifest`, `context`, or `witness` remains acceptable where it describes kernel behavior rather than Paint-specific runtime contracts.

## Standalone entrypoint used from Paint

The canonical Premath workspace entrypoint now lives in the extracted repo:

```bash
/Users/arj/dev/fish/tools/premath/scripts/workspace_ci.sh
```

From the Paint repo root, use the consumer-side wrapper:

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

This wrapper intentionally excludes the Paint CLI and product integration tests,
and delegates to the extracted Premath workspace.

Paint's general Cargo commands also consume Premath through a repo-local `./premath` projection. The supported local setup flow is:

```bash
./scripts/link_premath_checkout.sh ../premath
```

## Metadata contract

Current standalone metadata for the `premath-*` crates:

- lockstep `0.1.0`
- `publish = false`
- documented MSRV: Rust `1.89`
- package descriptions present in each crate manifest

Workspace-level discovery metadata in Paint records the extracted member set and the external workspace entrypoint.

## Remaining blockers

There are no remaining direct Paint-code dependencies inside the `premath-*` crates.

The remaining extraction blockers are repo-level concerns:

- final Paint cutover cleanup
- CI and contributor-flow normalization around the extracted workspace
- any future publication/release work

Those blockers are handled by `tbp-e3k.5` and later follow-up work.
