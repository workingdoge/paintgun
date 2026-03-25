# Premath Standalone Workspace Prep

This document defines the standalone ownership boundary for the extracted `premath-*` crates that Paint now consumes from the sibling Premath repo.

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

## Ownership boundary

These crates are treated as reusable Premath kernels, not Paint product crates.

The current boundary is:

- no `premath-*` crate depends on `paintgun-*`
- no `premath-*` crate exposes Paintgun-branded public types
- product CLI, target emitters, manifests, reports, and trust flows remain in Paint

Generic artifact vocabulary such as `pack`, `manifest`, `context`, or `witness` remains acceptable where it describes kernel behavior rather than Paint-specific runtime contracts.

## Standalone entrypoint used from Paint

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

This entrypoint intentionally excludes the Paint CLI and product integration tests, and delegates to the extracted Premath workspace.

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
