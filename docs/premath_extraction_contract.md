# Premath Extraction Contract

## Purpose

This document turns the code-home decision in `docs/premath_code_home.md` into an executable extraction contract.

The question here is no longer whether Premath code should leave the Paint workspace. The question is exactly what moves, where it moves, and what remains product-owned after the move.

## Binding decisions

- The extracted code home is a dedicated sibling code repo/workspace, not `sites/premath`.
- `sites/premath` remains the site, spec, governance, and curated-reference surface.
- The working target name for the extracted code home is `premath`, with a sibling repo path under `fish/tools/premath`.
- The first extraction wave moves the reusable `premath-*` Rust crates only.
- Paint remains the product owner for the CLI, product manifests, target emitters, trust/report flows, and all `paintgun-*` crates.

## First extraction wave

The first extraction wave moves exactly these crates:

- `premath-admissibility`
- `premath-composability`
- `premath-compose`
- `premath-dsl`
- `premath-gate`
- `premath-kcir-kernel`
- `premath-kcir`

These crates move together as one lockstep workspace. Do not split the first wave into per-crate repo moves.

## What stays in Paint

The extraction does not move the Paint product.

The following remain owned by this repo:

- the root `paintgun` package and CLI
- all `paintgun-*` crates
- DTCG-specific resolver and emitter flows
- product manifests, report schemas, and signing/trust orchestration
- target-backend packaging and release machinery
- product examples, fixtures, and adoption docs

If a crate or API still depends on those product surfaces, it is not extraction-ready and must be handled by follow-up cleanup before or during `tbp-e3k.2`.

## Target repo and workspace shape

The extracted Premath code home should start as a code-only Rust workspace rooted at `fish/tools/premath`.

The initial workspace contract is:

- one git repo dedicated to Premath code
- one virtual Cargo workspace at the repo root
- one `crates/` directory containing the extracted `premath-*` crates
- one top-level `README.md` explaining scope, consumers, and local development
- one `docs/` directory for release/checklist and CI contract material
- no product CLI package at the repo root
- no site/spec/governance content beyond code-adjacent contributor docs

The extracted workspace should not depend on Paint as a build-time or test-time prerequisite.

## Versioning and publication

The extracted workspace starts with one lockstep `0.x` version line across the first-wave crates.

Initial publication policy:

- keep `publish = false` during the extraction and first consumer cutover
- do not promise per-crate independent semver yet
- treat extraction as ownership separation first, public package release second

Reconsider public publication only after the extracted workspace is stable as a standalone code home.

## Release ownership

The extracted workspace needs explicit code ownership independent of `sites/premath`.

At minimum, the extracted code home must define:

- a maintainer or maintainer group for code review and releases
- a documented MSRV
- a release checklist that does not depend on the Paint CLI release flow
- a CI entrypoint that validates the extracted workspace without invoking product-specific commands

## CI contract

The extracted workspace must support these baseline checks as first-class entrypoints:

- `cargo check --workspace`
- `cargo test --workspace`
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets`

If additional law/conformance checks are required for Premath kernels, they should be expressed as repo-local commands in the extracted workspace rather than delegated back to Paint.

## Consumer contract

After extraction:

- Paint consumes Premath as an external code home
- the dependency direction is `paint -> premath`, never `premath -> paint`
- Paint-specific adapters stay in Paint
- generic Premath kernels stay in the extracted workspace

The first consumer cutover may use git or path dependencies during local development, but the ownership boundary must already be external.

## Non-goals

This contract does not:

- move code into `sites/premath`
- define a crates.io publication plan
- broaden the extraction to product-specific Paint crates
- define downstream adoption work for Kurma, Nerve, or other consumers

## Issue mapping

This contract is the prerequisite for the remaining extraction sequence:

- `tbp-e3k.2` prepares the in-tree crates for standalone ownership under this contract
- `tbp-e3k.3` scaffolds the dedicated Premath code repo/workspace
- `tbp-e3k.4` moves the first-wave crates
- `tbp-e3k.5` rewires Paint to consume the extracted workspace
