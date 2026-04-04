# Backend Artifact Contract

This document defines the alpha-stable backend artifact contract for Paint.

It applies to:

- pack manifests: `ctc.manifest.json`
- compose manifests: `compose.manifest.json`
- pack JSON reports: `validation.json`
- compose JSON reports: `compose.report.json`

The contract here is narrower than the full internal implementation. Alpha consumers should depend on this document, the referenced schema, and the covered regression tests rather than on incidental file ordering or extra human-readable output.

## Canonical Backend IDs

The canonical backend ids are:

- `web-css-vars`
- `swift-tokens`
- `android-compose-tokens`
- `web-tokens-ts`

The legacy names `css`, `swift`, and `kotlin` remain accepted as CLI compatibility aliases through alpha, but manifests and reports are expected to emit canonical backend ids.

## Descriptor Shape

`backendArtifacts` entries use this stable shape:

- `backendId`
- `kind`
- `file`
- `sha256`
- `size`
- optional `apiVersion`

In reports, the JSON shape is validated by [`schemas/report.schema.json`](../schemas/report.schema.json).

In manifests, the same descriptor shape is serialized through [`BackendArtifactDescriptor`](../src/cert.rs).

## Path Rules

`backendArtifacts[].file` is always relative to the output root that owns the artifact:

- for pack outputs, relative to the pack output directory
- for compose outputs, relative to the compose output directory

Alpha consumers may rely on these path rules:

- paths are relative, not absolute
- paths do not escape the output root
- hashes and sizes bind to the file content at that relative path

## Artifact Kinds

The stable backend artifact kinds are:

- `primaryTokenOutput`
- `tokenStylesheet`
- `systemStylesheet`
- `typeDeclarations`
- `packageManifest`
- `packageSettings`
- `packageBuildScript`
- `packageSource`
- `packageTest`

Future backends should fit into this vocabulary rather than introduce backend-specific top-level metadata fields.

## Primary Output Expectations

Each backend must emit exactly one `primaryTokenOutput`.

Current built-ins:

- `web-css-vars`
  - primary output: `tokens.css`
  - additional outputs may include `tokens.vars.css`, `components.css`, and `tokens.d.ts`
  - browser support for these CSS artifacts is defined separately in
    [`docs/web_css_compatibility.md`](web_css_compatibility.md)
- `swift-tokens`
  - primary output: `tokens.swift`
- `android-compose-tokens`
  - primary output: `tokens.kt`
- `web-tokens-ts`
  - primary output: `tokens.ts`

Consumers may treat `primaryTokenOutput` as the main token artifact for a backend, but should not assume it is the only emitted file.

## API Version Policy

`apiVersion` is optional at the descriptor level.

The alpha policy is:

- `web-css-vars`
  - no `apiVersion` is promised
- `swift-tokens`
  - `apiVersion` is promised on the primary token artifact and generated package source artifacts
- `android-compose-tokens`
  - `apiVersion` is promised on the primary token artifact and generated package source artifacts
- `web-tokens-ts`
  - `apiVersion` is promised on the primary token artifact and generated package source artifacts

Artifacts such as package manifests, build scripts, settings files, and tests do not promise an `apiVersion`.

## Reports vs Manifests

Reports and manifests intentionally expose different machine-readable surfaces.

`validation.json` and `compose.report.json`:

- include `backendArtifacts`
- do not include `nativeApiVersions`

`ctc.manifest.json` and `compose.manifest.json`:

- include `backendArtifacts`
- may include `nativeApiVersions`

This split is intentional. `backendArtifacts` is the primary backend contract. `nativeApiVersions` remains only as a compatibility projection for legacy Swift/Kotlin-oriented consumers.

## Compatibility Fields

`nativeApiVersions` is a compatibility shim, not the primary long-term contract.

Alpha consumers should prefer:

- `backendArtifacts[].backendId`
- `backendArtifacts[].kind`
- `backendArtifacts[].file`
- `backendArtifacts[].sha256`
- `backendArtifacts[].size`
- `backendArtifacts[].apiVersion` when present

Consumers that still need `nativeApiVersions` may rely on this projection behavior during alpha:

- `swift-tokens` and legacy `swift` project to `nativeApiVersions.swift`
- `android-compose-tokens` and legacy `kotlin` project to `nativeApiVersions.kotlin`

No compatibility projection is promised for `web-css-vars` or `web-tokens-ts`.

## Regression Coverage

The contract is covered by:

- [`tests/backend_registry.rs`](../tests/backend_registry.rs)
- [`tests/build_cli_errors.rs`](../tests/build_cli_errors.rs)
- [`tests/native_api_versions.rs`](../tests/native_api_versions.rs)
- [`tests/report_schema.rs`](../tests/report_schema.rs)
- [`tests/backend_contract.rs`](../tests/backend_contract.rs)

Changes that would alter the stable contract should update this document and the relevant regression coverage in the same change.
