# Design-Tool-Neutral Catalog IR

## Decision

Paint should expose design-tool bridges through a generated, design-tool-neutral catalog IR.

That IR sits:

- above the canonical design-system schema
- above generated backend artifacts and verification outputs
- alongside other projection IRs such as the web runtime IR and diagnostics projection
- below concrete design-tool adapters such as a Figma bridge or read-only catalog browser

The first concrete artifact should be a neutral serialized document such as:

- `system.catalog.json`

Optional typed adapters may be generated above it:

- `system-catalog.ts`
- future Rust adapters

## Why This Exists

The canonical design-system schema owns authored component semantics.

That is the right place for:

- component ids
- semantic parts and slots
- inputs and examples
- status and accessibility intent

But it is not the right runtime surface for design-tool bridges.

Design tools need a consumer-facing projection that packages:

- component catalog records
- release/provenance identity
- backend artifact references
- verification summaries
- neutral example and status metadata

without forcing the bridge to parse:

- authored schema internals
- Storybook layout
- web-only runtime choices such as tag names and reflected attributes

## Consumer Boundary

Design-tool bridges may depend on:

- `system.catalog.json`
- generated typed adapters over that catalog IR
- backend artifact descriptors referenced by the catalog IR
- verification summaries surfaced by the catalog IR

Design-tool bridges must not depend on:

- web runtime IR details such as `tagName`, reflected attributes, or event payloads unless the
  bridge is explicitly web-only
- Storybook stories
- browser demo layout
- Paint internal Rust types

## Top-Level Record Families

Recommended top-level record families:

- `catalogSystem`
  - system id, title, release
  - schema version and catalog version
  - source pack/manifests used to derive the catalog
  - system-level verification summary
  - system-level artifact references
- `catalogComponents`
  - one record per component
  - semantic parts/slots
  - inputs and examples
  - accessibility and status metadata
  - component-scoped or system-scoped artifact references
  - component-facing verification summary

This is intentionally broader than the web runtime IR and intentionally narrower than a plugin UI.

## Catalog System Contract

`catalogSystem` should include:

- `id`
- `title`
- `release`
- `schemaVersion`
- `catalogVersion`
- `paintSources`
  - source id
  - manifest path
  - tool name/version
  - DTCG spec version
  - pack identity
  - diagnostics path when available
- `artifactReferences`
  - backend id
  - artifact kind
  - file path
  - hash/size
  - optional API version
- `verificationSummary`
  - scope
  - total and clean
  - family rollups
  - severity rollups
  - source report rollups

## Component Record Contract

Each `catalogComponents[]` record should include:

- `id`
- `title`
- `description`
- `status`
- `compatibility`
- `accessibility`
- `parts`
- `slots`
- `inputs`
- `examples`
- `tokenRoleBindings`
- `artifactScope`
- `artifactReferences`
- `verificationSummary`

### Token Role Bindings

`tokenRoleBindings` belongs in the catalog IR even if the current canonical schema does not yet
author them richly.

Reason:

- design tools care about semantic token usage, not only component metadata
- this is a stable place to grow those records later

Alpha guidance:

- allow an empty array when the authored schema does not yet define semantic token-role bindings
- do not infer token roles from web-only style hooks

### Artifact Scope

Artifact references may be:

- `component`
- `system-wide`

This matters because many early artifacts will be shared system outputs rather than
component-specific files.

The catalog IR should make that scope explicit instead of pretending all artifacts are
component-local.

## Verification Summary Contract

Design tools need provenance and health, but not every technical witness detail.

The catalog IR should summarize:

- total findings
- clean/unclean
- family rollups
- severity rollups
- source reports used to derive the summary

This keeps the bridge useful without making the design tool a report viewer first.

The richer diagnostics projection remains the editor-facing contract.

## Relationship To Existing Contracts

This IR builds on:

- [`docs/live_consumer_contract.md`](live_consumer_contract.md)
- [`docs/editor_design_tool_seam.md`](editor_design_tool_seam.md)
- [`docs/web_runtime_ir.md`](web_runtime_ir.md)
- [`docs/diagnostics_projection.md`](diagnostics_projection.md)
- [`docs/backend_contract.md`](backend_contract.md)

The key distinction is:

- `system.web.json` is web-runtime-facing
- `system.catalog.json` is design-tool/catalog-facing

## Alpha Scope

In alpha, the catalog IR should stay:

- read-only
- design-tool-neutral
- provenance-aware
- explicit about what is system-scoped versus component-scoped

Out of scope:

- plugin-private layout geometry
- Figma frame composition
- authoring round-trips back into Paint

## Reference Schema

The canonical schema for this contract is
[`schemas/system.catalog.schema.json`](../schemas/system.catalog.schema.json).

## Reference Example

The current reference example lives in:

- [`examples/web-runtime-prototype/generated/system.catalog.json`](../examples/web-runtime-prototype/generated/system.catalog.json)
- [`examples/web-runtime-prototype/src/generated/system-catalog.ts`](../examples/web-runtime-prototype/src/generated/system-catalog.ts)
