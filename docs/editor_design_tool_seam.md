# Editor And Design-Tool Adapter Seam

## Decision

Paint should expose editors and design tools through generated, read-only adapter seams.

Those seams sit above:

- backend artifact contracts
- machine-readable verification/report artifacts
- canonical design-system schema
- generated projection IRs such as the web runtime IR

They sit below:

- VS Code or other editor extensions
- Figma or other design-tool bridges
- future diagnostics dashboards

Paint should not become an interactive design tool or editor runtime.

## Why This Needs Its Own Seam

Storybook and the browser prototype proved that a live consumer can sit above generated IRs.

Editors and design tools are different from Storybook in one important way:

- editors are diagnostics-first
- design tools are catalog/provenance-first

If both are forced through one shared consumer model, the result gets scrunched again:

- editor decorations leak into shared IRs
- plugin frame/layout choices leak into canonical semantics
- one surface becomes the accidental source of truth for another

So the next seam should split these adapter families explicitly.

## Layering

The intended stack is:

1. DTCG documents and resolver inputs
2. Paint backend artifacts and verification outputs
3. canonical design-system schema
4. generated projection IRs
5. adapter-focused projection records
6. editor or design-tool product surfaces

The important distinction is between:

- projection IRs that describe shared meaning
- adapter records that package that meaning for a class of consumer
- product surfaces that render those records

## Two Adapter Families

### 1. Editor Diagnostics Seam

This seam is for:

- VS Code
- read-only IDE panels
- CI-linked local review tools

Its primary job is:

- surface findings where code is edited
- map findings to source locations and JSON Pointers
- show the user-facing family first and the technical witness second
- link the finding to the next action

Editors are not the source of component truth. They are the place where verification becomes
actionable.

### 2. Design-Tool Bridge Seam

This seam is for:

- Figma
- token/catalog explorers inside design tools
- future read-only design-system browsers

Its primary job is:

- surface component and token semantics in a design-friendly catalog
- expose states, variants, examples, status, and accessibility notes
- expose provenance and verification status without forcing users into CLI reports
- reference platform/runtime outputs without becoming the authoring source

Design tools are not the source of token or component truth. They are a projection surface above
the canonical schema and generated IRs.

## Editor Diagnostics Contract

An editor adapter may depend on:

- `validation.json` and `compose.report.json`
- stable finding families from [`docs/witness_taxonomy.md`](witness_taxonomy.md)
- stable file path and JSON Pointer fields in report findings
- `ctc.witnesses.json` and `compose.witnesses.json` when a deeper trace is needed
- backend artifact metadata when the finding needs to reference generated outputs

An editor adapter must not depend on:

- terminal text output
- Storybook arg shaping
- demo host layout
- raw internal Rust structs

### Recommended Editor Projection

The current report artifacts are enough to build a basic read-only editor surface, but they are not
ideal as the long-term editor contract because they still mix:

- general archival diagnostics
- human-facing summaries
- details an editor would prefer already normalized

The next clean layer is a dedicated diagnostics projection, for example:

- `diagnostics.pack.json`
- `diagnostics.compose.json`

The projection contract is documented in
[`docs/diagnostics_projection.md`](diagnostics_projection.md).

Suggested record shape:

- stable finding id
- user-facing family id and label
- technical kind
- severity
- fixability
- short summary
- next action
- file path
- JSON Pointer
- optional pack identity
- optional related backend artifact references

This should stay additive above existing report contracts, not replace them.

### Editor UX Boundary

The first supported editor shape should be read-only:

- diagnostics
- source navigation
- explain-style detail panels
- links to generated artifacts or reports

Out of scope for this seam:

- live mutation of token documents through the extension
- Paint becoming an editor daemon with its own state model
- editor-specific quick-fix protocols becoming canonical semantics

## Design-Tool Bridge Contract

A design-tool bridge may depend on:

- canonical design-system schema outputs
- documentation-oriented metadata
- generated projection IRs such as the web runtime IR where public runtime semantics matter
- backend artifact metadata and verification summaries

A design-tool bridge must not depend on:

- browser host layout
- Storybook story structure
- HTML-specific presentation details unless the bridge is explicitly web-only
- plugin frame geometry encoded as shared truth

### Recommended Design-Tool Projection

The web runtime IR is not enough by itself for a design-tool bridge.

It is web-facing, while a design tool needs a broader catalog/provenance surface. The cleaner next
projection is a design-tool-neutral catalog IR, for example:

- `system.catalog.json`

The projection contract is documented in [`docs/catalog_ir.md`](catalog_ir.md).

Suggested record families:

- system metadata and release
- component catalog entries
- variant/state definitions
- semantic parts/slots
- token-role bindings
- examples
- accessibility/support notes
- status/deprecation metadata
- verification summary for the component or package
- links to relevant backend/runtime artifacts

This should be design-tool-neutral first. A Figma bridge would consume it as one adapter, not
define it.

### Figma-Specific Guidance

For alpha, Figma should be treated as a read-only bridge:

- inspect tokens and components
- browse examples and status
- surface verification/provenance notes

Not in alpha scope:

- Figma as canonical authoring input for Paint
- round-tripping Paint semantics through plugin-private data models
- inventing plugin-specific layout/config records as shared IR

If a design-tool bridge later needs richer geometry or preview metadata, that should be added as a
new documented projection layer, not smuggled into the canonical schema.

## Shared Metadata Requirements

These are the likely shared records editors and design tools both need:

- stable finding families
- source file path and JSON Pointer
- component/status metadata
- verification summary
- artifact references
- release/version identity

These are likely split by adapter family:

- editor-only:
  - fixability
  - next-action phrasing
  - related witness ids
- design-tool-only:
  - component examples
  - accessibility/support notes
  - semantic parts/slots
  - variant/state catalog records

That split is healthy. Do not force them into one giant adapter schema.

## Relationship To Existing Contracts

This seam builds on existing repo contracts:

- live-consumer boundary: [`docs/live_consumer_contract.md`](live_consumer_contract.md)
- web-facing runtime projection: [`docs/web_runtime_ir.md`](web_runtime_ir.md)
- backend artifact contract: [`docs/backend_contract.md`](backend_contract.md)
- finding families: [`docs/witness_taxonomy.md`](witness_taxonomy.md)

The key extension is:

- editor adapters need a diagnostics-first projection
- design-tool bridges need a catalog/provenance-first projection

Neither should force Paint core to grow UI-framework semantics.

## Follow-On Work

The clean next implementation lanes are:

1. add a diagnostics projection and a read-only VS Code prototype
2. define a design-tool-neutral catalog IR above the canonical schema
3. prototype a read-only design-tool bridge over that catalog IR

That keeps the progression honest:

- stable contracts first
- one adapter prototype per family
- no promotion of one product surface into canonical truth

## Acceptance Boundary

This seam is in good shape when:

- a VS Code extension can be built over documented diagnostics/projection records
- a Figma or other design-tool bridge can be built over a documented catalog projection
- neither consumer needs to read Paint internals or authored schema directly at runtime
- neither consumer becomes the new source of truth for the system
