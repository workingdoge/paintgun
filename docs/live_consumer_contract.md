# Live Consumer Integration Contract

## Decision

Paint should expose live consumer integrations through generated contracts, not by letting each
consumer reach directly into canonical inputs or Paint internals.

For alpha, a live consumer may depend on:

- documented backend artifact contracts
- documented projection IRs such as the shared web runtime IR
- generated typed adapters over those IRs
- stable finding families and machine-readable verification artifacts

A live consumer should not depend on:

- Paint internal Rust types
- ad hoc file layout beyond documented artifact paths
- the authored canonical schema as its primary runtime input
- another consumer's view model, layout, or framework choices

This keeps Paint as the semantic compiler, keeps the design-system schema as canonical component
truth, and keeps Storybook, docs, editors, and design tools as consumers rather than new sources of
truth.

## Layer Stack

The intended stack is:

1. DTCG documents and resolver inputs
2. Paint backend artifacts and verification outputs
3. canonical design-system schema
4. generated projection IRs
5. generated typed adapters and shared pure selectors
6. consumer-local view models and product surfaces

The key rule is:

- layers 1 through 4 define shared truth
- layer 5 may package that truth for consumption
- layer 6 may present it, but must not redefine it

## Shared Truth Versus Consumer Surfaces

### Shared Truth

Shared truth is data or behavior that multiple consumers should agree on byte-for-byte or
semantically.

Examples:

- backend artifact descriptors from [`docs/backend_contract.md`](backend_contract.md)
- the generated `system.web.json` shape from [`docs/web_runtime_ir.md`](web_runtime_ir.md)
- stable finding families from [`docs/witness_taxonomy.md`](witness_taxonomy.md)
- canonical component semantics from the authored design-system schema

### Consumer Surfaces

Consumer surfaces are the places where that truth becomes visible:

- Storybook workspaces
- first-party docs hosts
- pure web-component packages
- editor diagnostics panels
- design-tool bridges

Those surfaces may differ in layout, interaction model, and local UX. They should not differ in
the semantics they present.

## What A Live Consumer May Depend On

### 1. Backend Artifacts And Artifact Metadata

Consumers may depend on:

- backend ids and artifact kinds
- relative artifact paths recorded in manifests and reports
- generated backend files such as `web-css-vars` and `web-tokens-ts` outputs

This is how a consumer discovers the concrete files it can load or reference without encoding repo
internals.

### 2. Generated Projection IRs

Consumers may depend on generated IRs that sit above canonical semantics and below consumer UX.

Examples:

- `system.web.json` for web-facing runtime semantics
- a future documentation projection IR for docs/catalog/search surfaces
- `diagnostics.pack.json` and `diagnostics.compose.json` for read-only editor consumers
- `system.catalog.json` for design-tool-neutral catalog/provenance consumers

Consumers should prefer these generated IRs over reading the authored canonical schema directly at
runtime.

### 3. Generated Typed Adapters

Generated typed adapters are valid dependency surfaces when they are derived from documented IRs.

Examples:

- the generated TypeScript adapter over `system.web.json`
- future Rust adapters over the same IR

These adapters are transport conveniences, not new truth layers.

### 4. Stable Finding Presentation Contracts

Live consumers that surface verification should depend on:

- machine-readable findings and report JSON
- diagnostics projection records where a consumer wants a narrower editor-facing contract
- stable family names, severity, and fixability concepts
- the family-first presentation model described in [`docs/witness_taxonomy.md`](witness_taxonomy.md)

They should not invent their own competing semantics for what a gap, conflict, or stability issue
means.

## What A Live Consumer Must Not Depend On

### 1. Paint Internals

Consumers must not depend on:

- internal Rust module structure
- private implementation helpers
- incidental CLI text formatting
- unnamed fields in internal intermediate structs

If a consumer needs something repeatedly, that is a signal to promote it into a documented IR or
contract rather than reaching inward.

### 2. Canonical Authored Inputs As Runtime APIs

The design-system schema remains canonical, but consumers should not treat the authored schema files
as their main runtime API.

Reason:

- canonical authored inputs are for authorship and compilation
- generated IRs are for consumption

Reading authored schema directly couples consumers to authoring concerns and makes them brittle
against schema refactors that preserve generated meaning.

### 3. Another Consumer's View Model

A Storybook surface must not depend on a docs page's local card model.

A VS Code extension must not depend on Storybook arg shaping.

A design-tool bridge must not depend on HTML host layout or browser demo formatting.

Consumer-local view models are allowed, but they are leaf code.

## Shared Code Boundary

Some shared code above the IR is healthy. Some is not.

Healthy shared code:

- typed adapters generated from IR
- pure selectors over IR records
- artifact lookups and path resolution helpers
- finding-family normalization helpers

Unhealthy shared code:

- Storybook-specific `argTypes` baked into the canonical adapter
- demo-page cards, labels, or layout logic shared as if they were semantics
- editor decoration shapes treated as canonical records
- Figma-plugin frame layout encoded into shared model code

Rule of thumb:

- if a helper is lossless and consumer-neutral, it may be shared
- if it formats, prioritizes, or lays out for one surface, keep it local to that consumer

## Projection-Only Surfaces Versus Candidate Product Surfaces

Projection-only surfaces:

- generated projection IRs
- generated typed adapters
- pure selector/helper layers over those IRs
- artifact lookup helpers

Candidate product surfaces:

- Storybook workspace
- first-party docs host
- pure web-component package
- editor extension
- design-tool bridge

Projection-only layers exist to make product surfaces possible. They are not end-user products on
their own.

## Consumer Matrix

### Storybook

Storybook may depend on:

- web runtime IR
- generated adapter
- shared neutral selectors
- finding taxonomy for diagnostics panels

Storybook must not define:

- canonical component API
- canonical examples
- canonical artifact bindings

### First-Party Docs

First-party docs may depend on:

- docs projection records when they exist
- web runtime IR where web API details are needed
- backend artifact descriptors
- stable verification/report artifacts

First-party docs may add narrative, comparisons, and navigation, but should not become the only
place where component semantics are encoded.

### Editor Integrations

Editor integrations may depend on:

- machine-readable findings
- stable finding family taxonomy
- artifact/path metadata where relevant

They should not parse terminal text as their primary source of truth.
The editor-specific diagnostics seam is shaped in
[`docs/editor_design_tool_seam.md`](editor_design_tool_seam.md).

### Design-Tool Bridges

Design-tool bridges may depend on:

- generated token packages
- design-system schema projections promoted specifically for design-tool use, such as
  `system.catalog.json`
- finding families and compatibility metadata where useful

They should not require Paint core to become an interactive design tool.
The design-tool bridge seam is shaped in
[`docs/editor_design_tool_seam.md`](editor_design_tool_seam.md).

## Reference Implementation Boundary

The current reference prototypes are:

- [`examples/web-runtime-prototype/README.md`](../examples/web-runtime-prototype/README.md)
- [`examples/design-tool-bridge-prototype/README.md`](../examples/design-tool-bridge-prototype/README.md)

Their intended split is:

- authored canonical schema
- authored web projection config
- generated web runtime IR
- generated catalog IR
- generated typed adapter
- authored consumer-local model/view code for the demo host, Storybook consumer, and design-tool bridge

That is the right direction. The contract here makes explicit which of those layers are reusable and
which are local to the consumer surface.

## Consequences For Follow-On Work

`tbp-qnb.7` should build a real Storybook/docs consumer workspace without promoting Storybook
shaping into the canonical layer.

`tbp-qnb.8` should define editor and design-tool seams by promoting only consumer-neutral needs into
shared IRs or helper layers, not by sharing one surface's local UX model with another.

## Acceptance Criteria

This contract is satisfied when:

- a live consumer can be built over documented IRs and backend contracts
- the consumer does not need to read Paint internals or authored schema directly at runtime
- consumer-local formatting stays outside shared generated contracts
- multiple consumers can present the same underlying semantics without duplicating truth
