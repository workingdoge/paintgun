# Editor Diagnostics Projection

Paint exposes editor-facing diagnostics through generated projection artifacts:

- `diagnostics.pack.json`
- `diagnostics.compose.json`

These files sit above:

- `validation.json`
- `compose.report.json`
- stable finding-family semantics from [`docs/witness_taxonomy.md`](witness_taxonomy.md)

They sit below:

- editor extensions
- read-only IDE panels
- future diagnostics dashboards

## Why This Exists

Raw report JSON is stable enough for CI and archival use, but it still mixes:

- report-shape concerns
- human summary text
- details an editor would rather receive already normalized

The diagnostics projection exists to give editor consumers a narrower contract:

- stable record ids
- family id and family label
- severity
- fixability
- next action
- file path and JSON Pointer
- optional backend artifact metadata at the document level

## File Contract

Each projection contains:

- source report identity
- top-level clean/total summary
- family rollups
- severity rollups
- editor-friendly records

Each record includes:

- `recordId`
- `witnessId`
- `kind`
- `familyId`
- `familyLabel`
- `severity`
- `fixability`
- `summary`
- `meaning`
- `nextAction`
- optional `tokenPath`
- optional `context`
- optional `filePath`
- optional `jsonPointer`
- optional `pack`

The canonical schema is [`schemas/diagnostics.schema.json`](../schemas/diagnostics.schema.json).

## Consumer Boundary

Editor consumers may depend on:

- `diagnostics.pack.json`
- `diagnostics.compose.json`
- stable finding families from [`docs/witness_taxonomy.md`](witness_taxonomy.md)
- generated backend artifact metadata carried at the projection level

Editor consumers should not depend on:

- terminal text output
- raw Rust structs
- Storybook-local models
- demo-host formatting

## Current Prototype

The first read-only consumer lives in
[`examples/vscode-diagnostics-prototype/README.md`](../examples/vscode-diagnostics-prototype/README.md).
