# Design-Tool Bridge Prototype

This example is the first read-only design-tool bridge above the neutral catalog IR.

It deliberately consumes:

- `../web-runtime-prototype/generated/system.catalog.json`
- `../web-runtime-prototype/src/generated/system-catalog.ts`
- generated diagnostics projections under `../web-runtime-prototype/generated/paint/*/diagnostics.pack.json`
- the generated `web-tokens-ts` backend output for token previews

It deliberately does not consume:

- the authored schema as a runtime API
- Storybook stories
- web runtime layout details such as tag names or reflected attributes
- any design-tool-private authoring model

The bridge is browser-hosted so it is easy to run locally, but the surface is intentionally shaped
like a read-only design-tool panel:

- catalog-first
- provenance-aware
- verification-aware
- not an authoring source

## Refresh and run

From the repo root:

```bash
cd examples/design-tool-bridge-prototype
bun install
bun run check
bun run serve
```

`bun run check` does three things:

1. refreshes the shared producer outputs in `../web-runtime-prototype`
2. bundles the bridge host under `bridge/dist/`
3. runs the bridge tests

`bun run serve` mounts the browser host at `/bridge/`.

## Structure

- `src/source/catalog.ts`
  - imports the shared catalog adapter, diagnostics projections, and token package output
- `src/model/bridge.ts`
  - builds a design-tool-facing read-only view model
- `src/main.ts`
  - renders the bridge UI over that model
- `bridge/index.html`
  - browser host shell
- `scripts/build-bridge.ts`
  - bundles the browser entrypoint
- `scripts/serve-bridge.ts`
  - serves the host at an explicit `/bridge/` mount

This is a prototype bridge, not a canonical design-tool contract by itself. The contract stays in
[`docs/catalog_ir.md`](../../docs/catalog_ir.md) and
[`docs/editor_design_tool_seam.md`](../../docs/editor_design_tool_seam.md).
