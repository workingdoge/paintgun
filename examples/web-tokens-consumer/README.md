# Web Tokens TypeScript Consumer

This example shows the supported TypeScript consumer path for the `web-tokens-ts`
backend:

- Paint generates the token package under `generated/paint/web/`
- the consumer imports that package by name: `paintgun-web-tokens`
- the consumer keeps its own small helper layer in `src/index.ts`

This is intentionally narrower than the web runtime prototype. It proves package
wiring and token usage without pulling in web components or Storybook.

## Refresh And Run

From the repo root:

```bash
cd examples/web-tokens-consumer
bun run generate:paint
bun install
bun run demo
bun run check
```

`bun run generate:paint` rebuilds the generated token package from
`examples/charter-steel/charter-steel.resolver.json` and refreshes:

- `generated/paint/tokens.ts`
- `generated/paint/web/package.json`
- `generated/paint/web/src/index.ts`

`bun install` wires the consumer package to that generated output via:

```json
{
  "dependencies": {
    "paintgun-web-tokens": "file:./generated/paint/web"
  }
}
```

## What The Consumer Does

The consumer code in `src/index.ts` demonstrates three things:

1. Discover supported inputs from the generated `contexts` export.
2. Resolve a stable Paint context key from a TS object such as
   `{ mode: "docs", theme: "light" }`.
3. Read typed values from `valuesByContext` and derive a small surface preview.

`src/demo.ts` prints one concrete preview so a first-time user can see the shape
of the generated API without reading raw `tokens.ts`.

## Boundary

The generated package remains the source of token truth. This example adds only
consumer-local helpers and does not treat the authored design-system schema or
Paint internals as a runtime API.
