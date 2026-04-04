# VS Code Diagnostics Prototype

This example prototypes the editor seam shaped in
[`docs/editor_design_tool_seam.md`](../../docs/editor_design_tool_seam.md):

- Paint writes a dedicated editor diagnostics projection (`diagnostics.pack.json`)
- the extension reads that projection instead of reaching into raw Rust internals
- the extension stays read-only and opens source files plus JSON Pointer context

The fixture is intentionally narrow:

- one resolver workspace at `fixtures/read-only-demo/`
- one intentional gap witness
- one generated output directory at `fixtures/read-only-demo/dist/`
- one read-only VS Code tree view over `diagnostics.*.json`

## Refresh And Build

From the repo root:

```bash
cd examples/vscode-diagnostics-prototype
bun install
bun run check
```

`bun run check` does three things:

1. regenerates the fixture build output (including `diagnostics.pack.json`)
2. compiles the extension scaffold under `dist/`
3. runs a small Bun test over the consumer model

## What To Open In VS Code

Open this example folder in VS Code:

```bash
code examples/vscode-diagnostics-prototype
```

Then run the normal extension-development flow for this folder. The prototype contributes a
`Paintgun Diagnostics` view in the Explorer and a `Paintgun: Refresh Diagnostics` command.

The consumer stays read-only:

- it lists generated diagnostics documents
- it renders stable finding families, severity, fixability, and next action
- it opens the source file for a finding when one is available
- it shows the JSON Pointer in an info message for precise follow-up

It does not mutate token documents or invent its own truth layer.
