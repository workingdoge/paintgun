# Incremental Build And Compose Cache

Paint now has a deterministic, output-root-local cache foundation for `build` and `compose`.

This is intentionally a first practical win, not a daemon:

- repeated identical invocations can reuse existing outputs
- invalidation is explicit and content-based
- cache metadata lives beside the output tree
- no background service is required

## What Gets Cached

Each output root may carry hidden stage metadata under:

- `<out>/.paint/cache/build.json`
- `<out>/.paint/cache/compose.json`

These records describe:

- the stage name
- a deterministic cache key
- the input fingerprint used to derive that key
- the relative output files expected for a cache hit

## Invalidation Boundary

### `paint build`

The build-stage key includes:

- the current Paint executable fingerprint
- backend id
- conflict mode
- output format
- context mode
- planner-trace flag
- profile
- KCIR wire format id
- resolver file content
- external token source file content referenced by the resolver
- contracts file content when present
- policy file content when present

A build cache hit also requires that the expected output files for that invocation still exist.

That expected set includes:

- core outputs such as `resolved.json`, `validation.txt`, `authored.json`, `ctc.witnesses.json`,
  `ctc.manifest.json`, and `diagnostics.pack.json`
- `validation.json` when `--format json`
- `admissibility.witnesses.json` when `--profile full`
- backend-specific artifact files
- staged portable inputs under `inputs/`

### `paint compose`

The compose-stage key includes:

- the current Paint executable fingerprint
- backend id
- conflict mode
- output format
- context mode
- planner-trace flag
- verification/composability gate flags used by the invocation
- contracts file content when present
- policy file content when present
- for each input pack:
  - `ctc.manifest.json`
  - `ctc.witnesses.json`
  - `resolved.json`
  - `authored.json` when present

A compose cache hit also requires the expected compose outputs for that invocation to exist.

## Current Behavior

On a cache hit:

- `paint build` reuses the existing output directory and prints the normal success line
- `paint compose` reuses the existing report artifacts and replays the expected stdout surface
- both commands emit a cache-hit note on stderr

On a cache miss:

- Paint rebuilds normally
- successful runs refresh the stage cache metadata

Unreadable or stale cache metadata is treated as a miss and rebuilt safely.

## Non-Goals Of This First Version

This cache foundation does not yet try to:

- share cache state across output roots
- introduce a long-lived daemon
- clean stale extra files left by older runs with different targets
- deduplicate intermediate work across unrelated commands

Those would be follow-on optimizations, not prerequisites for the current win.

## First Practical Win

The main value of this first version is simple:

- agents and local users can rerun the same `paint build` or `paint compose` command against the
  same output root without paying the full resolve/analyze/emit cost again
- invalidation remains explicit and deterministic when resolver inputs, policy, backend selection,
  or compose inputs change

That is enough to improve tight local edit loops without committing the project to a daemon or a
cross-workspace cache architecture.
