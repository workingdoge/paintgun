# Premath Code Home and Packaging Strategy

## Decision

`premath-*` now live in the dedicated sibling code repo/workspace at `/Users/arj/dev/fish/tools/premath`.

Do not move Premath code into `/Users/arj/dev/fish/sites/premath`.
That repo remains the site, spec, governance, and curated-reference surface.

The code-home decision is therefore no longer provisional: Premath code is extracted to a sibling code repo, not the site repo.

The execution contract for that later move is defined in `docs/premath_extraction_contract.md`.

## Resulting operating model

The current operating model is:

- Code home now: keep `premath-*` under `/Users/arj/dev/fish/tools/premath/crates/premath-*`.
- Paint now consumes those crates through a repo-local `./premath` projection of the extracted code home.
- Public packaging now: still do not publish `premath-*` crates independently.
- Versioning now: keep `premath-*` on the extracted workspace's lockstep `0.x` version line with no standalone semver promise yet.
- CI now: materialize the extracted code home into `./premath`, validate Premath there, and use Paint boundary tests only for adapter behavior.

This keeps code ownership aligned with the extracted workspace while leaving publication and broader downstream adoption for later work.

## Options Considered

### 1. Keep Premath in-tree in this repo

Pros:

- Lowest operational overhead.
- No cross-repo release choreography while APIs are still moving.
- Keeps boundary tests close to the product adapters they constrain.
- Matches the current reality: Paintgun/TBP is the only real consumer today.

Cons:

- Shared-kernel and product code still ship from the same repo.
- Extraction pressure is easy to postpone unless the boundary stays explicit.

### 2. Move Premath to a sibling code repo now

Pros:

- Cleanest long-term ownership boundary.
- Makes package/release contracts explicit immediately.

Cons:

- Too much cost for the current maturity level.
- Requires semver, release, CI, and dependency coordination before the APIs are ready.
- Still blocked on finishing product-neutralization of some public seams.

### 3. Put Premath code into `sites/premath`

Pros:

- Puts the Premath name, site, and code in one place.

Cons:

- Wrong repo purpose.
- `sites/premath` is explicitly a site/spec/governance surface, not a code workspace.
- Would mix normative/site content with Rust build, CI, and release concerns.

This option is rejected.

## Packaging Policy

Current packaging policy:

- All `premath-*` crates stay `publish = false`.
- No `premath-*` crate should claim independent API stability.
- Workspace integration remains the source of truth for compatibility.
- Breaking changes across `premath-*` crates may ship together with the product while they are still internal kernels.

If Premath packaging broadens later:

- Start with one dedicated code repo and one lockstep workspace version for all published `premath-*` crates.
- Stay on `0.x` until there is a real external compatibility promise.
- Only consider per-crate independent versioning after multiple releases show materially different cadence across crates.

## CI Expectations

Current expectation after extraction:

- Paint contributors materialize the extracted code home into `./premath` before running Cargo commands.
- `cargo test --workspace` remains required from the Paint repo after that projection exists.
- Boundary tests must keep enforcing that product manifests, report contracts, path safety, signing policy, and CLI concerns stay out of `premath-*`.
- Kernel crates should keep unit tests for deterministic witness assembly and law-evaluation behavior.

Required before broader publication:

- A Premath-only CI entrypoint that can run without the product CLI.
- Standalone crate docs and metadata suitable for external consumers.
- A documented MSRV and release owner.
- A release checklist that does not depend on the site repo.

## Extraction Preconditions

The extraction preconditions were satisfied enough to execute the first-wave move. Remaining work is now cutover polish rather than code-home indecision:

1. `premath-*` public APIs are product-neutral.
2. Product-specific nouns and contracts are out of the public surface.
   Examples: product manifests, report schemas, signing policy, path-safety adapters, CLI error namespaces.
3. The set of crates that truly belong to Premath is stable enough to name and support.
4. There is at least one credible non-product consumer, or a concrete near-term consumer that justifies the overhead.
5. Crate metadata, docs, CI, and release ownership are ready for external use.

## Revisit Trigger

Reopen this note only if the dedicated Premath code home itself needs to move again. The current code-home question is closed.
