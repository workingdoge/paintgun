# Premath Code Home and Packaging Strategy

## Decision

Keep `premath-*` in this repository's Cargo workspace for now.

Do not move Premath code into `/Users/arj/dev/fish/sites/premath`.
That repo remains the site, spec, governance, and curated-reference surface.

If Premath code is extracted later, the target should be a sibling code repo or a dedicated code workspace, not the site repo.

The execution contract for that later move is defined in `docs/premath_extraction_contract.md`.

## Recommendation

The recommended operating model is:

- Code home now: keep `premath-*` under `crates/premath-*` in this repo.
- Public packaging now: do not publish `premath-*` crates independently.
- Versioning now: keep `premath-*` on the workspace's lockstep `0.x` version line with no standalone semver promise.
- CI now: validate Premath through the existing workspace test suite and boundary tests that enforce the product/kernel split.
- Extraction target later: a dedicated Premath code repo or code-only multi-workspace arrangement once the preconditions below are met.

This is the lowest-risk choice because it preserves the current working integration loop while making the eventual extraction target explicit.

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

Until extraction preconditions are met:

- All `premath-*` crates stay `publish = false`.
- No `premath-*` crate should claim independent API stability.
- Workspace integration remains the source of truth for compatibility.
- Breaking changes across `premath-*` crates may ship together with the product while they are still internal kernels.

If Premath is extracted later:

- Start with one dedicated code repo and one lockstep workspace version for all published `premath-*` crates.
- Stay on `0.x` until there is a real external compatibility promise.
- Only consider per-crate independent versioning after multiple releases show materially different cadence across crates.

## CI Expectations

Current expectation while Premath stays in-tree:

- `cargo test --workspace` remains required.
- Boundary tests must keep enforcing that product manifests, report contracts, path safety, signing policy, and CLI concerns stay out of `premath-*`.
- Kernel crates should keep unit tests for deterministic witness assembly and law-evaluation behavior.

Required before extraction:

- A Premath-only CI entrypoint that can run without the product CLI.
- Standalone crate docs and metadata suitable for external consumers.
- A documented MSRV and release owner.
- A release checklist that does not depend on the site repo.

## Extraction Preconditions

Do not extract Premath code until all of these are true:

1. `premath-*` public APIs are product-neutral.
2. Product-specific nouns and contracts are out of the public surface.
   Examples: product manifests, report schemas, signing policy, path-safety adapters, CLI error namespaces.
3. The set of crates that truly belong to Premath is stable enough to name and support.
4. There is at least one credible non-product consumer, or a concrete near-term consumer that justifies the overhead.
5. Crate metadata, docs, CI, and release ownership are ready for external use.

## Revisit Trigger

Reopen this decision when either:

- a second real consumer appears,
- extraction-ready cleanup is complete across the remaining `premath-*` seams, or
- release pressure makes independent Premath publication more valuable than in-repo coordination.

Until then, keep Premath in-tree and treat this repo as the code home.
