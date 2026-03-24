# Paint Target Backends

## Decision

`paint` should stay the deterministic token compiler/verifier/signing tool, not the full design system.

The product boundary should be:

- `paint` core: resolve, verify, sign, compose, and package token artifacts.
- target backends: turn resolved token artifacts into platform-facing outputs such as CSS vars, Swift tokens, Android tokens, or future target artifacts.
- design-system packages: web components, React packages, SwiftUI helpers, Android UI kits, and similar system packages that consume backend outputs instead of being generated inside core.

That keeps Paint narrow enough to stay reliable while still making platform output a first-class concern.

## Current State

Today the repo already has the right raw ingredients, but the boundary is implicit:

- [`src/main.rs`](../src/main.rs) accepts built-in target ids such as `css`, `swift`, and `android-compose-tokens`, with `kotlin` retained as a compatibility alias.
- [`src/emit.rs`](../src/emit.rs) is a thin adapter over [`crates/paintgun-emit`](../crates/paintgun-emit/src/lib.rs).
- [`crates/paintgun-emit`](../crates/paintgun-emit/src/lib.rs) mixes:
  - backend-neutral value emission helpers,
  - concrete backends,
  - component-contract CSS emission,
  - scaffold/package generation for Swift and Android/Kotlin.

That is workable for the current built-ins, but it is the wrong shape for:

- a typed web package backend,
- Android-focused naming and packaging,
- future backend families,
- separating token backends from higher-level system packages.

## Recommended Architecture

### Layer 1: Paint Core

Paint core owns:

- resolver semantics
- policy normalization
- verification, signing, trust, and compose
- stable resolved token artifacts
- backend invocation and artifact recording

Paint core should not own a web component library, a React component set, a SwiftUI package, or an Android widget kit.

### Layer 2: Target Backends

A target backend consumes Paint's resolved token model and emits platform-facing artifacts.

Examples:

- `web-css-vars`
- `web-tokens-ts`
- `swift-tokens`
- `android-compose-tokens`
- `json-runtime`

A backend may also emit convenience scaffolding, but only when that scaffolding is still a token package, not a full design system.

Good examples:

- Swift token source plus a minimal Swift Package wrapper
- Android token source plus a minimal Gradle module wrapper
- TypeScript token source plus `package.json` and typings

Bad examples for core:

- full web components
- React/Vue/Svelte component libraries
- SwiftUI view sets
- Android UI component kits

Those belong above the backend layer.

### Layer 3: System Packages

System packages consume backend outputs and add component semantics.

Examples:

- web components using CSS variables or generated token modules
- React wrappers using typed token packages
- SwiftUI helpers over Swift token output
- Android Compose theme/component libraries over Android token output

This layer is where component contracts, slot mapping, and framework-specific authoring should live long term.

## Backend Contract

The current `Emitter` trait is value-level. Future target growth needs a backend-level contract.

Recommended shape:

```rust
trait TargetBackend {
    fn id(&self) -> &'static str;
    fn api_version(&self) -> Option<&'static str>;
    fn capabilities(&self) -> BackendCapabilities;
    fn emit(&self, request: &BackendRequest) -> Result<Vec<BackendArtifact>, BackendError>;
}
```

Conceptually:

- `BackendRequest` should carry the resolved token store, axes/context metadata, policy, and any backend-specific options.
- `BackendArtifact` should describe each emitted file with a stable kind, relative path, backend id, and optional api version.
- `BackendCapabilities` should declare whether the backend needs component contracts, whether it emits package scaffolding, and whether it is a token backend or a higher-level package backend.

This is the right level for:

- CLI target dispatch
- manifest/report metadata
- future plugin-like growth inside the repo

It is a better seam than pushing more behavior into the low-level `Emitter` trait.

## Target Taxonomy

The CLI should evolve away from ad hoc names toward explicit backend ids.

Recommended direction:

- keep current compatibility aliases for now:
  - `css`
  - `swift`
  - `kotlin`
- introduce canonical backend ids:
  - `web-css-vars`
  - `swift-tokens`
  - `android-compose-tokens`
  - `web-tokens-ts`

Compatibility rule:

- the old names stay as aliases for one compatibility period
- docs and manifests move to canonical backend ids first

In particular, `kotlin` is too language-shaped. The product surface should talk about the platform/backend intent, not just the implementation language.

## Web Recommendation

Web should not be a single backend.

It should split into:

- `web-css-vars`
  - emits CSS custom properties and related stylesheet artifacts
- `web-tokens-ts`
  - emits typed token data for JS/TS consumers
- system-package layer above those
  - web components
  - React/Vue/Svelte adapters

This matters because CSS stylesheet emission and component-library generation have different stability and ownership boundaries.

## Apple Recommendation

The existing Swift output fits the backend model well.

Recommended shape:

- `swift-tokens` remains a backend
- SwiftUI helpers or component packages stay outside Paint core

The existing Swift package scaffold is acceptable as long as it stays a thin token package wrapper.

## Android Recommendation

Android should be modeled as an Android backend, not a generic `kotlin` target.

Recommended shape:

- canonical backend id: `android-compose-tokens`
- keep `kotlin` as a temporary alias
- separate any future Android design system or widget kit from core backend output

## Manifest and Metadata Direction

Paint now records backend output metadata generically in manifest/report `backendArtifacts` entries:

- backend id
- backend artifact kind
- relative file path plus hash/size binding
- optional backend api version

`nativeApiVersions` remains as a compatibility projection for existing Swift/Kotlin consumers, but it should no longer be treated as the primary long-term contract.

## Crate Boundary Recommendation

Near term:

- keep backend orchestration in the root crate
- keep built-in backend implementations under `paintgun-emit`
- add a backend-level registry/contract above the current value-level `Emitter`

Do not split each backend into its own crate immediately.

That should wait until:

- there are more built-in targets,
- the backend contract is stable,
- or one backend genuinely needs an independent release cadence.

## Implementation Sequence

Recommended order:

1. Completed: typed backend registry and backend request/artifact contract.
2. Completed: existing `css`, `swift`, and Android/Kotlin flows now run through that registry.
3. Completed: CSS component-system emission is split from token backend emission.
4. Next: add a typed web token-package backend.
5. Completed: the canonical Android backend id is `android-compose-tokens`, with `kotlin` retained as a compatibility alias.
6. Completed: manifest metadata now records backend artifact descriptors instead of relying on target-specific fields alone.

## Boundary Rule

If a feature needs to understand component slots, framework runtime behavior, or UI framework authoring patterns, it is probably above the Paint core boundary.

If a feature only needs resolved tokens plus backend options to emit deterministic artifacts, it belongs in the target backend layer.
