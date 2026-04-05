# Backend Compatibility Matrix

This document defines the consumer-facing compatibility contract for Paint's
current built-in backends:

- `web-css-vars`
- `web-tokens-ts`
- `swift-tokens`
- `android-compose-tokens`

It answers four different questions that should not be collapsed together:

- what files the backend emits
- what toolchain or platform assumptions the generated output makes
- what Paint actively validates today
- what Paint does not promise

## How To Read This

The rows below mix three different kinds of compatibility:

- browser feature floors for browser-delivered CSS
- package and toolchain expectations for generated source packages
- runtime assumptions about what layer Paint owns versus what the consumer owns

That distinction matters:

- browser compatibility is mostly relevant to `web-css-vars`
- package/toolchain compatibility is the main question for `web-tokens-ts`,
  `swift-tokens`, and `android-compose-tokens`
- runtime assumptions apply to all of them

## Matrix

| Backend | Primary outputs | Compatibility surface | What Paint validates today | Not promised |
| --- | --- | --- | --- | --- |
| `web-css-vars` | `tokens.css`, `tokens.vars.css`, `components.css`, `tokens.d.ts` | Modern browser CSS delivery. The emitted stylesheets require CSS cascade layers. With the current alpha examples and common policies, they also rely on modern CSS color syntax. | Rust tests assert layered CSS output and direct `oklch()` emission. The web runtime prototype and Storybook workspace consume the generated CSS artifacts. | Legacy-browser fallbacks, no-`@layer` alternate stylesheets, automatic CSS downleveling, or consumer polyfills. |
| `web-tokens-ts` | `tokens.ts`, `web/package.json`, `web/tsconfig.json`, `web/src/index.ts`, generated test scaffold | ESM TypeScript source package. Consumers are expected to compile or bundle the generated package rather than treat it as precompiled JS. The generated scaffold targets `ES2022` and `moduleResolution: Bundler`. | The generated package is consumed in [`examples/web-tokens-consumer/README.md`](../examples/web-tokens-consumer/README.md) and in the shared web runtime prototype. Rust tests validate emitted backend artifacts and API-version markers. | CommonJS output, precompiled browser-ready JS, framework-specific runtime bindings, or support for arbitrary package-manager/runtime combinations beyond the documented source-package shape. |
| `swift-tokens` | `tokens.swift`, `swift/Package.swift`, generated Swift sources and tests | Swift Package Manager package scaffold. The supported integration surface is the generated Swift package, not a broader Apple UI framework layer. | CI runs `swift test` against generated pack and compose outputs, including the alpha-color fixture path, on the generated Swift package scaffold. | SwiftUI helpers, Xcode project generation, CocoaPods/Carthage integration, XCFramework packaging, or compatibility promises for Apple-specific UI runtimes beyond the tested package surface. |
| `android-compose-tokens` | `tokens.kt`, `android/settings.gradle.kts`, `android/build.gradle.kts`, generated source and tests | Gradle module scaffold for Android-oriented token output. The supported integration surface is the generated Gradle module plus token source, not a full Android component library. | CI runs `gradle --no-daemon test` on generated pack and compose outputs, including the alpha-color fixture path, with Java 17 setup in the workflow. | A full Android UI kit, consumer app wiring, legacy Gradle/JDK combinations beyond the tested scaffold, or broader Kotlin/JVM packaging contracts outside the generated module. |

## Per-Backend Notes

### `web-css-vars`

`web-css-vars` is the only current backend whose compatibility story is mainly a
browser-feature question.

The current alpha contract is:

- treat it as a modern-web backend
- require CSS cascade layers
- expect modern CSS color syntax in normal `preserve-space` flows
- own any older-browser fallback strategy outside Paint

The web-specific note previously tracked in `docs/web_css_compatibility.md` is
folded into this section now.

Practical alpha guidance:

- the layer-only floor is:
  - Chrome / Edge 99+
  - Firefox 97+
  - Safari 15.4+
- the current OKLCH-heavy example outputs are safer to treat as:
  - Chrome / Edge 111+
  - Firefox 113+
  - Safari 15.4+

Those documented floors are CI-watched against trusted MDN
browser-compat-data via `.github/workflows/web-compat-watch.yml` and
`spec-watch/web-compat.json`.

That practical floor is an inference from the emitted alpha CSS shape, not a
guarantee that every future stylesheet will require the same versions.

### `web-tokens-ts`

`web-tokens-ts` is not a browser stylesheet contract. It is a generated source
package contract.

Consumers should assume:

- ESM package shape
- TypeScript source entrypoint
- consumer-owned bundling or transpilation
- generated token truth, consumer-local helper layers

Consumers should not assume:

- prebuilt JS bundles
- CommonJS entrypoints
- framework-owned component semantics

### `swift-tokens`

`swift-tokens` is a token package backend, not an Apple design-system runtime.

Consumers should treat the generated Swift Package as the validated boundary:

- import the generated package
- build or test it with SwiftPM
- add app or UI-framework glue outside Paint

### `android-compose-tokens`

`android-compose-tokens` is a generated Android-oriented token module, not a
full Android UI system.

Consumers should treat the generated Gradle module as the validated boundary:

- import the generated module into a larger app or system package
- keep app/theme/component composition outside Paint core
- rely on CI-backed `gradle test` coverage for the scaffold itself, not for a
  full Android application surface

## Shared Rule

All backend compatibility promises are intentionally narrow.

Paint validates generated token artifacts and package scaffolds where documented.
It does not promise that every backend output is a full end-user runtime surface
on its own.

If you need richer runtime guarantees, framework adapters, or long-tail platform
support, that should be handled by consumer-owned layers above these backend
artifacts.
