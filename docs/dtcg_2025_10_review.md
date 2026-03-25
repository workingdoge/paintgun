# Paint DTCG 2025.10 Review

This review captures a repo-local assessment of Paint against the Design Tokens Community Group 2025.10 specifications, focused on the parts Paint claims or implies today:

- Format module
- Resolver module
- Color module
- Tool-role fit for translation, documentation, and design-tool expectations

Status labels used here:

- `pass`: current code and tests materially line up with the reviewed spec requirement
- `gap`: a concrete spec requirement is currently unmet
- `risk`: likely interoperability concern or SHOULD-level deviation
- `deferred`: relevant to product quality or tool-role fit, but not a strict current conformance blocker

## Tool role

Paint is best understood as a translation and verification tool, with some documentation/reporting behavior:

- Translation-tool fit is strong: resolver loading, token normalization, backend emission, manifests, signing, and compose all center on deterministic translation into stable backend artifacts.
- Documentation-tool fit is partial: `verify`, `verify-compose`, `explain`, `annotate-report`, manifests, and report JSON provide machine- and human-readable diagnostics.
- Design-tool fit is intentionally out of scope: Paint is not an interactive authoring environment and should not be treated as one in the current architecture.

This matches the DTCG Format module's examples for `$description`: design tools may surface descriptions in UI, translation tools may render them into code comments, and documentation tools may present them alongside previews. Paint should continue optimizing for translation first, documentation second, and leave design-tool behavior to higher layers.

## Review matrix

| Module | Topic | Status | Local evidence | Notes |
| --- | --- | --- | --- | --- |
| Format | Curly-brace aliases and JSON Pointer `$ref` support | `pass` | `crates/paintgun-resolver-kernel/src/lib.rs`, `tests/resolver_references.rs`, `tests/conformance/fixtures/alias_json_pointer*` | Paint normalizes curly-brace aliases, supports JSON Pointer syntax, rejects invalid escapes, and covers same-document pointer behavior in tests. |
| Format | Token/group name character restrictions | `gap` | `crates/paintgun-resolver-kernel/src/lib.rs` tree walks skip `$`-prefixed keys and join path segments with `.`, but there is no visible validation path for illegal names | DTCG Format requires token and group names to not begin with `$` and to not contain `{`, `}`, or `.`. Paint does not currently surface those as load-time errors. Follow-up: `tbp-dbb`. |
| Format | `$description` usage | `deferred` | `README.md`, `docs/ci_contract.md`, `crates/paintgun-emit/src/lib.rs` | Paint has doc/report surfaces, but generated backend artifacts do not yet obviously render token descriptions as comments. This is optional and more about translation-tool polish than conformance. |
| Format | `$extensions` strategy | `deferred` | no explicit `$extensions` handling found in `src`, `crates`, `tests`, `README.md`, or `docs` | DTCG allows vendor-specific extension data. Paint does not appear to preserve or expose it today. This is not a hard conformance failure, but it matters if Paint wants stronger translation-tool round-tripping. |
| Resolver | Same-document and file-based reference objects | `pass` | `tests/resolver_references.rs`, `crates/paintgun-resolver-kernel/src/lib.rs` | Paint supports same-document resolver refs, local file refs, inline overrides, and cycle/error cases. |
| Resolver | Resolution order and alias resolution stages | `pass` | `tests/resolver_references.rs`, `tests/conformance.rs`, `crates/paintgun-resolver-kernel/src/lib.rs` | Current tests cover ordering, conflict precedence, circular refs, unresolved aliases, and JSON Pointer edge cases. |
| Resolver | Missing required modifier inputs | `gap` | `crates/paintgun-resolver-model/src/lib.rs`, `crates/paintgun-resolver-kernel/src/lib.rs` | `validate_input_selection()` only checks unknown axes and unknown context values. `resolve_modifier()` returns `Ok(None)` when a modifier has no default and the input omits it. DTCG Resolver requires this to error. Follow-up: `tbp-mdw`. |
| Resolver | Case-insensitive input handling | `risk` | `crates/paintgun-resolver-model/src/lib.rs` exact-match lookups, `src/resolver.rs`, `src/resolver_runtime.rs`, `README.md` | The spec says inputs SHOULD be case-insensitive, but Paint currently treats modifier names and context values as exact matches. Alpha decision: keep exact-match behavior for now and document it explicitly as an accepted interoperability tradeoff. |
| Color | Structured color values, alpha, `hex`, and `none` support | `pass` | `crates/paintgun-resolver-kernel/src/lib.rs`, `tests/resolver_context_modes.rs`, conformance fixtures | Paint enforces object-based color values, supports `alpha`, validates 6-digit `hex`, and accepts `"none"` component values. |
| Color | Supported color spaces and range checks | `pass` | `crates/paintgun-resolver-kernel/src/lib.rs` | Paint supports `srgb`, `srgb-linear`, `hsl`, `hwb`, `lab`, `lch`, `oklab`, `oklch`, `display-p3`, `a98-rgb`, `prophoto-rgb`, `rec2020`, `xyz-d65`, and `xyz-d50`, with range validation aligned to the module's intent. |

## Findings

### Hard gaps

1. Name restrictions are not enforced.
   DTCG Format 2025.10 requires token and group names to avoid leading `$` plus `{`, `}`, and `.` anywhere in the name. Paint's current tree walking code treats `$`-prefixed keys as properties and joins path segments using `.`, but it does not appear to reject invalid names explicitly.

2. Missing required resolver inputs do not currently error.
   DTCG Resolver 2025.10 requires tools to reject inputs that omit modifiers without defaults. Paint currently lets that path fall through and simply omits the modifier branch.

### Interoperability risk

1. Resolver input matching is case-sensitive.
   The Resolver module only says this behavior is a SHOULD, not a MUST. Paint now documents this as an accepted alpha deviation rather than leaving it implicit, but it remains an interoperability tradeoff for mixed-case ecosystems or external pipelines.

### Deferred excellence items

1. `$extensions` has no explicit story yet.
   That is acceptable for the current compiler/verifier shape, but it weakens Paint's posture as a translation tool when vendor metadata matters.

2. `$description` is not yet a first-class translation-output feature.
   The Format module explicitly calls out translation-tool and documentation-tool uses for descriptions. Paint has enough reporting infrastructure to support this later if it becomes valuable.

## Follow-up issues

- `tbp-dbb` Enforce DTCG token and group name restrictions
- `tbp-mdw` Reject missing required resolver modifier inputs
- `tbp-32f` Resolved by documenting the accepted alpha deviation: resolver input matching remains case-sensitive

## Source references

Official DTCG sources reviewed:

- TR: <https://www.designtokens.org/TR/2025.10/>
- Format: <https://www.designtokens.org/TR/2025.10/format/>
- Resolver: <https://www.designtokens.org/TR/2025.10/resolver/>
- Color: <https://www.designtokens.org/TR/2025.10/color/>

Particularly relevant spec sections:

- Format 5.1 / 5.1.1 on names and character restrictions
- Format 5.2.1 / 5.2.3 on `$description` and `$extensions`
- Format 7.1.2 / 7.2 on JSON Pointer support and reference resolution
- Resolver 4.2 on reference objects
- Resolver 5.1 / 5.2 / 6.1 on input handling
- Color 4.1 / 4.2 on structured color values and supported spaces
