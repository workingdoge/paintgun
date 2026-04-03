# Web Runtime IR

## Decision

Pure web components, Storybook, and future server-side web adapters should not consume the
canonical design-system schema directly.

They should consume a derived web runtime IR that:

- expresses the public web-facing contract of the system
- stays neutral across implementation styles
- can be consumed by both browser-side and server-side tools

This IR sits:

- above the canonical design-system schema
- alongside the documentation projection IR
- below concrete consumers such as pure custom elements, Storybook, and future Rust/htmx adapters

## Why A Separate Web IR Exists

The canonical design-system schema owns component semantics.

The web runtime layer needs additional web-facing information that is not purely canonical
component semantics but also should not be trapped inside one implementation:

- custom-element tag names
- slot names
- exposed part names
- public attributes and properties
- public events
- styling hooks for CSS consumers
- references to generated web token artifacts

Those belong in a web-facing projection layer, not in:

- raw DTCG tokens
- Paint core
- Storybook config
- one specific web-component runtime library

In practice, that means the authored prototype should not collapse canonical component semantics and
web projection choices into one schema file. A separate authored web projection input is the right
place for tag names, reflected attributes/properties, public events, style hooks, and artifact
bindings before those choices are compiled into the generated web runtime IR.

## Public Web Contract

The web runtime IR should describe the public contract a web consumer can rely on.

That contract includes:

- component-to-tag mapping
- named slots
- exposed parts
- public attributes
- public properties
- public events
- variants and states as web-facing selectors or state inputs
- styling hooks
- accessibility defaults and support notes
- references to supporting token/backend artifacts

This is the information a pure custom-element package, Storybook, or a server-side adapter needs
to understand the component surface.

## What Is Canonical In The Web IR

Canonical for the web IR:

- stable custom-element tag name
- public slot names
- exposed `part` names
- public attribute/property/event names
- mapping from schema variants/states to web-facing controls
- public styling hooks such as CSS custom properties and exposed parts
- references to generated backend artifacts needed by the web layer
- web examples and example inputs

Not canonical in the web IR:

- framework internals
- render templates
- implementation language
- Storybook story file structure
- shadow-tree implementation details that are not part of the public contract

## Shadow DOM And Internal Structure

The IR should not force one internal rendering model, but it should let consumers describe public
shadow-DOM-facing hooks when they matter.

For example:

- exposed `part` names belong in the IR
- named slots belong in the IR
- whether styling relies on CSS custom properties belongs in the IR

But these do not:

- exact internal node layout
- internal template structure
- how a component schedules rendering
- whether a particular implementation uses a helper library

The public contract matters. The private tree does not.

## Recommended Record Families

Recommended top-level record families for the web runtime IR:

- `webSystem`
  - system id
  - design-system release version
  - compatible backend artifact references
- `webComponents`
  - one record per component
  - tag name
  - title/description/status
  - accessibility/support notes
- `webParts`
  - exposed part names and their semantic meaning
- `webSlots`
  - slot names and slot semantics
- `webInputs`
  - web-facing variant/state controls
  - attribute/property mapping
- `webEvents`
  - public event names and payload expectations
- `webStyleHooks`
  - CSS custom properties
  - exposed `part` names
  - any required supporting stylesheets
- `webExamples`
  - example scenarios and example input payloads
- `webArtifacts`
  - references to generated `web-css-vars` and `web-tokens-ts` artifacts

The exact names may change. The separation is the important part.

## Styling Hooks

The IR should make web styling hooks explicit.

That means the IR may describe:

- required token stylesheets
- optional component stylesheets
- CSS custom properties intended for consumers
- exposed `part` names

It should not encode:

- every CSS rule
- all rendered selectors
- implementation-private classes

CSS artifacts themselves stay generated assets. The IR should describe how consumers relate to
those assets.

## Events, Attributes, And Properties

These need explicit treatment because browser, Storybook, and server-side consumers all care about
them differently.

The IR should distinguish:

- attribute name and value shape
- property name and value shape
- event name and payload shape
- whether an event is intended to cross component boundaries

That gives:

- Storybook a control surface
- pure web components a public API contract
- server-side consumers a predictable surface for template generation and docs

## States And Variants

The canonical schema owns semantic states and variants.

The web runtime IR should own their web-facing projection:

- which variants are exposed as attributes or properties
- which states are externally settable versus internal-only
- which states are represented as styling hooks or public indicators

This is important because the web layer may need to say:

- `tone` is a reflected attribute
- `disabled` is both a property and an attribute
- `selected` is public but `pressedTransient` is not

Those are runtime contract choices, not canonical design-system truths.

## Serialization Decision

The web runtime IR is conceptual first, but the first portable artifact should be a neutral
serialized representation.

Recommended alpha shape:

- one neutral serialized artifact such as `system.web.json`
- optional generated typed adapters for TypeScript and Rust

Why:

- pure web components can load or compile from a neutral artifact
- Storybook can consume the same neutral artifact
- Rust/htmx or other server-side adapters can consume the same source without JS-specific coupling

JSON is not the idea itself. It is simply the most practical first transport.

## Typed Adapters

Typed adapters are recommended, but they should be derived from the neutral artifact.

Examples:

- ESM/TypeScript adapter for browser-side tooling
- Rust types or codegen adapter for server-side rendering and docs helpers

The important rule is:

- one conceptual IR
- one portable neutral artifact
- many typed adapters

Not:

- one JS truth
- one Rust truth
- one Storybook truth

## Relationship To Existing Paint Outputs

The web runtime IR should reference existing backend outputs rather than replace them.

Likely references include:

- `web-css-vars` artifacts such as token and component stylesheets
- `web-tokens-ts` package artifacts
- backend artifact descriptors from manifests/reports

This keeps Paint responsible for token/backend generation while the web IR stays responsible for
public runtime semantics.

## Relationship To Storybook

Storybook should consume the web runtime IR as one projection consumer.

Storybook may derive from it:

- control definitions
- example bindings
- component metadata

Storybook should not define:

- the canonical web API
- part names
- slot names
- event surface

## Relationship To Pure Web Components

The prototype web-components package should consume the IR as an authored runtime package.

That means the package may implement:

- custom elements
- shadow DOM
- templates
- slots
- exposed parts

But the IR should remain independent of the specific authoring technique.

## Relationship To Server-Side Consumers

Server-side consumers should be able to use the same IR for:

- docs rendering
- template helpers
- component catalogs
- htmx-oriented HTML helpers

This is why the IR should not assume a JS-only execution model.

## Non-Goals

This IR does not define:

- one required web-component library
- full Storybook setup
- browser build tooling
- exact package layout for the prototype
- full code generation

It defines the public web-facing contract and the transport shape the next prototype should
consume.

## Guidance For The Prototype Issue

`tbp-z74.3` should prove one narrow path:

- canonical design-system schema
- web runtime IR
- pure web-components consumer
- Storybook consumer

If that works, later adapters can be added without reopening the canonical truth question.
