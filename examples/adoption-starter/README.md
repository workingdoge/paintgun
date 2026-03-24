# External Adoption Walkthrough

This is the canonical end-to-end example for external adopters of `tbp`.

It intentionally uses two semantically identical packs:
- `adoption-core`
- `adoption-brand`

The point of this walkthrough is the release contract and portable bundle layout, not cross-pack conflict handling.

## Layout

```text
examples/adoption-starter/
  component-contracts.json
  policy.json
  core.resolver.json
  brand.resolver.json
  sources/
    foundation.tokens.json
    theme/
    mode/
```

Both pack resolvers read from the shared `sources/` tree. `build` stages those inputs into each output bundle under `inputs/`, so the generated artifacts stay portable even though the authored files live elsewhere.

## Clean-clone flow

Run these commands from the repo root:

```bash
# Build the core pack
cargo run -- build \
  examples/adoption-starter/core.resolver.json \
  --contracts examples/adoption-starter/component-contracts.json \
  --policy examples/adoption-starter/policy.json \
  --out dist-adoption/packs/core \
  --target css \
  --format json

# Verify and sign the core pack
cargo run -- verify dist-adoption/packs/core/ctc.manifest.json
cargo run -- sign dist-adoption/packs/core/ctc.manifest.json --signer ci@example
cargo run -- verify dist-adoption/packs/core/ctc.manifest.json --require-signed

# Build the brand pack
cargo run -- build \
  examples/adoption-starter/brand.resolver.json \
  --contracts examples/adoption-starter/component-contracts.json \
  --policy examples/adoption-starter/policy.json \
  --out dist-adoption/packs/brand \
  --target css \
  --format json

# Verify and sign the brand pack
cargo run -- verify dist-adoption/packs/brand/ctc.manifest.json
cargo run -- sign dist-adoption/packs/brand/ctc.manifest.json --signer ci@example
cargo run -- verify dist-adoption/packs/brand/ctc.manifest.json --require-signed

# Compose the two signed packs into a portable bundle
cargo run -- compose \
  dist-adoption/packs/core \
  dist-adoption/packs/brand \
  --out dist-adoption/compose \
  --target css \
  --contracts examples/adoption-starter/component-contracts.json \
  --policy examples/adoption-starter/policy.json \
  --format json

# Sign and strictly verify the compose bundle
cargo run -- sign dist-adoption/compose/compose.manifest.json --signer ci@example
cargo run -- verify-compose dist-adoption/compose/compose.manifest.json \
  --require-signed \
  --require-packs-signed \
  --format json
```

## Artifact guide

CI-facing artifacts:
- `dist-adoption/packs/*/ctc.manifest.json`
- `dist-adoption/packs/*/ctc.manifest.sig.json`
- `dist-adoption/packs/*/ctc.witnesses.json`
- `dist-adoption/packs/*/validation.json`
- `dist-adoption/compose/compose.manifest.json`
- `dist-adoption/compose/compose.manifest.sig.json`
- `dist-adoption/compose/compose.witnesses.json`
- `dist-adoption/compose/compose.report.json`

Human-facing artifacts:
- `dist-adoption/packs/*/tokens.css`
- `dist-adoption/packs/*/tokens.d.ts`
- `dist-adoption/packs/*/validation.txt`
- `dist-adoption/packs/*/authored.json`
- `dist-adoption/compose/compose.report.txt`

## Portable bundle rule

Keep the whole `dist-adoption/` tree together when moving or archiving the compose output.

`compose.manifest.json` records pack directories relative to `dist-adoption/compose/`, so the supported verification shape is:

```text
dist-adoption/
  packs/
    core/
    brand/
  compose/
```

Moving only `dist-adoption/compose/` without its sibling `packs/` directories will break `verify-compose`.
