# CI Contract

This document defines the machine-readable surfaces that external CI is allowed to depend on in `tbp`.

## Scope

All Cargo-based CI commands in this repo assume a repo-local Premath projection at `./premath`. In a local clone, materialize that projection first with `./scripts/link_premath_checkout.sh ../premath` or by checking out the extracted Premath repo directly into `./premath`.

The supported CI-facing commands and artifacts are:

- `build --format json`, which writes `validation.json`
- `compose --format json`, which writes `compose.report.json`
- `verify --format json`
- `verify-compose --format json`
- `annotate-report`

Human-readable stdout and stderr outside those surfaces may change more freely than the contract below.

## Schema-backed Report Artifacts

`build --format json` and `compose --format json` emit report artifacts that conform to [`schemas/report.schema.json`](../schemas/report.schema.json):

- `dist/validation.json`
- `dist-compose/compose.report.json`

Contract points:

- `reportVersion` is the schema version marker. Current value: `1`.
- `reportKind` is `pack` or `compose`.
- `plannerTrace` is optional and only appears when explicitly requested.
- Breaking schema changes must either preserve backward compatibility or bump `reportVersion`.

These artifacts are the recommended inputs for downstream annotation or archival steps.

## Verification JSON Envelopes

`verify --format json` and `verify-compose --format json` print command-result envelopes to stdout. These envelopes do not currently have a standalone JSON schema file, but the following fields are treated as stable and are covered by CLI regression tests:

- top-level:
  - `kind`
  - `manifest`
  - `ok`
- `verify` object:
  - `ok`
  - `errors`
  - `errorDetails`
- `verify.errorDetails[]` entries:
  - `code`
  - `message`
- `semantics` object:
  - `ok`
  - `errors`

`verify --format json` also includes:

- `verify.notes`

Contract points:

- `ok == true` means the command passed both artifact verification and semantic checks.
- `verify.ok` isolates the artifact/signature/path/witness verification step.
- `semantics.ok` isolates optional semantic-policy checks such as `policyDigest` and `conflictMode`.
- `errorDetails[].code` values are the stable CI-facing identifiers for machine matching.
  - Per-pack verify codes come from `tbp::verify::error_codes`.
  - Compose verify codes come from `tbp::compose::error_codes`.
- `errors` arrays are human-readable summaries and should not be the primary machine-matching surface.

## Exit Codes

Supported exit behavior:

- `verify --format json`
  - exits `0` when top-level `ok` is `true`
  - exits `1` when top-level `ok` is `false`
- `verify-compose --format json`
  - exits `0` when top-level `ok` is `true`
  - exits `1` when top-level `ok` is `false`
- `annotate-report`
  - exits `0` when the input report is readable and valid
  - exits `1` when the input report cannot be read or parsed

Important boundary:

- Pre-verification CLI/input failures such as unreadable policy files or malformed command arguments also exit `1`, but they may print a plain CLI error to stderr instead of a JSON envelope because verification never started.

## Annotation Output

`annotate-report` consumes a schema-backed report artifact (`validation.json` or `compose.report.json`) and writes:

- zero or more GitHub Actions annotation commands to stdout
- one final summary notice line with this stable prefix:
  - `::notice title=tbp/report::`

The summary notice includes:

- `reportKind`
- `conflictMode`
- `findings`
- `emitted`
- `truncated`

## Recommended CI Flow

Recommended separation of concerns:

1. Run `build --format json` or `compose --format json` to generate schema-backed diagnostic artifacts.
2. Run `verify --format json` or `verify-compose --format json` for gating and machine-readable pass/fail decisions.
3. Run `annotate-report` on `validation.json` or `compose.report.json` to emit GitHub Actions annotations for human review.

Example shape:

```bash
cargo run -- build examples/charter-steel/charter-steel.resolver.json \
  --out dist \
  --target swift \
  --format json > /tmp/build.stdout.json

cargo run -- verify dist/ctc.manifest.json --format json > /tmp/verify.json

cargo run -- annotate-report dist/validation.json \
  --file-root examples/charter-steel \
  --max 200 > /tmp/annotations.txt
```
