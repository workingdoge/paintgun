# Trust Policy

This document defines the public signing and verification contract for Paint artifacts in the current release line.

## Public v1 policy

For the first public Paint release track, signing is optional by default.

That means:
- unsigned pack manifests are valid input to `verify`
- unsigned compose manifests are valid input to `verify-compose`
- unsigned referenced pack manifests are valid during `verify-compose` unless the caller opts into stricter policy flags
- once a manifest declares `trust.status = "signed"`, `paint` always verifies the detached signature and trust metadata consistency

Consumers that want signed-only enforcement can opt in without changing artifact shape:
- `verify --require-signed`
- `verify-compose --require-signed`
- `verify-compose --require-packs-signed`

## Policy matrix

Pack verification:
- default `verify`: accepts unsigned or signed manifests; signed manifests must verify successfully
- `verify --require-signed`: requires the top-level pack manifest to be signed and valid

Compose verification:
- default `verify-compose`: accepts unsigned or signed compose manifests, and unsigned or signed referenced pack manifests; any signed manifest must verify successfully
- `verify-compose --require-signed`: requires the top-level compose manifest to be signed and valid
- `verify-compose --require-packs-signed`: requires every referenced pack manifest to be signed and valid
- both compose flags may be combined for fully signed bundle enforcement

## Trust metadata contract

Supported `trust.status` values:
- `unsigned`
- `signed`

Unsigned manifests:
- may omit the remaining trust fields entirely
- are still valid in the default verifier profile for this release line

Signed manifests:
- must use the recognized scheme `paintgun-detached-sha256-v1`
- must include `trust.signatureFile`
- must include `trust.claimsSha256`
- may include `trust.signer`
- must have a detached sidecar whose claims hash matches the manifest's canonical claims payload

The current sidecar format is repo-local and intentionally minimal. The public compatibility expectation is the trust field shape above, not a promise that the signing backend will always be hand-rolled JSON.

## Compatibility expectations

- Making signing mandatory by default would be a release-policy change and must be called out explicitly in release notes.
- Adding a new signing backend is acceptable only if verifiers keep the trust metadata contract explicit and fail cleanly on unsupported schemes.
- Signed artifact verification is stricter than unsigned verification by design: once `trust.status` is `signed`, verification must fail on trust metadata or detached-signature mismatch even when `--require-signed` is not set.

## Related docs

- `SIGNING.md` covers the detached signature scheme and CLI usage.
- `README.md` shows the verifier flags in the main command-line flow.
