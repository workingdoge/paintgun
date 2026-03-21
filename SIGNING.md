# Signing and Trust Metadata

`tbp` supports detached manifest signatures for `ctc.manifest.json` and `compose.manifest.json`.

Current scheme:

- `tbp-detached-sha256-v1`
- Detached JSON sidecar (`*.sig.json`)
- Claims hash binding (`claimsSha256`) over canonical manifest claims

This is a local integrity/trust envelope and is intentionally minimal. It is designed so pipelines can move to Sigstore/cosign without changing trust metadata shape.

## CLI

Sign a manifest:

```bash
cargo run -- sign dist/ctc.manifest.json --signer ci@example
cargo run -- sign dist-compose/compose.manifest.json --signer ci@example
```

Require signed artifacts during verify:

```bash
cargo run -- verify dist/ctc.manifest.json --require-signed

cargo run -- verify-compose dist-compose/compose.manifest.json \
  --require-signed \
  --require-packs-signed
```

## Manifest trust fields

Unsigned (default):

```json
{
  "trust": {
    "status": "unsigned"
  }
}
```

Signed:

```json
{
  "trust": {
    "status": "signed",
    "signatureScheme": "tbp-detached-sha256-v1",
    "signatureFile": "ctc.manifest.sig.json",
    "signer": "ci@example",
    "claimsSha256": "sha256:..."
  }
}
```

## Verification behavior

- If `trust.status == "signed"`, verify always checks detached signature consistency.
- Full-profile CTC signing claims include `admissibilityWitnessesSha256`, so admissibility bindings are tamper-evident.
- `--require-signed` enforces signed trust metadata for the top-level manifest.
- `--require-packs-signed` additionally enforces signed trust metadata for each referenced pack manifest during `verify-compose`.
- Path resolution for signature files is root-bound and traversal-safe (same trust root policy as other manifest entries).

## Next integration step

Replace detached hash records with Sigstore/cosign-produced attestations while keeping:

- `trust.status`
- `trust.signatureScheme`
- `trust.signatureFile`
- `trust.signer`
- `trust.claimsSha256`
