# Releasing Paint

This document defines the first public release path for Paint. It is intentionally narrow: source installs are supported everywhere Rust stable works, and maintainers may additionally publish target-specific binary tarballs built from this repo.

## Supported install paths

Source install:

```bash
./scripts/link_premath_checkout.sh ../premath
cargo install --locked --path .
paint --version
```

Distributable artifact path:

```bash
./scripts/package_release.sh
```

The packaging helper builds the current Cargo version for the host target by default and writes:
- `release-artifacts/paintgun-vX.Y.Z-<target>.tar.gz`
- `release-artifacts/paintgun-vX.Y.Z-<target>.tar.gz.sha256`

Use `--target <triple>` to package a different Rust target when the toolchain is available.

## Artifact contents

Each binary tarball contains:
- `paint`
- `README.md`
- `SIGNING.md`
- `CHANGELOG.md`
- `Cargo.toml`

That is the minimum supported public artifact shape for the first release. Package-manager integrations and hosted update infrastructure are out of scope for this track.

## Versioning policy

`paintgun` uses SemVer tags in the form `vX.Y.Z`, and the tag must match the root crate version in `Cargo.toml`.

Release policy:
- `0.x.y` is pre-1.0. Breaking CLI or workflow changes may happen in a minor release, but they must be called out in `CHANGELOG.md` and release notes.
- Patch releases are for bug fixes, packaging/docs corrections, and other low-risk changes that do not intentionally break documented flows.
- Breaking changes to machine-readable verification outputs, schema-backed reports, or manifest compatibility must also be reflected in their explicit version markers and called out in release notes.
- The supported spec track for this release line is DTCG `2025.10`; widening or changing that support must be noted in release notes.

## Changelog expectations

Before tagging a release:
- update `CHANGELOG.md`
- move user-visible changes out of `Unreleased` into a new `## X.Y.Z - YYYY-MM-DD` section
- call out CLI, report/schema, trust-policy, and artifact-shape changes explicitly

## Signing and trust expectations

For the first public release, detached manifest signing is supported but not required by default:
- unsigned pack and compose manifests remain valid unless a verifier opts into `--require-signed` or `--require-packs-signed`
- if release examples or published artifacts are signed, release notes should name the signer identity and detached signature scheme
- any change to that default policy belongs in release notes and should stay aligned with `SIGNING.md`

## Maintainer checklist

1. Confirm the release version in `Cargo.toml` and update `CHANGELOG.md`.
2. Materialize the extracted Premath repo into the local `./premath` projection if it is not already present:

   ```bash
   ./scripts/link_premath_checkout.sh ../premath
   ```

3. Run the release quality gates:

   ```bash
   cargo test --workspace
   python3 scripts/spec_watch.py check --targets spec-watch/targets.json --lock spec-watch/lock.json --artifact-dir spec-watch-artifacts
   cargo install --locked --path . --root "$(mktemp -d)"
   ```

4. Build at least one target-specific artifact:

   ```bash
   ./scripts/package_release.sh
   ```

5. If publishing multiple targets, rerun the helper with `--target <triple>` per target.
6. Review whether the release ships unsigned artifacts or signed example manifests, and make that explicit in the release notes.
7. Publish the tarball(s), `.sha256` sidecar(s), and the corresponding changelog/release notes together.

## Notes

- The CI baseline for this repo is documented in `.github/workflows/ci.yml`.
- Upstream Design Tokens drift is checked by `.github/workflows/spec-watch.yml`; keep the lockfile current before shipping.
- The release artifact path in this document is intentionally mechanical and repo-local so maintainers do not need hidden packaging infrastructure to cut the first public release.
