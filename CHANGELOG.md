# Changelog

All notable changes to `tbp` should be documented in this file.

The release process in `docs/releasing.md` assumes:
- tags use `vX.Y.Z` and match `Cargo.toml`
- `Unreleased` is trimmed into a dated release section when shipping
- CLI, manifest, schema, or verification-contract changes are called out explicitly

## Unreleased

### Added
- Release packaging guidance, changelog policy, and a maintainer packaging helper.
- A public tarball-first install path via `docs/install.md`, `scripts/install_paint.sh`, and `scripts/test_public_install.sh`.
- A deterministic output-root-local incremental cache foundation for `paint build` and `paint compose`, documented in `docs/incremental_builds.md`.

### Changed
- Documented the current resolver-input behavior as case-sensitive by exact match, as an explicit alpha-era deviation from the DTCG Resolver 2025.10 case-insensitivity SHOULD guidance.
- Documented and enforced the alpha policy that Paint stays version-strict to DTCG 2025.10 and rejects unknown reserved `$...` properties by default.
- Made the README and release docs consumer-first: public installs no longer lead with the contributor-only `./premath` bootstrap path.
