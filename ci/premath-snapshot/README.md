This directory is a minimal CI-only snapshot of the extracted Premath code home.

It exists so GitHub Actions can materialize a valid `./premath` projection even
before the dedicated extracted Premath workspace is published at a stable remote
that Paint can clone in CI.

Rules:

- do not treat this as the canonical code home
- do not edit these files by hand inside Paint unless the CI snapshot itself is
  being refreshed
- refresh this snapshot from `/Users/arj/dev/fish/tools/premath` when the
  extracted workspace changes in a way that affects Paint CI

The canonical Premath code home remains the sibling workspace documented in
`docs/premath_code_home.md`.
