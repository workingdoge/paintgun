# Web Compatibility Watch

`Paintgun` ships a third narrow external-drift watch for the documented
`web-css-vars` compatibility floor.

Unlike the pinned DTCG digest watch and the stable-release discovery watch, this
check is not about token-spec versions. It answers a smaller product question:
do Paint's documented modern-web assumptions still match trusted external
browser compatibility data for the specific CSS features Paint says consumers
must support?

## Trusted sources

The checked-in watch config lives at `spec-watch/web-compat.json` and currently
trusts MDN browser-compat-data raw JSON for:

- CSS cascade layers: `@layer`
- CSS `oklch()` color values

These are the two externally sourced assumptions that currently back the
documented `web-css-vars` floor in [`docs/backend_compatibility.md`](backend_compatibility.md).

## Manual Use

Run the check locally with:

```bash
python3 scripts/spec_watch.py web-compat-check \
  --compat spec-watch/web-compat.json \
  --artifact-dir web-compat-watch-artifacts
```

The GitHub Actions workflow `.github/workflows/web-compat-watch.yml` runs the
same command weekly and on manual dispatch.

## Triage

When the web compatibility watch fails:

1. Inspect `web-compat-watch-artifacts/report.json` and the uploaded payload
   copies to confirm which documented floor drifted.
2. Decide whether the drift means:
   - the external platform data changed and Paint's docs should move, or
   - Paint's actual emitted web CSS contract changed and the compatibility docs
     and watch config should be updated together.
3. Open or update a `bd` follow-up issue in the canonical repo root for any
   accepted contract change.
4. Keep the watch narrow. If a new web-facing compatibility assumption becomes
   part of the documented contract, add it to `spec-watch/web-compat.json` in
   the same review that updates the docs and tests.

This keeps CI anchored to a small set of trusted external facts without turning
Paint into a general-purpose browser-compat crawler.
