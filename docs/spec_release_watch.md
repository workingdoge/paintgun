# Spec Release Discovery

`Paintgun` ships a second upstream-spec check alongside the pinned `2025.10` digest watch. The discovery watch does not compare payload hashes. It checks a small set of trusted upstream index pages to answer a different question: has DTCG published a newer stable release than the one Paint currently targets?

## Trusted sources

The checked-in discovery config lives at `spec-watch/discovery.json` and currently trusts:

- `https://www.designtokens.org/technical-reports/`
- `https://www.w3.org/community/design-tokens/`

These are treated as discovery sources only. They do not widen Paint's runtime support surface, and they do not replace the pinned `2025.10` digest lock in `spec-watch/lock.json`.

## Manual Use

Run the discovery check locally with:

```bash
python3 scripts/spec_watch.py discover-check \
  --discovery spec-watch/discovery.json \
  --artifact-dir spec-release-discovery-artifacts
```

The GitHub Actions workflow `.github/workflows/spec-release-discovery.yml` runs the same command weekly and on manual dispatch.

## Triage

When the discovery watch fails:

1. Inspect `spec-release-discovery-artifacts/report.json` and the uploaded payload copies to confirm which trusted source changed.
2. Open or update a `bd` follow-up issue in the canonical repo root for the newly detected stable version.
3. Review the new upstream release against Paint's current support boundary and conformance docs before changing runtime behavior.
4. If Paint adopts the new stable version, update `spec-watch/discovery.json`, the DTCG review docs, and any pinned release notes in the same change.

This keeps Paint version-strict by default while still making new upstream stable releases visible in CI.
