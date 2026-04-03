# Spec Watch

`Paintgun` pins the upstream Design Tokens 2025.10 technical-report and schema endpoints it depends on in `spec-watch/targets.json` and `spec-watch/lock.json`.

The dedicated GitHub Actions workflow `.github/workflows/spec-watch.yml` runs on a weekly schedule and via manual dispatch. It fetches each canonical endpoint, compares status/content type/resolved URL/size/SHA-256 against the checked-in lock file, uploads a report artifact, and fails when drift is detected.

This is the pinned-digest watch only. New upstream stable release detection lives in [`docs/spec_release_watch.md`](spec_release_watch.md) and `.github/workflows/spec-release-discovery.yml`.

## Manual Use

Check the current upstream digests against the pinned lock:

```bash
python3 scripts/spec_watch.py check \
  --targets spec-watch/targets.json \
  --lock spec-watch/lock.json \
  --artifact-dir spec-watch-artifacts
```

Refresh the lock file after reviewing and accepting upstream changes:

```bash
python3 scripts/spec_watch.py refresh \
  --targets spec-watch/targets.json \
  --lock spec-watch/lock.json
```

## Triage

When the spec-watch workflow fails:

1. Inspect `spec-watch-artifacts/report.json` and the uploaded payload copies to see which canonical endpoint changed.
2. Decide whether the upstream change affects Paintgun code, tests, schemas, docs, or release expectations.
3. Open or update a `bd` follow-up issue in the canonical repo root so the drift has an explicit owner.
4. If Paintgun should adopt the upstream change, update the code/docs as needed, run `python3 scripts/spec_watch.py refresh`, and commit the refreshed lock file in the same review.

If the only drift is on the technical-report HTML pages while `spec-release-discovery` still reports the same stable version and the schema endpoints remain unchanged, treat that as editorial/site-build churn rather than an automatic runtime-support change. In that case, inspect the live report metadata, decide whether the rendered TR content is still the same supported release, and refresh `spec-watch/lock.json` only after that review.

This flow keeps the watch deterministic without turning CI into a general-purpose crawler or auto-mutating issue bot.
