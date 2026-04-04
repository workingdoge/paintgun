# Compose Scale Benchmark

This fixture exists to measure compose and planner behavior on a pack graph large enough to feel
organizational rather than toy-sized.

The committed inputs are intentionally small:

- `spec.json` defines the pack matrix and axes
- `component-contracts.json` defines the contract-bounded planning surface

The actual 24-pack corpus is generated on demand by
[`scripts/compose_scale_metrics.py`](../../scripts/compose_scale_metrics.py).

## Corpus Shape

The generator expands:

- 6 orgs
- 4 surfaces per org
- 24 packs total

Each generated pack exposes the same axis universe:

- `theme`: `light`, `dark`
- `density`: `compact`, `comfortable`
- `mode`: `docs`, `marketing`
- `platform`: `web`, `ios`, `android`

The contract-bounded benchmark only cares about:

- `color.surface.bg`
- `color.action.primary`
- `dimension.radius.md`

That means `from-contracts` should be able to ignore the `mode` and `platform` dimensions for the
compose benchmark, while `partial` still expands across the whole lattice.

## What The Benchmark Measures

The benchmark script:

1. generates the 24 authored resolver documents into `dist-compose-scale/corpus/`
2. builds each pack in `partial` mode so the stored pack graph can support all compose modes
3. composes the 24-pack graph in:
   - `full-only`
   - `partial`
   - `from-contracts`
4. records:
   - compose runtime cost
   - planner context counts from `plannerTrace`
   - report/witness volume
   - finding counts by kind

## Run It

From the repo root:

```bash
python3 scripts/compose_scale_metrics.py
```

Outputs:

- `dist-compose-scale/` — generated corpus, built packs, and compose outputs
- `perf-metrics/compose-scale-metrics.json` — machine-readable metrics summary
- `perf-metrics/compose-scale-metrics.md` — human-readable metrics summary

This benchmark is measurement-first. It does not yet enforce budget thresholds. That follow-on
work belongs to `tbp-qnb.10`.

## What To Look For

This corpus is designed to surface two non-obvious behaviors:

- `partial` should still be the largest evaluated context set.
- `from-contracts` should be materially smaller than `partial`, but it may still exceed `full-only`
  on a large compose graph because it expands only the contract-relevant axes and keeps their
  partial combinations.

It is also intentionally possible for `from-contracts` to collapse the conflict surface much more
aggressively than the unbounded compose modes. That is useful for bounded UI-facing planning, but it
also means `from-contracts` is not a substitute for a full org-wide compose conflict review.
