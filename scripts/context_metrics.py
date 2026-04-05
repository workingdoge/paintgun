#!/usr/bin/env python3
import json
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESOLVER = "examples/perf-lattice/perf.resolver.json"
CONTRACTS = "examples/perf-lattice/component-contracts.json"
MODES = ["full-only", "partial", "from-contracts"]
MIN_FROM_CONTRACTS_REDUCTION_RATIO = 0.20
MIN_PARTIAL_EXPANSION_RATIO = 1.10


def ensure_premath_projection() -> None:
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts" / "ensure_premath_projection.sh")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)


def run_mode(mode: str) -> dict:
    out_dir = ROOT / f"dist-perf-{mode.replace('-', '_')}"
    if out_dir.exists():
        shutil.rmtree(out_dir)

    cmd = [
        "cargo",
        "run",
        "--",
        "build",
        RESOLVER,
        "--contracts",
        CONTRACTS,
        "--out",
        str(out_dir),
        "--target",
        "css",
        "--contexts",
        mode,
        "--format",
        "json",
    ]
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)

    manifest = json.loads((out_dir / "ctc.manifest.json").read_text())
    resolved = json.loads((out_dir / "resolved.json").read_text())
    summary = manifest["summary"]
    return {
        "mode": mode,
        "elapsedMs": elapsed_ms,
        "analysisContexts": int(summary["contexts"]),
        "emittedResolverContexts": len(resolved["contexts"]),
        "tokens": int(summary["tokens"]),
        "kanGaps": int(summary["kan_gaps"]),
        "kanConflicts": int(summary["kan_conflicts"]),
        "kanInherited": int(summary["kan_inherited"]),
        "bcViolations": int(summary["bc_violations"]),
        "orthogonalityOverlaps": int(summary["orthogonality_overlaps"]),
        "outDir": out_dir.name,
    }


def main() -> None:
    ensure_premath_projection()
    results = [run_mode(mode) for mode in MODES]
    by_mode = {r["mode"]: r for r in results}

    partial_ctx = by_mode["partial"]["analysisContexts"]
    full_ctx = by_mode["full-only"]["analysisContexts"]
    from_contracts_ctx = by_mode["from-contracts"]["analysisContexts"]

    # Hard ordering invariants.
    if not (partial_ctx > full_ctx > from_contracts_ctx):
        raise AssertionError(
            "analysis-context ordering invariant failed: expected partial > full-only > from-contracts "
            f"but got partial={partial_ctx}, full-only={full_ctx}, from-contracts={from_contracts_ctx}"
        )

    # Threshold gates to catch silent regressions.
    # Reduction ratio: fraction of full-only resolver contexts saved by from-contracts.
    reduction_ratio = (full_ctx - from_contracts_ctx) / float(full_ctx)
    if reduction_ratio < MIN_FROM_CONTRACTS_REDUCTION_RATIO:
        raise AssertionError(
            "from-contracts reduction below threshold: "
            f"got {reduction_ratio:.4f}, "
            f"required >= {MIN_FROM_CONTRACTS_REDUCTION_RATIO:.4f}"
        )

    # Expansion ratio: partial should remain materially larger than full-only for this fixture.
    expansion_ratio = partial_ctx / float(full_ctx)
    if expansion_ratio < MIN_PARTIAL_EXPANSION_RATIO:
        raise AssertionError(
            "partial expansion below threshold: "
            f"got {expansion_ratio:.4f}, required >= {MIN_PARTIAL_EXPANSION_RATIO:.4f}"
        )

    metrics = {
        "fixture": {
            "resolver": RESOLVER,
            "contracts": CONTRACTS,
        },
        "thresholds": {
            "minFromContractsReductionRatio": MIN_FROM_CONTRACTS_REDUCTION_RATIO,
            "minPartialExpansionRatio": MIN_PARTIAL_EXPANSION_RATIO,
        },
        "derived": {
            "fromContractsReductionRatio": round(reduction_ratio, 6),
            "partialExpansionRatio": round(expansion_ratio, 6),
        },
        "results": results,
    }

    metrics_dir = ROOT / "perf-metrics"
    metrics_dir.mkdir(exist_ok=True)
    json_path = metrics_dir / "context-metrics.json"
    json_path.write_text(json.dumps(metrics, indent=2) + "\n")

    lines = [
        "| mode | analysisContexts | emittedResolverContexts | elapsedMs | tokens | kanConflicts | bcViolations |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| {r['mode']} | {r['analysisContexts']} | {r['emittedResolverContexts']} | {r['elapsedMs']} | {r['tokens']} | {r['kanConflicts']} | {r['bcViolations']} |"
        )
    md_path = metrics_dir / "context-metrics.md"
    lines.extend(
        [
            "",
            f"- from-contracts reduction ratio: `{reduction_ratio:.4f}` (threshold `{MIN_FROM_CONTRACTS_REDUCTION_RATIO:.4f}`)",
            f"- partial expansion ratio: `{expansion_ratio:.4f}` (threshold `{MIN_PARTIAL_EXPANSION_RATIO:.4f}`)",
        ]
    )
    md_path.write_text("\n".join(lines) + "\n")

    print(f"Wrote metrics: {json_path}")
    print(md_path.read_text(), end="")


if __name__ == "__main__":
    main()
