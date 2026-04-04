#!/usr/bin/env python3
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "examples" / "compose-scale" / "spec.json"
CONTRACTS_PATH = ROOT / "examples" / "compose-scale" / "component-contracts.json"
OUTPUT_ROOT = ROOT / "dist-compose-scale"
METRICS_DIR = ROOT / "perf-metrics"
PACK_BUILD_MODE = "partial"
COMPOSE_MODES = ["full-only", "partial", "from-contracts"]

LIGHT_SURFACES = ["#f5f7fb", "#f7f4ea", "#eef6ff", "#f2f5f0", "#faf2ff", "#f4f6f8"]
DARK_SURFACES = ["#111827", "#1f1728", "#16213a", "#18231c", "#24182d", "#172233"]
ACTION_LIGHT = ["#276ef1", "#6d28d9", "#0f7b6c", "#c25100"]
ACTION_DARK = ["#8eb4ff", "#c5b4ff", "#6de0cb", "#ffb266"]
MODE_ACCENTS = {
    "docs": "#4c63ff",
    "marketing": "#ff7b54",
}
PLATFORM_DURATIONS = {
    "web": 120,
    "ios": 150,
    "android": 180,
}


@dataclass(frozen=True)
class PackSeed:
    org: str
    org_index: int
    surface: str
    surface_index: int

    @property
    def pack_id(self) -> str:
        return f"{self.org}-{self.surface}"


def load_spec() -> dict[str, Any]:
    return json.loads(SPEC_PATH.read_text())


def pack_seeds(spec: dict[str, Any]) -> list[PackSeed]:
    seeds: list[PackSeed] = []
    for org_index, org in enumerate(spec["orgs"]):
        for surface_index, surface in enumerate(spec["surfaces"]):
            seeds.append(PackSeed(org=org, org_index=org_index, surface=surface, surface_index=surface_index))
    return seeds


def color(hex_value: str) -> dict[str, Any]:
    return {
        "$type": "color",
        "$value": {
            "colorSpace": "srgb",
            "components": [0, 0, 0],
            "alpha": 1,
            "hex": hex_value,
        },
    }


def dimension(px: int) -> dict[str, Any]:
    return {
        "$type": "dimension",
        "$value": {
            "value": str(px),
            "unit": "px",
        },
    }


def duration(ms: int) -> dict[str, Any]:
    return {
        "$type": "duration",
        "$value": {
            "value": str(ms),
            "unit": "ms",
        },
    }


def pack_document(seed: PackSeed) -> dict[str, Any]:
    light_surface = LIGHT_SURFACES[seed.org_index]
    dark_surface = DARK_SURFACES[seed.org_index]
    light_action = ACTION_LIGHT[seed.surface_index]
    dark_action = ACTION_DARK[(seed.org_index + seed.surface_index) % len(ACTION_DARK)]
    compact_radius = 6 + (seed.surface_index * 2) + (seed.org_index % 2)
    comfortable_radius = compact_radius + 4
    docs_space = 16 + seed.surface_index
    marketing_space = 20 + seed.org_index

    return {
        "name": seed.pack_id,
        "version": "2025.10",
        "description": (
            "Synthetic compose-scale benchmark pack "
            f"for org {seed.org} surface {seed.surface}."
        ),
        "sets": {
            "foundation": {
                "sources": [
                    {
                        "color": {
                            "surface": {
                                "bg": color("#ffffff"),
                            },
                            "text": {
                                "primary": color("#111111"),
                            },
                            "action": {
                                "primary": color(light_action),
                            },
                            "modeAccent": {
                                "primary": color(MODE_ACCENTS["docs"]),
                            },
                        },
                        "dimension": {
                            "radius": {
                                "md": dimension(comfortable_radius),
                            },
                            "space": {
                                "lg": dimension(docs_space),
                            },
                        },
                        "duration": {
                            "fast": duration(PLATFORM_DURATIONS["web"]),
                        },
                    }
                ]
            }
        },
        "modifiers": {
            "theme": {
                "contexts": {
                    "light": [
                        {
                            "color": {
                                "surface": {
                                    "bg": color(light_surface),
                                },
                                "action": {
                                    "primary": color(light_action),
                                },
                            }
                        }
                    ],
                    "dark": [
                        {
                            "color": {
                                "surface": {
                                    "bg": color(dark_surface),
                                },
                                "action": {
                                    "primary": color(dark_action),
                                },
                            }
                        }
                    ],
                }
            },
            "density": {
                "contexts": {
                    "compact": [
                        {
                            "dimension": {
                                "radius": {
                                    "md": dimension(compact_radius),
                                }
                            }
                        }
                    ],
                    "comfortable": [
                        {
                            "dimension": {
                                "radius": {
                                    "md": dimension(comfortable_radius),
                                }
                            }
                        }
                    ],
                }
            },
            "mode": {
                "contexts": {
                    "docs": [
                        {
                            "color": {
                                "modeAccent": {
                                    "primary": color(MODE_ACCENTS["docs"]),
                                }
                            },
                            "dimension": {
                                "space": {
                                    "lg": dimension(docs_space),
                                }
                            },
                        }
                    ],
                    "marketing": [
                        {
                            "color": {
                                "modeAccent": {
                                    "primary": color(MODE_ACCENTS["marketing"]),
                                }
                            },
                            "dimension": {
                                "space": {
                                    "lg": dimension(marketing_space),
                                }
                            },
                        }
                    ],
                }
            },
            "platform": {
                "contexts": {
                    platform: [
                        {
                            "duration": {
                                "fast": duration(value + seed.surface_index * 10),
                            }
                        }
                    ]
                    for platform, value in PLATFORM_DURATIONS.items()
                }
            },
        },
        "resolutionOrder": [
            {"$ref": "#/sets/foundation"},
            {"$ref": "#/modifiers/theme"},
            {"$ref": "#/modifiers/density"},
            {"$ref": "#/modifiers/mode"},
            {"$ref": "#/modifiers/platform"},
        ],
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def run_checked(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(proc.returncode)
    return proc


def ensure_paint_binary() -> Path:
    run_checked(["bash", str(ROOT / "scripts" / "ensure_premath_projection.sh")], ROOT)
    run_checked(["cargo", "build", "--quiet", "--bin", "paint"], ROOT)
    return ROOT / "target" / "debug" / "paint"


def generate_corpus(spec: dict[str, Any], corpus_dir: Path) -> list[Path]:
    ensure_clean_dir(corpus_dir)
    resolvers: list[Path] = []
    for seed in pack_seeds(spec):
        path = corpus_dir / f"{seed.pack_id}.resolver.json"
        write_json(path, pack_document(seed))
        resolvers.append(path)
    return resolvers


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def build_pack(binary: Path, resolver_path: Path, out_dir: Path) -> dict[str, Any]:
    cmd = [
        str(binary),
        "build",
        str(resolver_path),
        "--contracts",
        str(CONTRACTS_PATH),
        "--out",
        str(out_dir),
        "--target",
        "web-css-vars",
        "--contexts",
        PACK_BUILD_MODE,
        "--planner-trace",
        "--format",
        "json",
    ]
    start = time.perf_counter()
    run_checked(cmd, ROOT)
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)

    manifest = read_json(out_dir / "ctc.manifest.json")
    validation = read_json(out_dir / "validation.json")
    trace = validation.get("plannerTrace", {})
    return {
        "packId": manifest["packIdentity"]["packId"],
        "elapsedMs": elapsed_ms,
        "resolvedContexts": int(manifest["summary"]["contexts"]),
        "findingCounts": validation["counts"],
        "plannerTrace": {
            "mode": trace.get("mode"),
            "analysisIncluded": trace.get("counts", {}).get("analysisIncluded"),
            "resolverIncluded": trace.get("counts", {}).get("resolverIncluded"),
            "universe": trace.get("counts", {}).get("universe"),
        },
    }


def compose_mode(binary: Path, pack_dirs: list[Path], mode: str, out_dir: Path) -> dict[str, Any]:
    cmd = [
        str(binary),
        "compose",
        *[str(path) for path in pack_dirs],
        "--out",
        str(out_dir),
        "--target",
        "web-css-vars",
        "--contracts",
        str(CONTRACTS_PATH),
        "--contexts",
        mode,
        "--planner-trace",
        "--format",
        "json",
    ]
    start = time.perf_counter()
    run_checked(cmd, ROOT)
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)

    report = read_json(out_dir / "compose.report.json")
    witnesses = read_json(out_dir / "compose.witnesses.json")
    trace = report.get("plannerTrace", {})
    findings = report["counts"]
    return {
        "mode": mode,
        "elapsedMs": elapsed_ms,
        "plannerTrace": {
            "analysisIncluded": trace.get("counts", {}).get("analysisIncluded"),
            "resolverIncluded": trace.get("counts", {}).get("resolverIncluded"),
            "universe": trace.get("counts", {}).get("universe"),
            "excluded": trace.get("counts", {}).get("excluded"),
            "traceBytes": len(json.dumps(trace, sort_keys=True).encode("utf8")),
        },
        "report": {
            "totalFindings": findings["total"],
            "byKind": findings["byKind"],
            "bytes": (out_dir / "compose.report.json").stat().st_size,
        },
        "witnesses": {
            "conflicts": len(witnesses["conflicts"]),
            "bytes": (out_dir / "compose.witnesses.json").stat().st_size,
        },
        "outDir": out_dir.name,
    }


def summarize_pack_builds(results: list[dict[str, Any]]) -> dict[str, Any]:
    elapsed = [r["elapsedMs"] for r in results]
    contexts = [r["resolvedContexts"] for r in results]
    traces = [r["plannerTrace"]["analysisIncluded"] for r in results]
    return {
        "count": len(results),
        "mode": PACK_BUILD_MODE,
        "elapsedMs": {
            "total": round(sum(elapsed), 2),
            "mean": round(sum(elapsed) / len(elapsed), 2),
            "max": round(max(elapsed), 2),
            "min": round(min(elapsed), 2),
        },
        "resolvedContexts": {
            "min": min(contexts),
            "max": max(contexts),
        },
        "plannerTrace": {
            "analysisIncludedMin": min(traces),
            "analysisIncludedMax": max(traces),
            "sample": results[0]["plannerTrace"],
        },
    }


def render_markdown(metrics: dict[str, Any]) -> str:
    lines = [
        "# Compose Scale Metrics",
        "",
        f"- pack count: `{metrics['fixture']['packCount']}`",
        f"- pack build mode: `{metrics['packBuild']['mode']}`",
        f"- compose modes: `{', '.join(metrics['fixture']['composeModes'])}`",
        "",
        "## Pack Build Summary",
        "",
        f"- total elapsed ms: `{metrics['packBuild']['elapsedMs']['total']}`",
        f"- mean elapsed ms: `{metrics['packBuild']['elapsedMs']['mean']}`",
        f"- resolved contexts per pack: `{metrics['packBuild']['resolvedContexts']['min']}` to `{metrics['packBuild']['resolvedContexts']['max']}`",
        "",
        "## Compose Modes",
        "",
        "| mode | elapsedMs | analysisIncluded | universe | findings | conflicts | reportBytes | witnessBytes | traceBytes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in metrics["composeModes"]:
        lines.append(
            "| {mode} | {elapsed} | {analysis} | {universe} | {findings} | {conflicts} | {report_bytes} | {witness_bytes} | {trace_bytes} |".format(
                mode=result["mode"],
                elapsed=result["elapsedMs"],
                analysis=result["plannerTrace"]["analysisIncluded"],
                universe=result["plannerTrace"]["universe"],
                findings=result["report"]["totalFindings"],
                conflicts=result["witnesses"]["conflicts"],
                report_bytes=result["report"]["bytes"],
                witness_bytes=result["witnesses"]["bytes"],
                trace_bytes=result["plannerTrace"]["traceBytes"],
            )
        )

    lines.extend(
        [
            "",
            "## Derived",
            "",
            f"- partial above full-only: `{metrics['derived']['partialAboveFullOnly']}`",
            f"- partial above from-contracts: `{metrics['derived']['partialAboveFromContracts']}`",
            f"- from-contracts above full-only: `{metrics['derived']['fromContractsAboveFullOnly']}`",
            f"- partial to from-contracts reduction ratio: `{metrics['derived']['fromContractsReductionVsPartialRatio']}`",
            f"- from-contracts to full-only expansion ratio: `{metrics['derived']['fromContractsExpansionVsFullOnlyRatio']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    spec = load_spec()
    binary = ensure_paint_binary()

    corpus_dir = OUTPUT_ROOT / "corpus"
    packs_dir = OUTPUT_ROOT / "packs"
    ensure_clean_dir(OUTPUT_ROOT)
    packs_dir.mkdir(parents=True, exist_ok=True)
    resolver_paths = generate_corpus(spec, corpus_dir)

    pack_results: list[dict[str, Any]] = []
    pack_dirs: list[Path] = []
    for resolver_path in resolver_paths:
        out_dir = packs_dir / resolver_path.stem.replace(".resolver", "")
        out_dir.mkdir(parents=True, exist_ok=True)
        pack_dirs.append(out_dir)
        pack_results.append(build_pack(binary, resolver_path, out_dir))

    compose_results: list[dict[str, Any]] = []
    for mode in COMPOSE_MODES:
        out_dir = OUTPUT_ROOT / f"compose-{mode.replace('-', '_')}"
        out_dir.mkdir(parents=True, exist_ok=True)
        compose_results.append(compose_mode(binary, pack_dirs, mode, out_dir))

    by_mode = {result["mode"]: result for result in compose_results}
    partial_analysis = by_mode["partial"]["plannerTrace"]["analysisIncluded"]
    full_analysis = by_mode["full-only"]["plannerTrace"]["analysisIncluded"]
    from_contracts_analysis = by_mode["from-contracts"]["plannerTrace"]["analysisIncluded"]
    partial_above_full_only = partial_analysis > full_analysis
    partial_above_from_contracts = partial_analysis > from_contracts_analysis
    if not (partial_above_full_only and partial_above_from_contracts):
        raise AssertionError(
            "expected compose planner partial mode to remain the largest evaluated set "
            f"but got partial={partial_analysis}, full-only={full_analysis}, "
            f"from-contracts={from_contracts_analysis}"
        )

    metrics = {
        "fixture": {
            "spec": str(SPEC_PATH.relative_to(ROOT)),
            "contracts": str(CONTRACTS_PATH.relative_to(ROOT)),
            "packCount": len(pack_dirs),
            "composeModes": COMPOSE_MODES,
        },
        "packBuild": summarize_pack_builds(pack_results),
        "composeModes": compose_results,
        "derived": {
            "partialAboveFullOnly": partial_above_full_only,
            "partialAboveFromContracts": partial_above_from_contracts,
            "fromContractsAboveFullOnly": from_contracts_analysis > full_analysis,
            "fromContractsReductionVsPartialRatio": round(
                (partial_analysis - from_contracts_analysis) / float(partial_analysis),
                6,
            ),
            "fromContractsExpansionVsFullOnlyRatio": round(
                from_contracts_analysis / float(full_analysis),
                6,
            ),
        },
    }

    METRICS_DIR.mkdir(exist_ok=True)
    json_path = METRICS_DIR / "compose-scale-metrics.json"
    md_path = METRICS_DIR / "compose-scale-metrics.md"
    write_json(json_path, metrics)
    md_path.write_text(render_markdown(metrics))

    print(f"Wrote metrics: {json_path}")
    print(md_path.read_text(), end="")


if __name__ == "__main__":
    main()
