#!/usr/bin/env python3
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts" / "compose_scale_metrics.py"

spec = importlib.util.spec_from_file_location("compose_scale_metrics", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_pack_matrix_size() -> None:
    loaded = module.load_spec()
    seeds = module.pack_seeds(loaded)
    assert len(seeds) == 24
    assert seeds[0].pack_id == "atlas-core"
    assert seeds[-1].pack_id == "summit-campaign"


def test_pack_document_shape() -> None:
    loaded = module.load_spec()
    seed = module.pack_seeds(loaded)[0]
    doc = module.pack_document(seed)
    assert doc["name"] == "atlas-core"
    assert set(doc["modifiers"].keys()) == {"theme", "density", "mode", "platform"}
    assert doc["modifiers"]["theme"]["contexts"]["dark"][0]["color"]["action"]["primary"]["$type"] == "color"
    assert doc["modifiers"]["density"]["contexts"]["compact"][0]["dimension"]["radius"]["md"]["$type"] == "dimension"
    assert doc["modifiers"]["platform"]["contexts"]["web"][0]["duration"]["fast"]["$type"] == "duration"


def test_markdown_render_contains_modes() -> None:
    markdown = module.render_markdown(
        {
            "fixture": {
                "packCount": 24,
                "composeModes": ["full-only", "partial", "from-contracts"],
            },
            "packBuild": {
                "mode": "partial",
                "elapsedMs": {"total": 10, "mean": 1, "max": 2, "min": 1},
                "resolvedContexts": {"min": 108, "max": 108},
            },
            "composeModes": [
                {
                    "mode": "full-only",
                    "elapsedMs": 1,
                    "plannerTrace": {
                        "analysisIncluded": 24,
                        "universe": 108,
                        "traceBytes": 100,
                    },
                    "report": {"totalFindings": 3, "bytes": 200},
                    "witnesses": {"conflicts": 3, "bytes": 300},
                }
            ],
            "derived": {
                "partialAboveFullOnly": True,
                "partialAboveFromContracts": True,
                "fromContractsAboveFullOnly": True,
                "fromContractsReductionVsPartialRatio": 0.5,
                "fromContractsExpansionVsFullOnlyRatio": 1.5,
            },
        }
    )
    assert "Compose Scale Metrics" in markdown
    assert "full-only" in markdown
    assert "from-contracts reduction ratio" in markdown
    assert "from-contracts above full-only" in markdown


if __name__ == "__main__":
    test_pack_matrix_size()
    test_pack_document_shape()
    test_markdown_render_contains_modes()
    print("compose_scale_metrics_test.py: ok")
