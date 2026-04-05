#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("spec_watch.py")
MODULE_SPEC = importlib.util.spec_from_file_location("paintgun_spec_watch", MODULE_PATH)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
spec_watch = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(spec_watch)


class DiscoverVersionsForSourceTest(unittest.TestCase):
    def test_extracts_stable_versions_from_technical_reports_page(self) -> None:
        text = (
            "Technical Reports Name Status Published "
            "2025.10 Stable 2025-10-28 "
            "2026.02 Stable 2026-02-10 "
            "Third Editors' Draft Draft 2025-07-21"
        )

        versions = spec_watch.discover_versions_for_source(
            "designtokens-technical-reports",
            text,
        )

        self.assertEqual(versions, ["2025.10", "2026.02"])

    def test_extracts_stable_versions_from_w3c_final_reports_page(self) -> None:
        text = (
            "Final reports "
            "2025-10-28 Design Tokens Format Module 2025.10 "
            "2025-10-28 Design Tokens Color Module 2025.10 "
            "2025-10-28 Design Tokens Resolver Module 2025.10 "
            "2026-02-10 Design Tokens Format Module 2026.02"
        )

        versions = spec_watch.discover_versions_for_source(
            "w3c-design-tokens-community",
            text,
        )

        self.assertEqual(versions, ["2025.10", "2026.02"])


class DiscoveryCheckTest(unittest.TestCase):
    def test_detects_newer_stable_version(self) -> None:
        config = {
            "version": 1,
            "expectedLatestStableVersion": "2025.10",
            "sources": [
                {
                    "id": "designtokens-technical-reports",
                    "kind": "designtokens-technical-reports",
                    "url": "https://example.invalid/technical-reports/",
                },
                {
                    "id": "w3c-design-tokens-community",
                    "kind": "w3c-design-tokens-community",
                    "url": "https://example.invalid/community/",
                },
            ],
        }

        responses = [
            {
                "id": "designtokens-technical-reports",
                "kind": "designtokens-technical-reports",
                "url": "https://example.invalid/technical-reports/",
                "status": 200,
                "resolvedUrl": "https://example.invalid/technical-reports/",
                "contentType": "text/html",
                "size": 0,
                "sha256": "x",
                "body": b"2025.10 Stable 2025-10-28 2026.02 Stable 2026-02-10",
            },
            {
                "id": "w3c-design-tokens-community",
                "kind": "w3c-design-tokens-community",
                "url": "https://example.invalid/community/",
                "status": 200,
                "resolvedUrl": "https://example.invalid/community/",
                "contentType": "text/html",
                "size": 0,
                "sha256": "y",
                "body": (
                    b"Design Tokens Format Module 2025.10 "
                    b"Design Tokens Color Module 2025.10 "
                    b"Design Tokens Resolver Module 2026.02"
                ),
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "discovery.json"
            artifact_dir = temp_path / "artifacts"
            spec_watch.write_json(config_path, config)
            args = types.SimpleNamespace(
                discovery=str(config_path),
                timeout=1.0,
                artifact_dir=str(artifact_dir),
            )

            with mock.patch.object(spec_watch, "fetch_target", side_effect=responses):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = spec_watch.command_discover_check(args)

            self.assertEqual(rc, 1)
            report = spec_watch.load_json(artifact_dir / "report.json")
            self.assertEqual(report["observedLatestStableVersion"], "2026.02")
            self.assertEqual(report["newVersionCount"], 2)


class ResolveSupportVersionTest(unittest.TestCase):
    def test_resolves_mirror_browser_support(self) -> None:
        support = {
            "chrome": {"version_added": "99"},
            "edge": "mirror",
        }

        self.assertEqual(spec_watch.resolve_support_version(support, "edge"), "99")

    def test_prefers_full_support_over_partial_entries(self) -> None:
        support = {
            "safari": [
                {
                    "version_added": "10.1",
                    "version_removed": "15",
                    "partial_implementation": True,
                },
                {
                    "version_added": "15",
                },
            ]
        }

        self.assertEqual(spec_watch.resolve_support_version(support, "safari"), "15")


class WebCompatCheckTest(unittest.TestCase):
    def test_detects_documented_floor_mismatch(self) -> None:
        config = {
            "version": 1,
            "checks": [
                {
                    "id": "css-at-layer-floor",
                    "kind": "mdn-browser-compat",
                    "url": "https://example.invalid/layer.json",
                    "description": "CSS cascade layers",
                    "featurePath": ["css", "at-rules", "layer", "__compat", "support"],
                    "expected": {
                        "chrome": "99",
                        "edge": "99",
                        "firefox": "98",
                        "safari": "15.4",
                    },
                }
            ],
        }
        response = {
            "id": "css-at-layer-floor",
            "kind": "mdn-browser-compat",
            "url": "https://example.invalid/layer.json",
            "status": 200,
            "resolvedUrl": "https://example.invalid/layer.json",
            "contentType": "application/json",
            "size": 0,
            "sha256": "abc",
            "body": json_bytes(
                {
                    "css": {
                        "at-rules": {
                            "layer": {
                                "__compat": {
                                    "support": {
                                        "chrome": {"version_added": "99"},
                                        "edge": "mirror",
                                        "firefox": {"version_added": "97"},
                                        "safari": {"version_added": "15.4"},
                                    }
                                }
                            }
                        }
                    }
                }
            ),
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "web-compat.json"
            artifact_dir = temp_path / "artifacts"
            spec_watch.write_json(config_path, config)
            args = types.SimpleNamespace(
                compat=str(config_path),
                timeout=1.0,
                artifact_dir=str(artifact_dir),
            )

            with mock.patch.object(spec_watch, "fetch_target", return_value=response):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = spec_watch.command_web_compat_check(args)

            self.assertEqual(rc, 1)
            report = spec_watch.load_json(artifact_dir / "report.json")
            self.assertEqual(report["mismatchCount"], 1)
            self.assertEqual(report["results"][0]["result"], "drift")
            self.assertEqual(report["mismatches"][0]["browsers"][0]["browser"], "firefox")

    def test_passes_when_documented_floors_match(self) -> None:
        config = {
            "version": 1,
            "checks": [
                {
                    "id": "css-oklch-floor",
                    "kind": "mdn-browser-compat",
                    "url": "https://example.invalid/color.json",
                    "description": "CSS oklch() colors",
                    "featurePath": ["css", "types", "color", "oklch", "__compat", "support"],
                    "expected": {
                        "chrome": "111",
                        "edge": "111",
                        "firefox": "113",
                        "safari": "15.4",
                    },
                }
            ],
        }
        response = {
            "id": "css-oklch-floor",
            "kind": "mdn-browser-compat",
            "url": "https://example.invalid/color.json",
            "status": 200,
            "resolvedUrl": "https://example.invalid/color.json",
            "contentType": "application/json",
            "size": 0,
            "sha256": "def",
            "body": json_bytes(
                {
                    "css": {
                        "types": {
                            "color": {
                                "oklch": {
                                    "__compat": {
                                        "support": {
                                            "chrome": {"version_added": "111"},
                                            "edge": "mirror",
                                            "firefox": {"version_added": "113"},
                                            "safari": {"version_added": "15.4"},
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            ),
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "web-compat.json"
            artifact_dir = temp_path / "artifacts"
            spec_watch.write_json(config_path, config)
            args = types.SimpleNamespace(
                compat=str(config_path),
                timeout=1.0,
                artifact_dir=str(artifact_dir),
            )

            with mock.patch.object(spec_watch, "fetch_target", return_value=response):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = spec_watch.command_web_compat_check(args)

            self.assertEqual(rc, 0)
            report = spec_watch.load_json(artifact_dir / "report.json")
            self.assertTrue(report["ok"])
            self.assertEqual(report["mismatchCount"], 0)


def json_bytes(payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
