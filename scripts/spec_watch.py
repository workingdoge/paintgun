#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request


USER_AGENT = "paintgun-spec-watch/1"
DEFAULT_TIMEOUT = 20.0
LOCK_VERSION = 1
DISCOVERY_VERSION = 1
WEB_COMPAT_VERSION = 1
VERSION_RE = re.compile(r"^\d{4}\.\d{2}$")
NUMERIC_VERSION_RE = re.compile(r"^\s*[^\d]*?(\d+(?:\.\d+)*)")

MDN_BROWSER_MIRRORS = {
    "chrome_android": "chrome",
    "edge": "chrome",
    "firefox_android": "firefox",
    "safari_ios": "safari",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh or check pinned Design Tokens upstream spec/schema digests."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("refresh", "check"):
        sub = subparsers.add_parser(command)
        sub.add_argument(
            "--targets",
            default="spec-watch/targets.json",
            help="Path to watched target definitions.",
        )
        sub.add_argument(
            "--lock",
            default="spec-watch/lock.json",
            help="Path to pinned upstream digests.",
        )
        sub.add_argument(
            "--timeout",
            type=float,
            default=DEFAULT_TIMEOUT,
            help="Per-request timeout in seconds.",
        )
        sub.add_argument(
            "--artifact-dir",
            default=None,
            help="Optional directory for reports and fetched payloads.",
        )

    discover = subparsers.add_parser(
        "discover-check",
        help="Check trusted upstream index pages for newer stable DTCG releases.",
    )
    discover.add_argument(
        "--discovery",
        default="spec-watch/discovery.json",
        help="Path to watched DTCG release discovery sources.",
    )
    discover.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout in seconds.",
    )
    discover.add_argument(
        "--artifact-dir",
        default=None,
        help="Optional directory for reports and fetched payloads.",
    )

    compat = subparsers.add_parser(
        "web-compat-check",
        help="Check documented web compatibility floors against trusted external browser data.",
    )
    compat.add_argument(
        "--compat",
        default="spec-watch/web-compat.json",
        help="Path to watched web compatibility definitions.",
    )
    compat.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout in seconds.",
    )
    compat.add_argument(
        "--artifact-dir",
        default=None,
        help="Optional directory for reports and fetched payloads.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def load_targets(path: Path) -> list[dict]:
    payload = load_json(path)
    if payload.get("version") != LOCK_VERSION:
        raise SystemExit(f"{path} has unsupported version {payload.get('version')!r}")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SystemExit(f"{path} must contain a non-empty targets list")

    seen_ids: set[str] = set()
    normalized: list[dict] = []
    for raw in targets:
        if not isinstance(raw, dict):
            raise SystemExit(f"{path} contains a non-object target entry")
        target_id = str(raw.get("id", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        url = str(raw.get("url", "")).strip()
        if not target_id or not kind or not url:
            raise SystemExit(f"{path} contains an incomplete target entry: {raw!r}")
        if target_id in seen_ids:
            raise SystemExit(f"{path} contains duplicate target id {target_id!r}")
        seen_ids.add(target_id)
        normalized.append({"id": target_id, "kind": kind, "url": url})
    return normalized


def load_lock(path: Path) -> dict[str, dict]:
    payload = load_json(path)
    if payload.get("version") != LOCK_VERSION:
        raise SystemExit(f"{path} has unsupported version {payload.get('version')!r}")
    entries = payload.get("targets")
    if not isinstance(entries, list):
        raise SystemExit(f"{path} must contain a targets list")
    by_id: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit(f"{path} contains a non-object lock entry")
        target_id = str(entry.get("id", "")).strip()
        if not target_id:
            raise SystemExit(f"{path} contains a lock entry without an id")
        by_id[target_id] = entry
    return by_id


def parse_version(value: object, field_name: str) -> str:
    version = str(value or "").strip()
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"{field_name} must be a YYYY.MM version string, got {value!r}")
    return version


def version_key(version: str) -> tuple[int, int]:
    year, month = version.split(".", 1)
    return (int(year), int(month))


def load_discovery(path: Path) -> dict:
    payload = load_json(path)
    if payload.get("version") != DISCOVERY_VERSION:
        raise SystemExit(f"{path} has unsupported version {payload.get('version')!r}")

    expected_latest = parse_version(
        payload.get("expectedLatestStableVersion"),
        f"{path} expectedLatestStableVersion",
    )
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise SystemExit(f"{path} must contain a non-empty sources list")

    seen_ids: set[str] = set()
    normalized: list[dict] = []
    for raw in sources:
        if not isinstance(raw, dict):
            raise SystemExit(f"{path} contains a non-object source entry")
        source_id = str(raw.get("id", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        url = str(raw.get("url", "")).strip()
        if not source_id or not kind or not url:
            raise SystemExit(f"{path} contains an incomplete source entry: {raw!r}")
        if source_id in seen_ids:
            raise SystemExit(f"{path} contains duplicate source id {source_id!r}")
        seen_ids.add(source_id)
        normalized.append({"id": source_id, "kind": kind, "url": url})

    return {
        "expectedLatestStableVersion": expected_latest,
        "sources": normalized,
    }


def browser_version_key(version: str) -> tuple[int, ...]:
    match = NUMERIC_VERSION_RE.match(str(version))
    if match is None:
        raise ValueError(f"unsupported browser version {version!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def parse_expected_browser_version(value: object, field_name: str) -> str:
    version = str(value or "").strip()
    if not version:
        raise SystemExit(f"{field_name} must be a non-empty browser version string")
    try:
        browser_version_key(version)
    except ValueError as exc:
        raise SystemExit(f"{field_name} must be a numeric browser version, got {value!r}") from exc
    return version


def load_web_compat(path: Path) -> dict:
    payload = load_json(path)
    if payload.get("version") != WEB_COMPAT_VERSION:
        raise SystemExit(f"{path} has unsupported version {payload.get('version')!r}")

    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        raise SystemExit(f"{path} must contain a non-empty checks list")

    seen_ids: set[str] = set()
    normalized: list[dict] = []
    for raw in checks:
        if not isinstance(raw, dict):
            raise SystemExit(f"{path} contains a non-object check entry")

        check_id = str(raw.get("id", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        url = str(raw.get("url", "")).strip()
        description = str(raw.get("description", "")).strip()
        feature_path = raw.get("featurePath")
        expected = raw.get("expected")

        if not check_id or not kind or not url or not description:
            raise SystemExit(f"{path} contains an incomplete check entry: {raw!r}")
        if check_id in seen_ids:
            raise SystemExit(f"{path} contains duplicate check id {check_id!r}")
        seen_ids.add(check_id)

        if kind != "mdn-browser-compat":
            raise SystemExit(f"{path} contains unsupported check kind {kind!r}")

        if not isinstance(feature_path, list) or not feature_path or not all(
            isinstance(part, str) and part.strip() for part in feature_path
        ):
            raise SystemExit(f"{path} check {check_id!r} must define a non-empty featurePath list")

        if not isinstance(expected, dict) or not expected:
            raise SystemExit(f"{path} check {check_id!r} must define a non-empty expected map")

        normalized_expected: dict[str, str] = {}
        for browser, version in expected.items():
            browser_id = str(browser).strip()
            if not browser_id:
                raise SystemExit(f"{path} check {check_id!r} contains an empty browser id")
            normalized_expected[browser_id] = parse_expected_browser_version(
                version,
                f"{path} check {check_id!r} expected {browser_id}",
            )

        normalized.append(
            {
                "id": check_id,
                "kind": kind,
                "url": url,
                "description": description,
                "featurePath": [part.strip() for part in feature_path],
                "expected": normalized_expected,
            }
        )

    return {"checks": normalized}


def fetch_target(target: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        target["url"],
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return {
                "id": target["id"],
                "kind": target["kind"],
                "url": target["url"],
                "status": int(getattr(response, "status", 200)),
                "resolvedUrl": response.geturl(),
                "contentType": response.headers.get_content_type(),
                "size": len(body),
                "sha256": sha256_hex(body),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        return {
            "id": target["id"],
            "kind": target["kind"],
            "url": target["url"],
            "error": f"HTTP {exc.code}: {exc.reason}",
        }
    except urllib.error.URLError as exc:
        return {
            "id": target["id"],
            "kind": target["kind"],
            "url": target["url"],
            "error": str(exc.reason),
        }


def html_to_text(body: bytes) -> str:
    html = body.decode("utf-8", errors="replace")
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def discover_versions_for_source(kind: str, text: str) -> list[str]:
    if kind == "designtokens-technical-reports":
        matches = re.findall(
            r"\b(\d{4}\.\d{2})\b\s+Stable\s+\d{4}-\d{2}-\d{2}\b",
            text,
            flags=re.IGNORECASE,
        )
    elif kind == "w3c-design-tokens-community":
        matches = re.findall(
            r"Design Tokens (?:Format|Color|Resolver) Module (\d{4}\.\d{2})\b",
            text,
            flags=re.IGNORECASE,
        )
    else:
        raise ValueError(f"unsupported discovery source kind {kind!r}")

    versions = sorted({match for match in matches if VERSION_RE.fullmatch(match)}, key=version_key)
    if not versions:
        raise ValueError(f"no stable DTCG versions found for source kind {kind!r}")
    return versions


def extract_feature_value(payload: object, feature_path: list[str]) -> object:
    current = payload
    traversed: list[str] = []
    for segment in feature_path:
        traversed.append(segment)
        if not isinstance(current, dict) or segment not in current:
            joined = ".".join(traversed)
            raise ValueError(f"feature path missing segment {joined!r}")
        current = current[segment]
    return current


def is_full_support_statement(statement: dict) -> bool:
    return not any(
        statement.get(field)
        for field in ("partial_implementation", "flags", "alternative_name", "prefix")
    )


def select_support_version(statements: list[dict]) -> str | None:
    full_versions: list[str] = []
    fallback_versions: list[str] = []

    for statement in statements:
        if statement.get("version_removed"):
            continue

        version_added = statement.get("version_added")
        if version_added in (None, False):
            continue

        version = str(version_added).strip()
        try:
            browser_version_key(version)
        except ValueError:
            continue

        if is_full_support_statement(statement):
            full_versions.append(version)
        else:
            fallback_versions.append(version)

    versions = full_versions or fallback_versions
    if not versions:
        return None
    return min(versions, key=browser_version_key)


def resolve_support_version(
    support_map: dict,
    browser: str,
    seen: set[str] | None = None,
) -> str | None:
    if seen is None:
        seen = set()
    if browser in seen:
        raise ValueError(f"cyclic mirror resolution for browser {browser!r}")
    seen = seen | {browser}

    if browser not in support_map:
        raise ValueError(f"support map is missing browser {browser!r}")

    entry = support_map[browser]
    if entry == "mirror":
        source_browser = MDN_BROWSER_MIRRORS.get(browser)
        if source_browser is None:
            raise ValueError(f"unsupported mirror browser {browser!r}")
        return resolve_support_version(support_map, source_browser, seen)
    if entry is False or entry is None:
        return None
    if isinstance(entry, str):
        version = entry.strip()
        try:
            browser_version_key(version)
        except ValueError as exc:
            raise ValueError(f"unsupported support version {version!r} for {browser!r}") from exc
        return version
    if isinstance(entry, dict):
        return select_support_version([entry])
    if isinstance(entry, list):
        statements = [statement for statement in entry if isinstance(statement, dict)]
        return select_support_version(statements)
    raise ValueError(f"unsupported support entry for {browser!r}: {entry!r}")


def to_lock_entry(observed: dict) -> dict:
    return {
        "id": observed["id"],
        "kind": observed["kind"],
        "url": observed["url"],
        "status": observed["status"],
        "resolvedUrl": observed["resolvedUrl"],
        "contentType": observed["contentType"],
        "size": observed["size"],
        "sha256": observed["sha256"],
    }


def guess_extension(content_type: str) -> str:
    if content_type == "application/json":
        return ".json"
    if content_type == "text/html":
        return ".html"
    guessed = mimetypes.guess_extension(content_type.split(";", 1)[0].strip())
    return guessed or ".bin"


def write_payload(artifact_dir: Path, observed: dict) -> None:
    payload_dir = artifact_dir / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    extension = guess_extension(observed.get("contentType", "application/octet-stream"))
    path = payload_dir / f"{observed['id']}{extension}"
    path.write_bytes(observed["body"])


def build_summary(report: dict) -> str:
    lines = [
        "# Spec Watch",
        "",
        f"- Checked: {report['checked']}",
        f"- Drift: {report['driftCount']}",
        f"- Errors: {report['errorCount']}",
        "",
        "| Target | Result | Notes |",
        "| --- | --- | --- |",
    ]

    for row in report["results"]:
        note = row["note"].replace("\n", "<br>")
        lines.append(f"| `{row['id']}` | {row['result']} | {note} |")

    lines.extend(
        [
            "",
            "Triage:",
            "1. Inspect `spec-watch-artifacts/report.json` and any uploaded payloads.",
            "2. Decide whether Paintgun code, tests, docs, or pinned expectations need updates.",
            "3. Open or update a `bd` follow-up issue in the canonical repo root.",
            "4. If the upstream change is accepted, run `python3 scripts/spec_watch.py refresh` and commit the updated lock file.",
            "",
        ]
    )
    return "\n".join(lines)


def build_discovery_summary(report: dict) -> str:
    lines = [
        "# Spec Release Discovery",
        "",
        f"- Expected latest stable version: {report['expectedLatestStableVersion']}",
        f"- Observed latest stable version: {report.get('observedLatestStableVersion') or 'none'}",
        f"- Sources checked: {report['checked']}",
        f"- New versions: {report['newVersionCount']}",
        f"- Errors: {report['errorCount']}",
        f"- Mismatches: {report['mismatchCount']}",
        "",
        "| Source | Latest | Result | Notes |",
        "| --- | --- | --- | --- |",
    ]

    for row in report["results"]:
        latest = row.get("latestStableVersion") or "n/a"
        note = row["note"].replace("\n", "<br>")
        lines.append(f"| `{row['id']}` | `{latest}` | {row['result']} | {note} |")

    lines.extend(
        [
            "",
            "Triage:",
            "1. Inspect `report.json` and any uploaded payload copies to confirm which trusted source changed.",
            "2. If a newer stable version appears, open or update a `bd` review/adoption issue in the canonical repo root.",
            "3. Review the new release against Paint's current support boundary before changing runtime behavior.",
            "4. If Paint adopts the new stable version, update `spec-watch/discovery.json` and any linked docs in the same change.",
            "",
        ]
    )
    return "\n".join(lines)


def build_web_compat_summary(report: dict) -> str:
    lines = [
        "# Web Compatibility Watch",
        "",
        f"- Checked: {report['checked']}",
        f"- Mismatches: {report['mismatchCount']}",
        f"- Errors: {report['errorCount']}",
        "",
        "| Check | Result | Notes |",
        "| --- | --- | --- |",
    ]

    for row in report["results"]:
        note = row["note"].replace("\n", "<br>")
        lines.append(f"| `{row['id']}` | {row['result']} | {note} |")

    lines.extend(
        [
            "",
            "Triage:",
            "1. Inspect `report.json` and any uploaded payload copies to confirm which documented baseline drifted.",
            "2. Decide whether Paint's documented web compatibility floor or the emitted web CSS contract changed.",
            "3. Open or update a `bd` follow-up issue in the canonical repo root for any accepted contract change.",
            "4. If the documented floor is intentionally changing, update `docs/backend_compatibility.md`, `spec-watch/web-compat.json`, and any linked release docs in the same change.",
            "",
        ]
    )
    return "\n".join(lines)


def command_refresh(args: argparse.Namespace) -> int:
    targets = load_targets(Path(args.targets))
    observed_entries: list[dict] = []
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else None
    for target in targets:
        observed = fetch_target(target, args.timeout)
        if "error" in observed:
            raise SystemExit(f"failed to fetch {target['id']} ({target['url']}): {observed['error']}")
        observed_entries.append(to_lock_entry(observed))
        if artifact_dir is not None:
            write_payload(artifact_dir, observed)

    payload = {"version": LOCK_VERSION, "targets": observed_entries}
    write_json(Path(args.lock), payload)
    print(f"refreshed {len(observed_entries)} spec-watch targets into {args.lock}")
    return 0


def command_check(args: argparse.Namespace) -> int:
    targets = load_targets(Path(args.targets))
    expected_by_id = load_lock(Path(args.lock))
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else None
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    drift: list[dict] = []
    errors: list[dict] = []

    expected_ids = {target["id"] for target in targets}
    lock_ids = set(expected_by_id)
    missing_from_lock = sorted(expected_ids - lock_ids)
    extra_in_lock = sorted(lock_ids - expected_ids)

    for target_id in missing_from_lock:
        errors.append(
            {
                "id": target_id,
                "url": "",
                "error": "target is missing from spec-watch/lock.json",
            }
        )
        results.append(
            {
                "id": target_id,
                "result": "error",
                "note": "target is missing from spec-watch/lock.json",
            }
        )

    for target_id in extra_in_lock:
        errors.append(
            {
                "id": target_id,
                "url": expected_by_id[target_id].get("url", ""),
                "error": "lock entry no longer exists in spec-watch/targets.json",
            }
        )
        results.append(
            {
                "id": target_id,
                "result": "error",
                "note": "lock entry no longer exists in spec-watch/targets.json",
            }
        )

    for target in targets:
        expected = expected_by_id.get(target["id"])
        if expected is None:
            continue

        observed = fetch_target(target, args.timeout)
        if "error" in observed:
            errors.append(
                {"id": target["id"], "url": target["url"], "error": observed["error"]}
            )
            results.append(
                {"id": target["id"], "result": "error", "note": observed["error"]}
            )
            continue

        if artifact_dir is not None:
            write_payload(artifact_dir, observed)

        changed_fields = [
            field
            for field in ("status", "resolvedUrl", "contentType", "size", "sha256")
            if observed[field] != expected.get(field)
        ]

        if changed_fields:
            drift.append(
                {
                    "id": target["id"],
                    "kind": target["kind"],
                    "url": target["url"],
                    "changedFields": changed_fields,
                    "expected": {
                        field: expected.get(field)
                        for field in ("status", "resolvedUrl", "contentType", "size", "sha256")
                    },
                    "observed": {
                        field: observed[field]
                        for field in ("status", "resolvedUrl", "contentType", "size", "sha256")
                    },
                }
            )
            results.append(
                {
                    "id": target["id"],
                    "result": "drift",
                    "note": "changed: " + ", ".join(changed_fields),
                }
            )
        else:
            results.append({"id": target["id"], "result": "ok", "note": "unchanged"})

    report = {
        "version": LOCK_VERSION,
        "ok": not drift and not errors,
        "checked": len(targets),
        "driftCount": len(drift),
        "errorCount": len(errors),
        "results": sorted(results, key=lambda item: item["id"]),
        "drift": drift,
        "errors": errors,
    }
    summary = build_summary(report)

    if artifact_dir is not None:
        write_json(artifact_dir / "report.json", report)
        (artifact_dir / "summary.md").write_text(summary, encoding="utf-8")

    print(summary)
    return 0 if report["ok"] else 1


def command_discover_check(args: argparse.Namespace) -> int:
    discovery = load_discovery(Path(args.discovery))
    expected_latest = discovery["expectedLatestStableVersion"]
    sources = discovery["sources"]
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else None
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    errors: list[dict] = []
    new_versions: list[dict] = []
    successful_results: list[dict] = []

    for source in sources:
        observed = fetch_target(source, args.timeout)
        if "error" in observed:
            errors.append({"id": source["id"], "url": source["url"], "error": observed["error"]})
            results.append(
                {
                    "id": source["id"],
                    "result": "error",
                    "latestStableVersion": None,
                    "note": observed["error"],
                }
            )
            continue

        if artifact_dir is not None:
            write_payload(artifact_dir, observed)

        try:
            text = html_to_text(observed["body"])
            versions = discover_versions_for_source(source["kind"], text)
        except ValueError as exc:
            errors.append({"id": source["id"], "url": source["url"], "error": str(exc)})
            results.append(
                {
                    "id": source["id"],
                    "result": "error",
                    "latestStableVersion": None,
                    "note": str(exc),
                }
            )
            continue

        latest_version = max(versions, key=version_key)
        result = {
            "id": source["id"],
            "kind": source["kind"],
            "url": source["url"],
            "versions": versions,
            "latestStableVersion": latest_version,
            "result": "ok",
            "note": "observed stable versions: " + ", ".join(versions),
        }
        successful_results.append(result)
        results.append(result)

        if version_key(latest_version) > version_key(expected_latest):
            new_versions.append(
                {
                    "id": source["id"],
                    "url": source["url"],
                    "expectedLatestStableVersion": expected_latest,
                    "observedLatestStableVersion": latest_version,
                    "versions": versions,
                }
            )
            result["result"] = "new-version"
            result["note"] = f"observed newer stable version {latest_version}"

    observed_latest = None
    mismatches: list[dict] = []
    observed_versions = sorted(
        {row["latestStableVersion"] for row in successful_results},
        key=version_key,
    )
    if observed_versions:
        observed_latest = observed_versions[-1]
        if len(observed_versions) > 1:
            mismatches.append(
                {
                    "latestStableVersions": observed_versions,
                    "sourceIds": [row["id"] for row in successful_results],
                }
            )

    report = {
        "version": DISCOVERY_VERSION,
        "ok": not errors and not new_versions and not mismatches,
        "checked": len(sources),
        "expectedLatestStableVersion": expected_latest,
        "observedLatestStableVersion": observed_latest,
        "newVersionCount": len(new_versions),
        "errorCount": len(errors),
        "mismatchCount": len(mismatches),
        "results": sorted(results, key=lambda item: item["id"]),
        "newVersions": new_versions,
        "errors": errors,
        "mismatches": mismatches,
    }
    summary = build_discovery_summary(report)

    if artifact_dir is not None:
        write_json(artifact_dir / "report.json", report)
        (artifact_dir / "summary.md").write_text(summary, encoding="utf-8")

    print(summary)
    return 0 if report["ok"] else 1


def command_web_compat_check(args: argparse.Namespace) -> int:
    compat = load_web_compat(Path(args.compat))
    checks = compat["checks"]
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else None
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    mismatches: list[dict] = []
    errors: list[dict] = []

    for check in checks:
        observed = fetch_target(check, args.timeout)
        if "error" in observed:
            errors.append({"id": check["id"], "url": check["url"], "error": observed["error"]})
            results.append({"id": check["id"], "result": "error", "note": observed["error"]})
            continue

        if artifact_dir is not None:
            write_payload(artifact_dir, observed)

        try:
            payload = json.loads(observed["body"].decode("utf-8"))
            support = extract_feature_value(payload, check["featurePath"])
            if not isinstance(support, dict):
                raise ValueError("feature path did not resolve to a browser support map")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append({"id": check["id"], "url": check["url"], "error": str(exc)})
            results.append({"id": check["id"], "result": "error", "note": str(exc)})
            continue

        check_mismatches: list[dict] = []
        observed_support: dict[str, str | None] = {}
        for browser, expected_version in check["expected"].items():
            try:
                observed_version = resolve_support_version(support, browser)
            except ValueError as exc:
                errors.append({"id": check["id"], "url": check["url"], "error": str(exc)})
                results.append({"id": check["id"], "result": "error", "note": str(exc)})
                check_mismatches = []
                observed_support = {}
                break

            observed_support[browser] = observed_version
            if observed_version is None:
                check_mismatches.append(
                    {
                        "browser": browser,
                        "expectedVersion": expected_version,
                        "observedVersion": None,
                    }
                )
                continue

            if browser_version_key(observed_version) != browser_version_key(expected_version):
                check_mismatches.append(
                    {
                        "browser": browser,
                        "expectedVersion": expected_version,
                        "observedVersion": observed_version,
                    }
                )

        if not observed_support and any(row["id"] == check["id"] and row["result"] == "error" for row in results):
            continue

        if check_mismatches:
            mismatches.append(
                {
                    "id": check["id"],
                    "description": check["description"],
                    "url": check["url"],
                    "featurePath": check["featurePath"],
                    "expected": check["expected"],
                    "observed": observed_support,
                    "browsers": check_mismatches,
                }
            )
            mismatch_notes = []
            for mismatch in check_mismatches:
                observed_version = mismatch["observedVersion"] or "unsupported"
                mismatch_notes.append(
                    f"{mismatch['browser']} expected {mismatch['expectedVersion']} observed {observed_version}"
                )
            results.append(
                {
                    "id": check["id"],
                    "result": "drift",
                    "note": "; ".join(mismatch_notes),
                }
            )
        else:
            notes = ", ".join(
                f"{browser} {observed_support[browser]}"
                for browser in sorted(observed_support)
            )
            results.append({"id": check["id"], "result": "ok", "note": f"matched: {notes}"})

    report = {
        "version": WEB_COMPAT_VERSION,
        "ok": not mismatches and not errors,
        "checked": len(checks),
        "mismatchCount": len(mismatches),
        "errorCount": len(errors),
        "results": sorted(results, key=lambda item: item["id"]),
        "mismatches": mismatches,
        "errors": errors,
    }
    summary = build_web_compat_summary(report)

    if artifact_dir is not None:
        write_json(artifact_dir / "report.json", report)
        (artifact_dir / "summary.md").write_text(summary, encoding="utf-8")

    print(summary)
    return 0 if report["ok"] else 1


def main() -> int:
    args = parse_args()
    if args.command == "refresh":
        return command_refresh(args)
    if args.command == "check":
        return command_check(args)
    if args.command == "discover-check":
        return command_discover_check(args)
    if args.command == "web-compat-check":
        return command_web_compat_check(args)
    raise AssertionError(f"unsupported command {args.command!r}")


if __name__ == "__main__":
    sys.exit(main())
