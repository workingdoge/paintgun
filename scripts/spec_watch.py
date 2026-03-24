#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
from pathlib import Path
import sys
import urllib.error
import urllib.request


USER_AGENT = "paintgun-spec-watch/1"
DEFAULT_TIMEOUT = 20.0
LOCK_VERSION = 1


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


def main() -> int:
    args = parse_args()
    if args.command == "refresh":
        return command_refresh(args)
    if args.command == "check":
        return command_check(args)
    raise AssertionError(f"unsupported command {args.command!r}")


if __name__ == "__main__":
    sys.exit(main())
