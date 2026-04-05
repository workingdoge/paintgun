#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
snapshot_root="$repo_root/ci/premath-snapshot"
target_path="${1:-$repo_root/premath}"

looks_like_premath_workspace() {
  local candidate="$1"
  [ -f "$candidate/Cargo.toml" ] && [ -d "$candidate/crates/premath-kcir" ]
}

if ! looks_like_premath_workspace "$snapshot_root"; then
  echo "repo-local Premath CI snapshot is missing or invalid: $snapshot_root" >&2
  exit 1
fi

rm -rf "$target_path"
mkdir -p "$(dirname "$target_path")"
cp -Rf "$snapshot_root" "$target_path"

if ! looks_like_premath_workspace "$target_path"; then
  echo "failed to materialize Premath snapshot into $target_path" >&2
  exit 1
fi

echo "materialized $target_path from repo-local CI snapshot"
