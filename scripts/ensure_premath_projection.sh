#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_path="$repo_root/premath"
allow_snapshot="${PREMATH_ALLOW_SNAPSHOT:-0}"
replace_invalid="${PREMATH_REPLACE_INVALID:-0}"

looks_like_premath_workspace() {
  local candidate="$1"
  [ -f "$candidate/Cargo.toml" ] && [ -d "$candidate/crates/premath-kcir" ]
}

if [ -e "$target_path" ]; then
  if looks_like_premath_workspace "$target_path"; then
    exit 0
  fi

  if [ "$replace_invalid" != "1" ]; then
    echo "refusing to treat invalid Premath target as valid: $target_path" >&2
    exit 1
  fi

  rm -rf "$target_path"
fi

if bash "$repo_root/scripts/link_premath_checkout.sh"; then
  exit 0
fi

if [ "$allow_snapshot" = "1" ]; then
  bash "$repo_root/scripts/materialize_premath_snapshot.sh"
  exit 0
fi

echo "failed to materialize a Premath projection at $target_path" >&2
exit 1
