#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_path="$repo_root/premath"

if [ -e "$target_path" ]; then
  if [ -L "$target_path" ] || [ -d "$target_path" ]; then
    exit 0
  fi

  echo "refusing to treat non-directory Premath target as valid: $target_path" >&2
  exit 1
fi

"$repo_root/scripts/link_premath_checkout.sh"
