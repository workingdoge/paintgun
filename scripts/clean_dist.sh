#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--dry-run]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIST_DIRS=()
while IFS= read -r rel; do
  DIST_DIRS+=("$rel")
done < <(find . -mindepth 1 -maxdepth 1 -type d -name 'dist*' | LC_ALL=C sort)

if [[ "${#DIST_DIRS[@]}" -eq 0 ]]; then
  echo "No dist* directories found."
  exit 0
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Would remove:"
else
  echo "Removing:"
fi

for rel in "${DIST_DIRS[@]}"; do
  name="${rel#./}"
  if [[ "$name" != dist* ]]; then
    echo "Skipping unexpected path: $name" >&2
    continue
  fi
  echo "  $name"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    rm -rf -- "$name"
  fi
done
