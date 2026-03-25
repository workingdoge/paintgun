#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${1:-$repo_root/../premath}"
target_path="$repo_root/premath"

if [ ! -d "$source_root" ]; then
  echo "source Premath repo not found at $source_root" >&2
  exit 1
fi

if [ ! -f "$source_root/Cargo.toml" ] || [ ! -d "$source_root/crates/premath-kcir" ]; then
  echo "source path does not look like the extracted Premath workspace: $source_root" >&2
  exit 1
fi

if [ -e "$target_path" ] && [ ! -L "$target_path" ]; then
  echo "refusing to overwrite non-symlink target at $target_path" >&2
  exit 1
fi

ln -sfn "$source_root" "$target_path"
echo "linked $target_path -> $source_root"
