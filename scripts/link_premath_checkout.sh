#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_path="$repo_root/premath"

canonical_root="$repo_root"
if [ "$(basename "$(dirname "$repo_root")")" = ".jj-workspaces" ]; then
  canonical_root="$(cd "$repo_root/../.." && pwd)"
fi

looks_like_premath_workspace() {
  local candidate="$1"
  [ -f "$candidate/Cargo.toml" ] && [ -d "$candidate/crates/premath-kcir" ]
}

resolve_default_source() {
  local candidate

  if [ -L "$canonical_root/premath" ]; then
    candidate="$(cd "$(dirname "$canonical_root/premath")" && cd "$(readlink "$canonical_root/premath")" && pwd)"
    if looks_like_premath_workspace "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  elif [ -d "$canonical_root/premath" ] && looks_like_premath_workspace "$canonical_root/premath"; then
    printf '%s\n' "$canonical_root/premath"
    return 0
  fi

  for candidate in "$canonical_root/../premath" "$repo_root/../premath"; do
    if [ -d "$candidate" ] && looks_like_premath_workspace "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

source_root="${1:-}"
if [ -z "$source_root" ]; then
  if ! source_root="$(resolve_default_source)"; then
    cat >&2 <<EOF
could not infer a Premath checkout for $repo_root

tried:
- canonical repo projection at $canonical_root/premath
- sibling checkout at $canonical_root/../premath
- sibling checkout at $repo_root/../premath

pass an explicit source path, for example:
  ./scripts/link_premath_checkout.sh /Users/arj/dev/fish/tools/premath
EOF
    exit 1
  fi
fi

if [ ! -d "$source_root" ]; then
  echo "source Premath repo not found at $source_root" >&2
  exit 1
fi

source_root="$(cd "$source_root" && pwd)"

if ! looks_like_premath_workspace "$source_root"; then
  echo "source path does not look like the extracted Premath workspace: $source_root" >&2
  exit 1
fi

if [ -e "$target_path" ] && [ ! -L "$target_path" ]; then
  echo "refusing to overwrite non-symlink target at $target_path" >&2
  exit 1
fi

ln -sfn "$source_root" "$target_path"
echo "linked $target_path -> $source_root"
