#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
repo_root=$(cd "$example_root/../.." && pwd)
fixture_root="$example_root/fixtures/read-only-demo"
out_dir="$fixture_root/dist"

cd "$repo_root"
"$repo_root/scripts/ensure_premath_projection.sh" >/dev/null
rm -rf "$out_dir"
cargo run --quiet -- build \
  "$fixture_root/paint.resolver.json" \
  --out "$out_dir" \
  --target web-tokens-ts \
  --format json >/dev/null

printf 'refreshed %s\n' "$out_dir"
