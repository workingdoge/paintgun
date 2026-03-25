#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/package_release.sh [--version X.Y.Z] [--target TARGET] [--out-dir DIR]

Build a target-specific Paint release tarball and checksum.

Defaults:
  --version  Cargo package version from the root Cargo.toml
  --target   host target reported by rustc -vV
  --out-dir  release-artifacts
EOF
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

version=""
target=""
out_dir="release-artifacts"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

manifest_version=$(
  cargo metadata --no-deps --format-version 1 |
    python3 -c 'import json,sys; data=json.load(sys.stdin); pkg=next(p for p in data["packages"] if p["name"]=="paintgun"); print(pkg["version"])'
)

if [[ -z "$version" ]]; then
  version="$manifest_version"
fi
version="${version#v}"

if [[ "$version" != "$manifest_version" ]]; then
  echo "requested version $version does not match Cargo.toml version $manifest_version" >&2
  exit 1
fi

if [[ -z "$target" ]]; then
  target=$(rustc -vV | awk '/^host: / {print $2}')
fi

artifact_base="paintgun-v${version}-${target}"
staging_dir="${out_dir}/${artifact_base}"
archive_path="${out_dir}/${artifact_base}.tar.gz"
checksum_path="${archive_path}.sha256"
binary_path="target/${target}/release/paint"

mkdir -p "$out_dir"
rm -rf "$staging_dir"
rm -f "$archive_path" "$checksum_path"

cargo build --locked --release --target "$target"

mkdir -p "$staging_dir"
cp -f "$binary_path" "$staging_dir/paint"
cp -f README.md SIGNING.md CHANGELOG.md Cargo.toml "$staging_dir/"

tar -C "$out_dir" -czf "$archive_path" "$artifact_base"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$archive_path" > "$checksum_path"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive_path" > "$checksum_path"
else
  echo "missing checksum tool: need shasum or sha256sum" >&2
  exit 1
fi

echo "wrote $archive_path"
echo "wrote $checksum_path"
