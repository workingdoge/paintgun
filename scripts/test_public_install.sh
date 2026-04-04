#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/test_public_install.sh [--archive-file PATH]

Build or reuse a release tarball, install it through the public installer path,
and verify that the resulting `paint` binary runs.
EOF
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

archive_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive-file)
      archive_file="${2:-}"
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

work_dir=$(mktemp -d)
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ -z "$archive_file" ]]; then
  bash ./scripts/ensure_premath_projection.sh >/dev/null
  bash ./scripts/package_release.sh --out-dir "$work_dir/artifacts" >/dev/null
  archive_file=$(find "$work_dir/artifacts" -maxdepth 1 -type f -name 'paintgun-v*.tar.gz' | head -n 1)
fi

[[ -n "$archive_file" ]] || {
  echo "failed to locate a release archive to test" >&2
  exit 1
}

install_root="$work_dir/install"
bash ./scripts/install_paint.sh --archive-file "$archive_file" --bin-dir "$install_root/bin" >/dev/null
"$install_root/bin/paint" --version >/dev/null

echo "public install smoke test passed"
