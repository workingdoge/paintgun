#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
premath_root="${PREMATH_REPO_ROOT:-$repo_root/../premath}"
cd "$premath_root"

mode="${1:-all}"

case "$mode" in
  all)
    cargo fmt --check
    cargo check --workspace
    cargo test --workspace
    cargo clippy --workspace --all-targets
    ;;
  check)
    cargo check --workspace
    ;;
  test)
    cargo test --workspace
    ;;
  clippy)
    cargo clippy --workspace --all-targets
    ;;
  fmt)
    cargo fmt --check
    ;;
  *)
    echo "usage: $0 [all|check|test|clippy|fmt]" >&2
    exit 2
    ;;
esac
