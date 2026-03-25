#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

packages=(
  premath-admissibility
  premath-composability
  premath-compose
  premath-dsl
  premath-gate
  premath-kcir-kernel
  premath-kcir
)

package_args=()
for package in "${packages[@]}"; do
  package_args+=(-p "$package")
done

mode="${1:-all}"

case "$mode" in
  all)
    cargo fmt --check
    cargo check "${package_args[@]}"
    cargo test "${package_args[@]}"
    cargo clippy "${package_args[@]}" --all-targets
    ;;
  check)
    cargo check "${package_args[@]}"
    ;;
  test)
    cargo test "${package_args[@]}"
    ;;
  clippy)
    cargo clippy "${package_args[@]}" --all-targets
    ;;
  fmt)
    cargo fmt --check
    ;;
  *)
    echo "usage: $0 [all|check|test|clippy|fmt]" >&2
    exit 2
    ;;
esac
