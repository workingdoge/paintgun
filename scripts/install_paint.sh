#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/install_paint.sh [options]

Install the public `paint` binary from a release tarball.

Options:
  --version X.Y.Z    Install a specific release version. Defaults to latest.
  --target TARGET    Override target triple detection.
  --bin-dir DIR      Install `paint` into DIR. Defaults to ~/.local/bin.
  --repo OWNER/REPO  Override the GitHub repository. Defaults to workingdoge/paintgun.
  --archive-url URL  Download an explicit tarball URL instead of resolving a release asset.
  --archive-file P   Install from a local tarball instead of downloading.
  -h, --help         Show this help text.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

download_to() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
    return
  fi
  fail "missing downloader: need curl or wget"
}

detect_target() {
  local os
  local arch
  case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux) os="unknown-linux-gnu" ;;
    *) fail "unsupported operating system: $(uname -s). Pass --target explicitly." ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture: $(uname -m). Pass --target explicitly." ;;
  esac

  printf '%s-%s\n' "$arch" "$os"
}

resolve_latest_version() {
  local repo="$1"
  local tmp_json="$2"
  local api_url="https://api.github.com/repos/${repo}/releases/latest"

  download_to "$api_url" "$tmp_json"
  local payload
  payload=$(tr -d '\n' < "$tmp_json")
  local tag
  tag=$(printf '%s' "$payload" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [[ -z "$tag" ]]; then
    fail "could not resolve the latest release tag from ${api_url}"
  fi
  printf '%s\n' "${tag#v}"
}

version="latest"
target=""
bin_dir="${HOME}/.local/bin"
repo="workingdoge/paintgun"
archive_url=""
archive_file=""

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
    --bin-dir)
      bin_dir="${2:-}"
      shift 2
      ;;
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --archive-url)
      archive_url="${2:-}"
      shift 2
      ;;
    --archive-file)
      archive_file="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [[ -n "$archive_url" && -n "$archive_file" ]]; then
  fail "--archive-url and --archive-file are mutually exclusive"
fi

if [[ -z "$target" ]]; then
  target=$(detect_target)
fi

tmp_dir=$(mktemp -d)
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

resolved_version="$version"
if [[ -z "$archive_url" && -z "$archive_file" && "$version" == "latest" ]]; then
  resolved_version=$(resolve_latest_version "$repo" "$tmp_dir/latest-release.json")
fi
resolved_version="${resolved_version#v}"

asset_name="paintgun-v${resolved_version}-${target}.tar.gz"
resolved_archive="${tmp_dir}/${asset_name}"

if [[ -n "$archive_file" ]]; then
  [[ -f "$archive_file" ]] || fail "archive file not found: $archive_file"
  cp -f "$archive_file" "$resolved_archive"
elif [[ -n "$archive_url" ]]; then
  download_to "$archive_url" "$resolved_archive"
else
  resolved_url="https://github.com/${repo}/releases/download/v${resolved_version}/${asset_name}"
  download_to "$resolved_url" "$resolved_archive" || fail "failed to download ${resolved_url}"
fi

extract_dir="${tmp_dir}/extract"
mkdir -p "$extract_dir"
tar -C "$extract_dir" -xzf "$resolved_archive"

binary_path=$(find "$extract_dir" -type f -name paint -perm -u+x | head -n 1 || true)
if [[ -z "$binary_path" ]]; then
  fail "could not find the paint binary in ${resolved_archive}"
fi

mkdir -p "$bin_dir"
if command -v install >/dev/null 2>&1; then
  install -m 0755 "$binary_path" "${bin_dir}/paint"
else
  cp -f "$binary_path" "${bin_dir}/paint"
  chmod 0755 "${bin_dir}/paint"
fi

echo "installed paint ${resolved_version} to ${bin_dir}/paint"
case ":${PATH}:" in
  *":${bin_dir}:"*) ;;
  *)
    echo "note: ${bin_dir} is not currently on PATH" >&2
    ;;
esac
