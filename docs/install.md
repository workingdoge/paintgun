# Install Paint

This document is consumer-facing.

If you are trying Paint as a tool user, the supported install surface is:

- a prebuilt GitHub release tarball
- or the `install_paint.sh` helper that downloads the right tarball for your platform

Source builds from a repo checkout remain available for contributors and maintainers, but they are not the primary public install path because they depend on the extracted Premath code home and other repo-local setup.

## Quick install

Download the installer, inspect it if you want, then run it:

```bash
curl -fsSL https://raw.githubusercontent.com/workingdoge/paintgun/main/scripts/install_paint.sh -o install_paint.sh
bash install_paint.sh
paint --version
```

By default, the installer resolves the latest GitHub release and installs `paint` into `~/.local/bin`.

If you want to pin the installer script itself to a release tag, replace `main` in the URL above with `vX.Y.Z`.

## Install a specific version

```bash
bash install_paint.sh --version 0.1.0
paint --version
```

## Manual release-tarball install

If you prefer not to use the helper, download the matching release asset from GitHub Releases and install it directly:

```bash
curl -fsSLO https://github.com/workingdoge/paintgun/releases/download/v0.1.0/paintgun-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf paintgun-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 paintgun-v0.1.0-x86_64-unknown-linux-gnu/paint ~/.local/bin/paint
paint --version
```

Replace the target triple in the archive name with the one that matches your system. The installer script handles that detection automatically for the supported macOS and Linux targets.

## Install location

The installer defaults to:

- `~/.local/bin` on Unix-like systems

Override it with:

```bash
bash install_paint.sh --bin-dir "$HOME/bin"
```

If the chosen directory is not already on `PATH`, add it before starting a new shell session.

## What the public install path does not require

The supported consumer install path does not require:

- Cargo
- a local clone of this repo
- `./premath`
- `jj`
- `bd`

Those are contributor or maintainer concerns, not consumer prerequisites.

## Contributor source builds

If you are working from a repo checkout and want to build from source, use the contributor path in [`docs/releasing.md`](releasing.md). That path still expects a repo-local `./premath` projection.

After installation, the shortest end-to-end walkthrough is [`docs/quickstart.md`](quickstart.md).
