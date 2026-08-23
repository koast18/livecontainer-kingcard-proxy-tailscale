#!/bin/bash
# Live Tailscale smoke test on macOS using the prebuilt tailscale-ios-dylib
# macOS dylib. Requires TAILSCALE_AUTH_KEY (GitHub secret) to actually log in.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
WORK="build/tailscale-smoke"
TAG="${TAILSCALE_DYLIB_TAG:-v0.2.0}"
mkdir -p "$WORK"
curl -fL -o "$WORK/tailscale.tar.gz" \
  "https://github.com/koast18/tailscale-ios-dylib/releases/download/${TAG}/tailscale-ios-dylib-${TAG}.tar.gz"
tar -xzf "$WORK/tailscale.tar.gz" -C "$WORK"
INC="$WORK/macos"
LIBDIR="$WORK/macos"
clang -I"$INC" -L"$LIBDIR" -ltailscale \
  Scripts/tailscale_smoke_test.c -o "$WORK/tailscale_smoke"
DYLD_LIBRARY_PATH="$LIBDIR" "$WORK/tailscale_smoke"
