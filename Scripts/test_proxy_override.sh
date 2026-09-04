#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/proxy-override-test
if command -v cc >/dev/null 2>&1; then
    CC=cc
elif python -m ziglang cc --version >/dev/null 2>&1; then
    CC="python -m ziglang cc"
else
    echo "no C compiler found (need cc or ziglang)" >&2
    exit 1
fi

$CC -std=c99 -O0 -g -D_POSIX_C_SOURCE=200809L \
  -DGN_NODELEN_T=socklen_t -DGN_SERVLEN_T=socklen_t -DGN_FLAGS_T=int \
  -ITweak/ProxyCore/src \
  -ITweak/ProxyCore/vendor/proxychains-ng/src \
  Scripts/test_proxy_override.c \
  Tweak/ProxyCore/src/proxy_override.c \
  -o build/proxy-override-test/proxy_override_test
./build/proxy-override-test/proxy_override_test
