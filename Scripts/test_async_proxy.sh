#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/async-test
cc -std=c99 -O0 -g -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE \
  -DGN_NODELEN_T=socklen_t -DGN_SERVLEN_T=socklen_t -DGN_FLAGS_T=int \
  -ITweak/ProxyCore/src \
  -ITweak/ProxyCore/vendor/proxychains-ng/src \
  Scripts/test_async_proxy.c \
  Tweak/ProxyCore/src/async_proxy.c \
  -o build/async-test/async_proxy_test
./build/async-test/async_proxy_test
