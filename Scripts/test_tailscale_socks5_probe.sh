#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/tailscale-socks5-test
cc -std=c11 -O0 -g -D_GNU_SOURCE -D_DARWIN_C_SOURCE -ITweak/Sources \
  Scripts/test_tailscale_socks5_probe.c Tweak/Sources/KPKIngCore.c \
  -lz -lpthread -o build/tailscale-socks5-test/tailscale_socks5_probe_test
./build/tailscale-socks5-test/tailscale_socks5_probe_test
