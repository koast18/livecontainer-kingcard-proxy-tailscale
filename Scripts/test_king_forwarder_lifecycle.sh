#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/king-forwarder-test
cc -std=c11 -O0 -g -D_GNU_SOURCE -D_DARWIN_C_SOURCE -ITweak/Sources \
  Scripts/test_king_forwarder_lifecycle.c Tweak/Sources/KPKIngCore.c \
  -lz -lpthread -o build/king-forwarder-test/king_forwarder_lifecycle_test
./build/king-forwarder-test/king_forwarder_lifecycle_test
