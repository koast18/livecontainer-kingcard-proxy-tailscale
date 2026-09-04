#!/bin/bash
# Local test runner for the async connect / proxychains dylib work.
#
# Usage:
#   bash Scripts/run_all_tests.sh
#
# This mirrors the GitHub Actions CI steps that can run on a local macOS
# machine. Linux/macOS both support the async relay test; the iOS dylib build
# step only works on macOS with Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$PWD"
FAILED=0

run_step() {
    local name="$1"
    shift
    echo "=== $name ==="
    if ! "$@"; then
        echo "!!! $name FAILED"
        FAILED=1
    else
        echo "--- $name passed ---"
    fi
}

run_step "King cache/refresh static checks" bash Scripts/test_king_cache_logic.sh
run_step "Foreground reload/shared-app forwarder static checks" bash Scripts/test_foreground_reload_logic.sh
run_step "Tailscale crash/isolation static checks" python3 Scripts/test_tailscale_safety.py
run_step "Tailscale SOCKS5 probe tests" bash Scripts/test_tailscale_socks5_probe.sh
run_step "King forwarder lifecycle tests" bash Scripts/test_king_forwarder_lifecycle.sh
run_step "Proxy override unit tests" bash Scripts/test_proxy_override.sh
run_step "Async proxy relay tests" bash Scripts/test_async_proxy.sh
run_step "Queen crypto self-test" bash Scripts/test_queen_crypto.sh
run_step "Queen WUP binary comparison" bash Scripts/test_queen_wup_compare.sh

if command -v xcrun >/dev/null 2>&1; then
    run_step "iOS dylib build (compile/link check)" bash Scripts/build_ios.sh
else
    echo "=== iOS dylib build skipped (requires macOS/Xcode) ==="
fi

if [ "$FAILED" -ne 0 ]; then
    echo
    echo "One or more test steps failed."
    exit 1
fi

echo
echo "All runnable tests passed."
