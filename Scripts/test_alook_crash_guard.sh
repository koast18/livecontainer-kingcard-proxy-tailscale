#!/bin/bash
# Static guards for the Alook/Speedtest high-download crash fixes.
#
# These are cheap source-level assertions that catch accidental regressions of
# the crash fixes:
#   v0.5.24:
#     - WKWebView nw_proxy_config is not released immediately on reload.
#     - KingCard forwarder caps concurrent clients.
#   v0.5.27:
#     - KingCard forwarder waits for client threads before freeing.
#   This branch:
#     - async_proxy relay threads are capped.
#     - WKWebView keeps multiple old nw_proxy_config generations.
#     - LCProxyKing does not stop/free the forwarder while holding self.lock.
set -euo pipefail
cd "$(dirname "$0")/.."

WEBKIT="Tweak/ProxyCore/src/webkit_proxy.m"
CORE="Tweak/Sources/KPKIngCore.c"
ASYNC="Tweak/ProxyCore/src/async_proxy.c"
KING="Tweak/Sources/LCProxyKing.m"

fail() {
    echo "Alook crash guard FAILED: $1" >&2
    exit 1
}

# --- nw_proxy_config lifecycle guard ---
grep -q "LC_WEBKIT_MAX_OLD_PROXY_CONFIGS" "$WEBKIT" \
    || fail "webkit_proxy.m no longer keeps multiple stale nw_proxy_config generations"
grep -q "lc_retire_current_proxy_config" "$WEBKIT" \
    || fail "webkit_proxy.m no longer defers nw_proxy_config release through a retirement queue"

# --- forwarder thread cap guard ---
grep -q "define KP_FORWARDER_MAX_CLIENTS 64" "$CORE" \
    || fail "KPKIngCore.c lost the 64-client forwarder cap"
grep -q "fw->active_clients >= KP_FORWARDER_MAX_CLIENTS" "$CORE" \
    || fail "KPKIngCore.c no longer rejects connections above the forwarder cap"

# --- forwarder stop waits for client threads before free guard ---
grep -q "client_cond" "$CORE" \
    || fail "KPKIngCore.c no longer has a client-exit condition variable"
grep -q "pthread_cond_wait(&fw->client_cond, &fw->client_lock)" "$CORE" \
    || fail "KPKIngCore.c no longer waits for active clients in kp_forwarder_stop"
grep -q "while (fw->active_clients > 0)" "$CORE" \
    || fail "KPKIngCore.c no longer waits on active_clients before freeing"

# --- async_proxy relay thread cap guard ---
grep -q "define LC_ASYNC_MAX_RELAY_THREADS 64" "$ASYNC" \
    || fail "async_proxy.c lost the relay thread cap"
grep -q "lc_async_relay_try_acquire" "$ASYNC" \
    || fail "async_proxy.c no longer bounds relay thread creation"

# --- LCProxyKing deadlock guard ---
grep -q "不要在持有 self.lock 时 stop/free" "$KING" \
    || fail "LCProxyKing.m lost the no-stop-under-lock comment/guard marker"

echo "Alook crash guard static checks OK"
