#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
else
    PYTHON_BIN=python
fi
"$PYTHON_BIN" - <<'PY'
from pathlib import Path
import re

king = Path('Tweak/Sources/LCProxyKing.m').read_text(encoding='utf-8')
control = Path('Tweak/Sources/LCTailscaleControl.m').read_text(encoding='utf-8')

# Preemptive refresh lead time must exist.
assert 'LCProxyKingRefreshLeadTime = 2 * 60;' in king, \
    'missing LCProxyKingRefreshLeadTime constant'

# `hasFreshCachedState` must gate the startup/foreground refresh decision.
assert 'hasFreshCachedState' in king, 'missing hasFreshCachedState'
assert re.search(r'if\s*\(!\s*\[self\s+hasFreshCachedState\]\s*\)', king), \
    'applyConfig does not skip refresh when fresh cache exists'

# Background refresh helper must exist so startup/foreground refreshes do not block.
assert 'refreshCredentialsAsync' in king, 'missing refreshCredentialsAsync'

# Timer must schedule based on the earliest token/proxy expiry.
assert 'earliestExpiry' in king, 'missing preemptive timer scheduling'

# Cache reads must search both primary and shared LiveContainer data dirs.
assert 'LCProxyAllDataDirectories' in king, 'loadState does not search shared dirs'

# Foreground activation should not force a synchronous refresh on the main thread.
assert 'refreshCredentials' not in control, 'foreground notification still forces refresh'

print('king cache/refresh logic static checks OK')
PY
