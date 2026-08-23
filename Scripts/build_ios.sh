#!/bin/bash
# Build LCTailscaleControl.dylib (iOS 15+ arm64). Requires macOS + Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="build/LCTailscaleControl.dylib"
VER="$(cat "$ROOT/version.txt" | tr -d ' \r\n' )"
OBJDIR="build/obj"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
MIN=15.0
ARCH=arm64

mkdir -p build
rm -rf "$OBJDIR"
mkdir -p "$OBJDIR"

# Generate embedded console HTML
node Scripts/gen_console_asset.js Resources/console.html Tweak/Sources/ConsoleHTML.h

# Tailscale static library is fetched from the tailscale-ios-dylib release.
# It already contains the friendly C wrapper (tailscale_new, tailscale_set_proxy, ...).
TAILSCALE_LIB="$ROOT/Tweak/Tailscale/libtailscale_ios.a"
TAILSCALE_VER="${TAILSCALE_VER:-v0.2.0}"
if [ ! -f "$TAILSCALE_LIB" ]; then
  echo ">> downloading Tailscale iOS static library ${TAILSCALE_VER}"
  mkdir -p build/tailscale-dl
  curl -fL -o build/tailscale-dl/tailscale.tar.gz     "https://github.com/koast18/tailscale-ios-dylib/releases/download/${TAILSCALE_VER}/tailscale-ios-dylib-${TAILSCALE_VER}.tar.gz"
  tar -xzf build/tailscale-dl/tailscale.tar.gz -C build/tailscale-dl
  cp build/tailscale-dl/ios/libtailscale_ios.a "$TAILSCALE_LIB"
  cp build/tailscale-dl/ios/tailscale.h Tweak/Tailscale/tailscale.h
fi

SRCS="$(find Tweak/ProxyCore/vendor/proxychains-ng/src -maxdepth 1 -name '*.c' ! -name 'main.c' | sort) \
Tweak/ProxyCore/fishhook/fishhook.c \
Tweak/ProxyCore/src/webkit_proxy.m Tweak/ProxyCore/src/async_proxy.c Tweak/ProxyCore/src/proxy_override.c \
$(find Tweak/Sources -name '*.m' -o -name '*.c' | sort) \
$(find Tweak/Vendor/GCDWebServer -name '*.m' | sort)"

CFLAGS="-target ${ARCH}-apple-ios${MIN} -isysroot ${SDK} \
  -fobjc-arc -O2 -DNDEBUG \
  -D_GNU_SOURCE -D_DARWIN_C_SOURCE -DIS_MAC=1 -DMONTEREY_HOOKING -DSUPER_SECURE \
  -DGN_NODELEN_T=socklen_t -DGN_SERVLEN_T=socklen_t -DGN_FLAGS_T=int -DHAVE_CLOCK_GETTIME \
  -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations \
  -I${ROOT}/Tweak/Sources   -I${ROOT}/Tweak/Tailscale \
  -I${ROOT}/Tweak/ProxyCore/src \
  -I${ROOT}/Tweak/ProxyCore/vendor/proxychains-ng/src \
  -I${ROOT}/Tweak/ProxyCore/fishhook \
  -I${ROOT}/Tweak/Vendor/GCDWebServer \
  -I${ROOT}/Tweak/Vendor/GCDWebServer/Core \
  -I${ROOT}/Tweak/Vendor/GCDWebServer/Requests \
  -I${ROOT}/Tweak/Vendor/GCDWebServer/Responses"

OBJS=""
for f in $SRCS; do
  base="$(basename "${f%.*}")_$(echo "$f" | cksum | awk '{print $1}')"
  o="$OBJDIR/${base}.o"
  echo ">> compile $f"
  EXTRA=""
  if [[ "$f" == *webkit_proxy.m ]]; then EXTRA="-fno-objc-arc"; fi
  clang $CFLAGS $EXTRA -c "$f" -o "$o"
  OBJS="$OBJS $o"
done

echo ">> link $OUT"
clang -dynamiclib -arch $ARCH -mios-version-min=$MIN -isysroot "$SDK" \
  -fobjc-arc -O2 \
  $OBJS \
  "$TAILSCALE_LIB" \
  -framework Foundation \
  -framework UIKit \
  -framework WebKit \
  -weak_framework Network \
  -framework SystemConfiguration \
  -framework CFNetwork \
  -framework Security \
  -framework CoreFoundation \
  -framework CoreServices \
  -lz \
  -o "$OUT"

cp "$OUT" "build/LCTailscaleControl-${VER}.dylib"
echo ">> done: $OUT"
file "$OUT"
ls -lh build/LCTailscaleControl-*.dylib
