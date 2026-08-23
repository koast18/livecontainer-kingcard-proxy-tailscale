#!/bin/bash
# Build LiveProxyTailscaleConsole.ipa (control app, WKWebView -> 127.0.0.1:19092).
# No signing: LiveContainer signs on import.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
MIN=15.0
ARCH=arm64
APP="build/LiveProxyTailscaleConsole.app"

mkdir -p build
rm -rf "$APP"
mkdir -p "$APP"

echo ">> compile ConsoleApp"
clang -target ${ARCH}-apple-ios${MIN} -isysroot "$SDK" \
  -fobjc-arc -O2 -DNDEBUG \
  -Wall -Wextra -Wno-unused-parameter \
  -I "$ROOT/ConsoleApp" \
  -framework UIKit -framework WebKit -framework Foundation -framework CoreGraphics \
  "$ROOT/ConsoleApp/main.m" \
  "$ROOT/ConsoleApp/AppDelegate.m" \
  "$ROOT/ConsoleApp/ViewController.m" \
  "$ROOT/ConsoleApp/AutoUpdater.m" \
  -o "$APP/LiveProxyTailscaleConsole"

echo ">> assemble .app"
cp "$ROOT/ConsoleApp/Info.plist" "$APP/Info.plist"
VER="$(cat "$ROOT/version.txt" | tr -d ' \r\n')"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VER" "$APP/Info.plist" || true
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VER" "$APP/Info.plist" || true

# 可覆盖 dylib 下载来源仓库（例如 Tailscale 分支使用独立公开仓库）。
if [[ -n "${LC_PROXY_UPDATE_REPO:-}" ]]; then
  /usr/libexec/PlistBuddy -c "Delete :LCProxyUpdateRepo" "$APP/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :LCProxyUpdateRepo string ${LC_PROXY_UPDATE_REPO}" "$APP/Info.plist"
fi

# 测试版构建：可指定 dylib 下载 pin 到的 GitHub Release tag，并可换 bundle id 以便与正式版共存。
if [[ -n "${LC_PROXY_UPDATE_TAG:-}" ]]; then
  BETA_VER="${LC_PROXY_UPDATE_TAG#v}"
  /usr/libexec/PlistBuddy -c "Delete :LCProxyUpdateTag" "$APP/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :LCProxyUpdateTag string ${LC_PROXY_UPDATE_TAG}" "$APP/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${BETA_VER}" "$APP/Info.plist" || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion 1" "$APP/Info.plist" || true
  if [[ -n "${LC_PROXY_BETA_BUNDLE_ID:-}" ]]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${LC_PROXY_BETA_BUNDLE_ID}" "$APP/Info.plist" || true
    /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName LiveProxy 测试版" "$APP/Info.plist" || true
  fi
fi
printf 'APPL????' > "$APP/PkgInfo"
file "$APP/LiveProxyTailscaleConsole"

echo ">> package .ipa"
cd build
rm -rf Payload
mkdir -p Payload
cp -R LiveProxyTailscaleConsole.app Payload/
rm -f LiveProxyTailscaleConsole.ipa
zip -qry LiveProxyTailscaleConsole.ipa Payload
cp LiveProxyTailscaleConsole.ipa "LiveProxyTailscaleConsole-${VER}.ipa"
cd "$ROOT"
echo ">> done: build/LiveProxyTailscaleConsole.ipa"
ls -la build/LiveProxyTailscaleConsole.ipa build/LiveProxyTailscaleConsole-*.ipa
