#!/bin/bash
# Generate AltStore/beta-source.json for the test channel.
# Usage: ./Scripts/update_beta_altstore_source.sh [owner/repo] [tag] [branch]
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="${1:-koast18/livecontainer-kingcard-proxy}"
TAG="${2:-v0.5.17-beta.1}"
BRANCH="${3:-perf/fix-dylib-lag}"
VER="$(cat version.txt | tr -d ' \r\n')"
IPA="build/LiveProxyTailscaleConsole-${VER}.ipa"
if command -v gstat >/dev/null 2>&1; then
  SIZE="$(gstat -c%s "$IPA")"
elif stat -f%z "$IPA" >/dev/null 2>&1; then
  SIZE="$(stat -f%z "$IPA")"
else
  SIZE="$(stat -c%s "$IPA")"
fi
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BETA_VER="${TAG#v}"
SOURCE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/AltStore/beta-source.json"
DOWNLOAD_URL="https://gh-proxy.com/https://github.com/${REPO}/releases/download/${TAG}/LiveProxyTailscaleConsole-${VER}.ipa"

cat > AltStore/beta-source.json <<JSON
{
  "name": "LiveProxy 测试版源",
  "identifier": "com.liveproxy.tailscale.source.beta",
  "sourceURL": "${SOURCE_URL}",
  "apps": [
    {
      "name": "LiveProxy 测试版控制台",
      "bundleIdentifier": "com.liveproxy.tailscale.console.beta",
      "developerName": "koast18",
      "version": "${BETA_VER}",
      "versionDate": "${DATE}",
      "versionDescription": "LiveProxy 测试版控制台：perf/fix-dylib-lag 热路径性能修复。",
      "downloadURL": "${DOWNLOAD_URL}",
      "localizedDescription": "测试版控制台 IPA。首次打开会从 GitHub Release ${TAG} 自动下载对应的 LCTailscaleControl dylib。用于验证 dylib 注入后的性能修复。",
      "iconURL": "https://raw.githubusercontent.com/${REPO}/${BRANCH}/AltStore/icon.png",
      "tintColor": "2E7D32",
      "size": ${SIZE},
      "versions": [
        {
          "version": "${BETA_VER}",
          "date": "${DATE}",
          "downloadURL": "${DOWNLOAD_URL}",
          "localizedDescription": "测试版 ${TAG}"
        }
      ]
    }
  ],
  "news": []
}
JSON
echo "Updated AltStore/beta-source.json for ${TAG} (${SOURCE_URL})"
