#!/bin/bash
# Regenerate AltStore/altstore-source.json from version.txt.
# Usage: ./Scripts/update_altstore_source.sh [owner/repo] [ipa_size]
#   ipa_size：必填的 public IP 的下载真实字节数（AltStore 用它校验文件完整性，
#   写错会装不上——常见旧脚本硬编码导致源头"看似没更新"）。
#   也可不传，脚本优先读本地 build/IPA，否则自动从 GitHub Release API 获取。
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="${1:-koast18/livecontainer-kingcard-proxy}"
VER="$(cat version.txt | tr -d ' \r\n')"
TAG="v${VER}"
IPA="build/LiveProxyTailscaleConsole-${VER}.ipa"
IPLEN="${2:-}"
if [ -z "$IPLEN" ] && [ -f "$IPA" ]; then
  if command -v gstat >/dev/null 2>&1; then
    IPLEN="$(gstat -c%s "$IPA")"
  elif stat -f%z "$IPA" >/dev/null 2>&1; then
    IPLEN="$(stat -f%z "$IPA")"
  else
    IPLEN="$(stat -c%s "$IPA")"
  fi
fi
if [ -z "$IPLEN" ]; then
  # 从 Release API 读取该 tag 下 LiveProxyTailscaleConsole-*.ipa 的实际字节数
  IPLEN="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/tags/$TAG" | \
    sed -n 's/.*"name":"LiveProxyTailscaleConsole-[^"]*\.ipa","size":\([0-9]*\).*/\1/p' | head -1)"
fi
if [ -z "$IPLEN" ] || ! [ "$IPLEN" -gt 0 ] 2>/dev/null; then
  echo "ERROR: 无法确定 IPA size（本地无 build 且 Release 查询失败）。用 --size 显式传入。" >&2
  exit 1
fi
cat > AltStore/altstore-source.json <<JSON
{
  "name": "LiveProxy Tailscale 源",
  "identifier": "com.liveproxy.tailscale.source",
  "sourceURL": "https://raw.githubusercontent.com/${REPO}/master/AltStore/altstore-source.json",
  "apps": [
    {
      "name": "LiveProxy Tailscale 控制台",
      "bundleIdentifier": "com.liveproxy.tailscale.console",
      "developerName": "koast18",
      "version": "${VER}",
      "versionDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "versionDescription": "LiveProxy Tailscale 控制台：LiveContainer 任意 App HTTP 代理开关、非 TCP 丢弃、10 分钟粒度蜂窝流量统计。首次打开自动下载 dylib。",
      "downloadURL": "https://gh-proxy.com/https://github.com/${REPO}/releases/download/${TAG}/LiveProxyTailscaleConsole-${VER}.ipa",
      "localizedDescription": "LiveContainer 内任意 App 走 HTTP 代理的控制台 IPA。依赖 LCTailscaleControl dylib（自动下载到 LiveContainer Tweaks 目录），支持代理开关、丢弃非 TCP、蜂窝网络上传/下载流量统计（10 分钟时段）。",
      "iconURL": "https://raw.githubusercontent.com/${REPO}/master/AltStore/icon.png",
      "tintColor": "2E7D32",
      "size": ${IPLEN},
      "versions": [
        {
          "version": "${VER}",
          "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
          "downloadURL": "https://gh-proxy.com/https://github.com/${REPO}/releases/download/${TAG}/LiveProxyTailscaleConsole-${VER}.ipa",
          "localizedDescription": "更新版本 ${VER}"
        }
      ]
    }
  ],
  "news": []
}
JSON
echo "Updated AltStore/altstore-source.json for ${VER}"
