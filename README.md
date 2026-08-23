# LiveProxy Control for LiveContainer

依赖 [`ios-proxy-dylib`](https://github.com/xiaobright/dsh-anchored-standard)（实际使用其中的 `livecontainer-proxychains`）的 HTTP 代理能力，为 LiveContainer 内任意 App 提供一个控制用 IPA 和配套 dylib。

## 功能

- **代理开关**：随时启用/禁用 HTTP 代理，不修改 `proxychains.conf` 也能立即生效。
- **共享 App 多实例兼容**：王卡本地转发器改为每进程独立临时端口，避免多个 LiveContainer 共享同一 App Group 时争用 `127.0.0.1:18080`，修复前后台切换时被切换应用短暂无网的问题。
- **网络切换 fail-closed**：使用 NWPathMonitor 实时感知 Wi-Fi/蜂窝变化；开启“非蜂窝自动直连”时，仅在确认非蜂窝才直连，切换期间默认保持王卡代理，并从直连切回代理时关闭旧直连 TCP 连接，降低蜂窝下直连公网风险。
- **丢弃非 TCP**：开关 `block_non_tcp`，禁止 UDP/QUIC/ICMP/raw socket 绕过代理。
- **代理地址配置**：在控制台修改 `http host port`，保存后写回共享 `proxychains.conf`。
- **上游模式**：支持“直连（无代理）”、“自定义代理”、“王卡代理”三种模式。
- **王卡代理（Queen/King 新版协议）**：王卡模式内置本地转发器：
  - 自动初始化 `Q-GUID`（PBProxy `GetGuid`，失败本地生成）。
  - 通过旧 WUP `httpWupToken/getTokenInfo` 获取 `Q-Token` / `Q-Key`（RSA+AES 加密信封，ECB/CBC 双模式）。
  - 通过旧 WUP `proxyip/getIPListByRouter` 拉取 `queen_http` / `queen_https` 代理池，支持 MCCMNC / APN / subtype / extra-info / card-type 网络匹配参数。
  - HTTP 走 `queen_http` 分头模式：`Q-GUID` / `Q-UA2` / `Q-Token` / `Q-Type` / `Q-Key` / `Q-RequestId`。
  - HTTPS 走 `queen_https` CONNECT 合并头：`Proxy-Authorization: Q-GUID|...,Q-UA2|...,Q-Token|...,Q-Key|...,Q-RequestId|...,Q-Type|...`。
  - 处理代理响应码 820/821（刷新凭证重试）、823（换节点重试）、822/824（自动直连兜底）。
  - 每 2 分钟自动周期刷新凭证与代理池，避免过期。
  - 可选“非蜂窝网络自动直连”：开启后，当前网络为非蜂窝（Wi-Fi/其他）时自动切到直连，否则走王卡代理；关闭时始终走王卡代理。
- **蜂窝流量统计**：
  - 按 10 分钟时段（bucket）记录上传/下载字节。
  - 只在检测到蜂窝网络（无 Wi-Fi）时累计。
  - 每个 App 进程独立落盘，控制台汇总所有 App。
- **本地 Web 控制台**：dylib 内嵌 HTTP 服务（`127.0.0.1:19092`），控制 IPA 用 WKWebView 打开。
- **首次自动安装 dylib**：控制 IPA 首次打开会从 GitHub Release 下载 `LCTailscaleControl-<version>.dylib` 到 LiveContainer 的 `Tweaks` 目录，签名后重启即可。

## 仓库结构

```
ConsoleApp/         控制 IPA（WKWebView → 127.0.0.1:19092，首次自动下载 dylib）
Tweak/Sources/      控制 dylib 的 ObjC/C 模块（配置、统计、Web 服务、Queen/King 协议、转发器）
Tweak/ProxyCore/    基于 ios-proxy-dylib 的 proxychains 核心 + 流量统计 hook
Tweak/Vendor/       GCDWebServer（Apache-2.0）
Resources/          控制台单文件 HTML
Scripts/            构建脚本 + Queen 原生冒烟测试
Tools/queen_proxy_kit/  Python 参考实现（抓取/验证 Queen 代理协议）
AltStore/           AltStore 源
.github/workflows/  GitHub Actions 构建发布 + Queen 原生冒烟测试
```

## 构建

需要 macOS + Xcode + Node.js：

```bash
./Scripts/build_all.sh
```

产物：

- `build/LCTailscaleControl.dylib` / `LCTailscaleControl-<version>.dylib`
- `build/LiveProxyTailscaleConsole.ipa` / `LiveProxyTailscaleConsole-<version>.ipa`

两个产物均**故意不签名**，由 LiveContainer 导入/签名时用你导入的证书处理。

## 测试

完整的测试流程见 [`docs/TESTING.md`](docs/TESTING.md)。

本地运行全部非 iOS 测试：

```bash
bash Scripts/run_all_tests.sh
```

GitHub Actions 会自动在 push/PR 时运行 CI，包含：

- 异步 connect relay 单元测试
- King cache/refresh 静态检查
- Queen crypto/WUP 对比测试
- iOS dylib 编译链接检查

## 使用

1. 将 `LiveProxyTailscaleConsole.ipa` 导入 LiveContainer 并打开。
2. 首次打开会自动下载 dylib 到 LiveContainer `Tweaks` 目录，按提示退出并重新打开。
3. 重新打开后进入控制台：
   - 直连：选择“直连（无代理）”，打开「启用代理」后所有流量不经过上游代理。
   - 自定义代理：选择“自定义代理”，填写代理地址/端口，打开「启用代理」。
   - 王卡代理：选择“王卡代理”，可修改上游地址/端口与取号接口，打开「启用代理」；保存后会自动取号并每 2 分钟自动刷新。可在王卡设置中开启“非蜂窝网络自动直连”。
4. 被代理的 App 也需在 LiveContainer 中加载 `LCTailscaleControl.dylib`（通常配置为全部 App 注入）。

## AltStore 源

在 AltStore/SideStore 中添加：

```
https://raw.githubusercontent.com/koast18/livecontainer-kingcard-proxy/master/AltStore/altstore-source.json
```

该地址固定不变；更新版本时只需更新仓库中的 `AltStore/altstore-source.json` 并打新 tag，Actions 会自动构建并发布 Release 资产。

> 配置读取：dylib 只会读取自己管理的 `<LC Documents>/LCProxy/proxychains.conf`，不会扫描系统其他 `proxychains.conf`，避免配置互相干扰。

## 流量统计说明

- 统计基于 dylib hook 的 `send/recv/sendto/recvfrom/sendmsg/recvmsg/read/write`，只统计蜂窝网络下非 loopback 的 socket 流量。
- 10 分钟一个时段，保留最近 14 天。
- 每个进程把自身统计写入 `<LC Documents>/LCProxy/stats/<bundle>.json`，控制台汇总。
- 精确度足够日常查看；系统私有网络栈/WKWebView 子进程等无法 100% 覆盖，与 ios-proxy-dylib 的代理覆盖范围一致。

## License

GPLv2（proxychains-ng 与派生代码），GCDWebServer 为 Apache-2.0。

## Tailscale 集成（实验性）

当前 `feature/tailscale-integration` 分支增加了嵌入式 Tailscale 支持：

- 在控制台「代理」页选择 **Tailscale** 模式，并在「Tailscale」页配置节点与 Exit Node。
- 整体链路：
  `用户 App -> LCTailscaleControl SOCKS5 -> 嵌入式 Tailscale -> DERP -> 王卡代理 -> 公网`
- Tailscale 强制 `TS_DEBUG_ALWAYS_USE_DERP=1` / `TS_DEBUG_NEVER_DIRECT_UDP=1`，关闭 P2P 直连和 UDP 打洞。
- Tailscale 的 control plane 和 DERP 外连都通过本进程的 KingCard 本地转发器 HTTP 代理。
- 可在 Tailscale 页面选择/启用 Exit Node，通过 `/api/tailscale/exit-node` 动态切换。

构建时会从 `tailscale-ios-dylib` Release 自动下载 `libtailscale_ios.a`（当前默认 `v0.2.0`），
与现有 proxychains 核心一起链接进 `LCTailscaleControl.dylib`。
