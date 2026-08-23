# 测试流程说明

本文档描述 `feat/async-connect` / `master` 上 3B 异步 connect 方案的测试流程，以及如何用 GitHub Actions 自动执行。

## 1. 测试范围

| 层级 | 覆盖内容 | 关键脚本 |
| --- | --- | --- |
| 静态检查 | 王卡缓存/刷新逻辑是否仍满足预期 | `Scripts/test_king_cache_logic.sh` |
| 单元测试 | 异步 loopback TCP relay 的核心行为 | `Scripts/test_async_proxy.sh` |
| 加密自测 | Queen 协议相关 crypto 原始字节正确性 | `Scripts/test_queen_crypto.sh` |
| 二进制对比 | native 与 Python 参考实现的 WUP 字节一致 | `Scripts/test_queen_wup_compare.sh` |
| 构建验证 | iOS dylib 能完整编译/链接 | `Scripts/build_ios.sh` |

## 2. 异步 relay 单元测试

`Scripts/test_async_proxy.c` 使用本地 echo server 和 `connect_proxy_chain()` 替身，不依赖真机，覆盖：

1. **非阻塞 `connect()` 立即返回**
   - 构造 `O_NONBLOCK` socket；
   - 调用 `lcproxy_async_connect_start()`；
   - 断言耗时 < 500ms（CI 上通常为 0ms）。

2. **调用方 fd 可通过 `poll()` 使用**
   - `POLLOUT` 应快速返回；
   - 证明 fd 已经是可用的本地回环 TCP 连接。

3. **小包双向转发 + ACK**
   - App → relay → upstream server → relay → App；
   - 验证双向泵和基础转发正确。

4. **大包双向转发（256 KiB）**
   - 验证 `pump_bidirectional()` 能处理连续/分片数据，不丢数据。

5. **上游连接失败**
   - 让 `connect_proxy_chain()` 返回失败；
   - 断言 App 端能观察到 EOF（`recv() == 0`），说明后台失败不会导致调用方永久挂起。

运行方式：

```bash
bash Scripts/test_async_proxy.sh
```

预期输出：

```text
small relay roundtrip OK: start=0ms payload=32 bytes ack=DONE
large relay roundtrip (256 KiB) OK: start=0ms payload=262144 bytes ack=DONE
upstream failure test OK: relay reported EOF to caller
all async proxy tests passed
```

## 3. 本地全量测试

macOS 有 Xcode 时执行：

```bash
bash Scripts/run_all_tests.sh
```

该脚本按顺序运行：

1. King cache/refresh 静态检查
2. Async proxy relay 单元测试
3. Queen crypto 自测
4. Queen WUP 二进制对比
5. iOS dylib 编译/链接检查

如果当前机器是 Linux 或没有 Xcode，只会跳过 iOS dylib 构建步骤，其余测试仍会运行。

## 4. GitHub Actions 自动测试

工作流文件：`.github/workflows/ci.yml`

触发方式：

- push 到任意分支；
- 创建/更新 Pull Request；
- 也可以进入仓库 Actions 页面手动 `Run workflow`。

CI 会执行：

```yaml
Install Python dependencies
King cache/refresh logic static tests
Async proxy relay test
Queen crypto self-test
Queen WUP binary comparison
Build dylib (compile/link check)
```

### 如何在 Actions 页面查看

1. 打开仓库的 **Actions** 标签。
2. 选择 **CI** workflow。
3. 点击最新一次运行。
4. 查看每个 step 是否绿色通过。

### 已通过的验证记录

最新一次实际运行：

- 运行 ID：`32316790659`
- 状态：✅ success
- 关键输出：
  - `async start returned in 0 ms`
  - `echo OK: hello-async-proxy`
  - `WUP binary comparison OK`
  - `build/LCTailscaleControl.dylib: Mach-O 64-bit dynamically linked shared library arm64`

## 5. 真机人工测试（最终确认）

CI 只能验证逻辑和编译，最终仍需真机确认动画流畅度：

1. 从 CI 的 `Build dylib` artifact 或本地构建取得：
   - `build/LCTailscaleControl.dylib`
   - `build/LiveProxyTailscaleConsole.ipa`
2. 导入 LiveContainer，并让 PiliPlus 等目标 App 加载 dylib。
3. 开启自定义/王卡代理模式。
4. 进入 PiliPlus 首页/视频页，触发网络请求。
5. 观察 loading/转场动画是否卡顿。
6. 对比：
   - 未加载 dylib；
   - 加载 dylib 但使用直连模式；
   - 加载 dylib 且使用代理模式（本方案重点）。

## 6. 失败排查

- **Async proxy relay test 失败**
  - 检查是否在 macOS/Linux 上可编译；
  - 检查 `Tweak/ProxyCore/src/async_proxy.c` 是否参与构建；
  - 检查 `Scripts/test_async_proxy.sh` 是否包含 `-DGN_NODELEN_T=socklen_t -DGN_SERVLEN_T=socklen_t -DGN_FLAGS_T=int`。

- **Queen tests 失败**
  - 确认已安装 `requests`、`pycryptodome`；
  - 可运行 `python3 -m pip install --user --break-system-packages --quiet -r Tools/queen_proxy_kit/requirements.txt`。

- **Build dylib 失败**
  - 需要 macOS + Xcode；
  - 检查 `Tweak/ProxyCore/Makefile` 和 `Scripts/build_ios.sh` 是否包含 `async_proxy.c`。
