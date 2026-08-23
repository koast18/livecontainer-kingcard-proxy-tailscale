# Alook 大流量下载 / Speedtest 闪退彻底排查

> 分支：`research/alook-speedtest-crash`
> 日期：2026-08-22
> 现象：Alook 浏览器打开 Speedtest 测速（不限于 Speedtest，任何大流量下载约 10 秒）时闪退。
> 方法：静态代码审查 + 近期修复提交追溯。当前仓库没有真机 crash log / sysdiagnose，因此本文把“已经能从代码确认的根因”和“仍需要真机日志确认的潜在根因”分开列出。

## 0. 结论速览

本项目 dylib 在“高速下载 10 秒左右闪退”上，**已经有多个明确的代码级根因被修复**；本分支又补上了 **死锁、async_proxy 线程上限、WebKit 多代 UAF 加固**，剩余主要是**需要 crash report 才能确认的 WebKit/资源型候选**：

| # | 根因 | 状态 | 对应提交/代码 |
|---|---|---|---|
| 1 | `nw_proxy_config` 被提前释放，WebKit 下载/网络栈 use-after-free | 已修复（延迟一代释放） | `7ed66fa` (v0.5.24), `Tweak/ProxyCore/src/webkit_proxy.m` |
| 2 | KingCard 本地转发器并发连接风暴，无限创建线程耗尽资源 | 已修复（64 并发上限 + 失败处理） | `7ed66fa` (v0.5.24), `Tweak/Sources/KPKIngCore.c` |
| 3 | 转发器 stop/free 时仍有 detached client 线程访问已释放结构体 | 已修复（跟踪 fd、shutdown、等待归零） | `f5078ec` (v0.5.27), `Tweak/Sources/KPKIngCore.c` |
| 4 | `LCProxyKing.applyConfig` 持锁调用 `kp_forwarder_stop`，与 client 线程取号刷新可能死锁 | **已修复（本分支）** | `Tweak/Sources/LCProxyKing.m:98-132`, `Tweak/Sources/KPKIngCore.c:2068-2098` |
| 5 | `async_proxy.c` 每个非阻塞 connect 都 detach 一个 relay 线程，无上限/无跟踪 | **已修复（本分支）** | `Tweak/ProxyCore/src/async_proxy.c:219-243` |
| 6 | WebKit 下载进行中反复 reload/clear `WKWebsiteDataStore.proxyConfigurations`，可能触发 WebKit 内部重配置崩溃 | 已加固（多代保留），真机验证 | `Tweak/ProxyCore/src/webkit_proxy.m:144-183,245-276` |
| 7 | iOS Jetsam 内存/线程超限被杀，表现为“闪退” | 需 crash report 确认 | 与 #2/#5 相关 |

## 1. 已确认根因 1：`nw_proxy_config` Use-After-Free（v0.5.24 修复）

### 证据

`Tweak/ProxyCore/src/webkit_proxy.m` 顶部注释已经直接写出：

```objc
// 上一代 config：WKWebsiteDataStore.setProxyConfigurations: 接收 nw_proxy_config
// 数组时通常不为其元素做强引用（nw_proxy_config 是 CF 类型）。因此 reload 时若
// 立即 nw_release 旧 config，WebKit 下载/网络栈仍可能持有已释放指针 → UAF 崩溃
// （症状：调起系统下载组件、或高速下载时闪退）。
```

提交 `7ed66fa` (v0.5.24) 修复方式：

```objc
static nw_proxy_config_t g_lc_proxy_config_old;

void livecontainer_reload_webkit_proxy(void) {
    if (g_lc_proxy_config_old)
        nw_release(g_lc_proxy_config_old);
    g_lc_proxy_config_old = g_lc_proxy_config;
    g_lc_proxy_config = NULL;
    ...
}
```

也就是“当前 config 降级为 old 保留一代，下一轮 reload 才释放”。

### 为什么会导致“大流量下载 10 秒闪退”

- Alook 是 WKWebView 浏览器，大流量下载常走 WebKit 的下载/网络栈（`WKDownload` 或系统网络进程）。
- `WKWebsiteDataStore.proxyConfigurations` 传的是 `nw_proxy_config`。
- WebKit 在下载进行中可能仍然持有这个 config 指针；旧代码一旦 reload（网络切换、前后台、设置保存、凭证刷新等）就立即 `nw_release`。
- 下载约 10 秒时通常正好发生一次网络状态变化/后台刷新/代理 reload，WebKit 继续读已释放对象 → `EXC_BAD_ACCESS`。

### 剩余风险

- 当前只保留“上一代”config。如果短时间内连续 reload 多次，且 WebKit 有多个 data store / 多个下载分别持有不同代的 config，仍可能释放仍被引用的更早 config。
- `setProxyConfigurations:@[]`（清除代理）本身也可能让 WebKit 在下载中重建网络栈，需要真机日志确认。

## 2. 已确认根因 2：KingCard 转发器线程风暴（v0.5.24 修复）

### 证据

`Tweak/Sources/KPKIngCore.c`：

```c
// 转发器活跃客户端/线程上限：防止高速下载并发连接风暴创建过量线程
// （iOS 对线程数/栈内存有硬限制，超限会整个 App 闪退）。
#define KP_FORWARDER_MAX_CLIENTS 64
```

v0.5.24 之前 `kp_forwarder_run()` 对每个 accept 直接 `pthread_create` + `pthread_detach`，且不检查 `pthread_create` 失败。

Speedtest / 多线程下载器会瞬间建立大量并发 TCP 连接，每个连接在本地转发器里创建一个 detached 线程。iOS 对线程数/栈内存有硬限制，超限时整个 App 闪退。

### 修复内容

- 活跃客户端上限 64；
- 超过上限直接回 `503` 并关闭；
- `pthread_create` / `malloc` 失败时回滚计数并释放资源。

## 3. 已确认根因 3：转发器结构体被提前释放，client 线程 UAF（v0.5.27 修复）

### 证据

提交 `f5078ec` 说明：

> Root cause of crashes during speed tests / high-throughput downloads:
> kp_forwarder_free called kp_forwarder_stop (which only joined the accept
> thread) then immediately destroyed cred_mutex/client_lock and freed the
> forwarder struct. Detached client threads still running kp_handle_client
> (high-speed pipe forwarding) would then access freed memory / destroyed
> mutex -> EXC_BAD_ACCESS.

修复：

- `kp_forwarder` 记录活跃 client fd；
- `kp_forwarder_stop` 先 join accept 线程，再 shutdown 所有活跃 fd，等待 `active_clients == 0`；
- `kp_forwarder_free` 在所有 client 线程退出后才销毁锁/条件变量并 free。

这个根因通常在“下载进行中切换代理/关闭王卡/切换网络模式”时触发，和用户“大流量下载约 10 秒闪退”高度吻合。

## 4. 已修复的并发风险：`applyConfig` 持锁 stop/free 转发器可能死锁

### 代码路径

`Tweak/Sources/LCProxyKing.m:applyConfig:`：

```objc
[self.lock lock];
...
if (!shouldRun) {
    [self stopRefreshTimer];
    if (self.forwarder) {
        kp_forwarder_stop(self.forwarder);   // 会等待 active_clients == 0
        kp_forwarder_free(self.forwarder);
        self.forwarder = NULL;
    }
    ...
    [self.lock unlock];
    return;
}
if (self.forwarder) {
    kp_forwarder_stop(self.forwarder);       // 同上
    kp_forwarder_free(self.forwarder);
    self.forwarder = NULL;
}
```

`kp_forwarder_stop()` 在 `Tweak/Sources/KPKIngCore.c` 中会：

```c
while (fw->active_clients > 0) {
    pthread_cond_wait(&fw->client_cond, &fw->client_lock);
}
```

而 client 线程在代理节点失败时可能调用：

```c
kp_forwarder_refresh_retry(fw, 3, 500)
  -> refresh_fn -> [LCProxyKing refreshCredentials]
  -> [self.lock lock]   // 与 applyConfig 的 self.lock 是同一把锁
```

### 死锁场景

1. Speedtest 下载中，本地转发器有多个活跃 client 线程。
2. 某个 client 线程遇到代理池需要刷新（例如响应码 820/821/823、代理池为空、超时）。
3. 用户/系统同时触发 `applyConfig`（设置保存、网络切换、前后台、关闭王卡、切换模式）。
4. 主线程持有 `self.lock`，进入 `kp_forwarder_stop()` 等待 `active_clients == 0`。
5. 该 client 线程在 `refreshCredentialsWithForce:` 开头等待 `self.lock`，永远不退出。
6. 主线程死等，App 卡死；iOS Watchdog 可能随后杀进程，表现也是“闪退”。

### 本分支修复

- `applyConfig:` 已改为：先在锁内摘除 `self.forwarder` 引用并释放 `self.lock`，再在锁外调用 `kp_forwarder_stop/free`；
- 创建新转发器也在锁外完成，最后回锁确认仍应运行且没有别的转发器被安装；
- 因此 client 线程取号刷新等待 `self.lock` 时，不会再与主线程的 stop 等待互相死锁。

### 建议修复方向（如果后续还要更稳）

- 让 `kp_forwarder_refresh_retry` 使用独立的 C 锁/异步刷新，不依赖 `LCProxyKing.lock`；
- 或给 stop 增加超时，超时后不无限等待，避免主线程永久卡死。

## 5. 已修复的并发风险：`async_proxy.c` 的 relay 线程无上限

`Tweak/ProxyCore/src/async_proxy.c` 为非阻塞 `connect()` 提供异步代理：

```c
pthread_t thread;
if (pthread_create(&thread, NULL, relay_worker, job) != 0) {
    free(job);
    close(peer_fd);
    return -1;
}
pthread_detach(thread);
```

每个非阻塞 TCP connect 都会创建一个 detached relay 线程。这个线程数量**没有上限、没有跟踪、没有 join/等待**。

如果 Alook 自带下载器 / Speedtest 使用大量非阻塞并发连接，主 App 进程内可能同时存在：

- 本地转发器 client 线程（已限制 64）
- `async_proxy` relay 线程（未限制）

线程/栈内存仍然可能被打爆，尤其是多个 App 或多次测速叠加时。

### 本分支修复

- `async_proxy.c` 已增加 `LC_ASYNC_MAX_RELAY_THREADS 64` 全局活跃 relay 线程上限；
- 达到上限时 `lcproxy_async_connect_start` 返回失败，调用方回退到同步代理路径，不再无限创建 detached 线程；
- `make_local_tcp_pair` / `calloc` / `pthread_create` 失败路径都会正确释放已占用的 relay 名额。

### 后续可选优化

- 把 relay 线程池化，避免每次连接都新建线程；
- `pthread_create` 失败时避免直接同步阻塞主线程，可考虑排队异步重试。

## 6. 需真机日志确认的 WebKit 行为

### 6.1 下载中反复 reload/clear 代理配置

`livecontainer_reload_webkit_proxy()` 会在以下时机被调用：

- 保存控制台配置；
- 网络路径变化；
- 前后台切换/凭证刷新触发 `applyToRuntime` 且 runtime signature 变化；
- 直连/代理切换。

每次 reload 都会对 `defaultDataStore` 重新 `setProxyConfigurations:`，无代理时还会 `setProxyConfigurations:@[]`。

如果 Speedtest 正在下载，WebKit 网络进程/下载任务正在使用旧 proxy config，此时更新/清空配置可能触发 WebKit 内部状态不一致。即使没有 UAF，也可能 crash 或终止下载。

**真机验证方法**：
- 在下载/测速过程中不要切换网络、不要保存配置、不要前后台，看是否还闪退；
- 如果只在“下载中发生 reload”时闪退，则这条是主因或叠加因素；
- 抓 `proxychains.log` 看闪退前是否有 `webkit proxy reload` 日志。

### 6.2 多个 WKWebsiteDataStore / 多个代 config 的 UAF 残留

本分支已把“只保留一代旧 config”改为“保留最多 3 个旧 config”，降低多 data store / 多次 reload 时的多代 UAF 风险。若仍出现崩溃，需用 crash report 确认是否还有 WebKit 内部生命周期问题。

### 6.3 Speedtest 使用 QUIC/HTTP3 与 `block_non_tcp`

Speedtest 某些节点可能使用 UDP/QUIC。若用户开启了“丢弃非 TCP”，`sendto`/`connect` 对 UDP 会返回 `EPROTONOSUPPORT`。这通常只会导致测速失败/降级，但如果 WebKit 或 Alook 对 socket 错误处理不当，也不排除异常退出。需要真机验证关闭 `block_non_tcp` 前后是否变化。

## 7. 排查清单（真机可执行）

建议收集以下证据后再下最终结论：

1. **闪退前日志**
   - `<LiveContainer Documents>/LCProxy/proxychains.log`
   - 控制台“调试日志”开一轮，复现后导出 `proxychains.log`
2. **系统 Crash Report / Jetsam 日志**
   - iOS 设置 → 隐私与安全性 → 分析与改进 → 分析数据
   - 找 `Alook` / `LiveContainer` 对应 `.ips`
   - 关键看：
     - `Exception Type: EXC_BAD_ACCESS` → 大概率 UAF/野指针
     - `Exception Type: EXC_RESOURCE` / `Jetsam` → 资源/线程/内存超限
     - `Exception Type: EXC_CRASH (SIGKILL)` + `watchdog` → 主线程卡死/死锁
     - 崩溃线程栈是否落在 `nw_proxy_config` / `KPKIngCore` / `async_proxy` 相关符号
3. **复现变量**
   - 关掉王卡/代理，直接模式是否还闪退？
   - 不加载 dylib 是否还闪退？（排除 Alook 自身问题）
   - 下载过程中不切后台/不保存配置/不切网络是否还闪退？
   - 开启 vs 关闭 `block_non_tcp`
   - Speedtest 用 1 线程 vs 多线程
4. **版本确认**
   - 当前 master 是 v0.5.28，已包含 v0.5.24 + v0.5.27 两个关键修复；本分支另有死锁/线程上限/WebKit 加固。
   - 如果用户实际使用的是早于 v0.5.24 的 dylib，先升级再复测。

## 8. 已完成的代码动作

1. 修复 `LCProxyKing.applyConfig` 持锁 stop/free 的死锁风险（第 4 节）。
2. 给 `async_proxy` relay 线程加上限（第 5 节）。
3. 对 `nw_proxy_config` 生命周期做更保守的保留：保留最多 3 个旧 config（第 1/6 节）。
4. 在 CI 静态测试中加入针对上述并发不变量的检查。

### 仍建议的真机验证/后续

- 增加“下载/测速期间延迟 WebKit proxy reload”或“只在空闲时 reload”的策略。
- 获取真机 `.ips`，确认是否还有 WebKit 内部重配置或 Jetsam 相关问题。

## 9. 与现有测试/GitHub Actions 的关系

当前仓库已有 CI（`.github/workflows/ci.yml`）覆盖：
- King cache/refresh 静态检查
- Foreground reload/shared-app forwarder 静态检查
- Proxy override 单元测试
- Async proxy relay 测试
- Queen crypto/WUP 对比
- iOS dylib 编译链接（macOS runner）

这些测试可以验证代码可编译、基础逻辑不回归，但**不能替代真机 crash log**。本分支的 CI 已加入 `Alook high-download crash guard static checks`，覆盖 WebKit 多代保留、转发器线程上限/等待、async_proxy relay 上限和死锁修复标记。
