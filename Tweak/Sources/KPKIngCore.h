//
//  KPKIngCore.h
//  LCProxyTweak
//
//  王卡免流转发器核心（纯 C，无 Foundation 依赖，可宿主单测）。
//  机制参考 boxjs/src/tencent.ts：
//  1) 自动取号：GET http://kc.iikira.com/kingcard → 响应体 "GUID,TOKEN"（逗号分隔）
//  2) 登录激活：经上游代理 CONNECT {guid}.{token}.iikira.com.token:80 并 GET /
//  3) 转发：CONNECT 目标 → 补 Q-GUID/Q-Token 头 → 上游代理 157.148.54.212:8091
//  4) 事件驱动：上游 CONNECT 非 200/连接失败 → refresh hook → 刷新成功后重试一次
//
//  取号链顺序（kp_fetch_guid_token_best）：经上游代理 → 直连，多次重试退避。
//  失败诊断：状态行 + Content-Encoding + 响应体前 512 字节（脱敏后由宿主落日志）。
//

#ifndef KPKIngCore_h
#define KPKIngCore_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------- 取号诊断 ----------

typedef struct kp_fetch_diag {
    char status_line[128];      // 例如 "HTTP/1.1 200 OK"
    char content_encoding[64];  // 例如 "gzip" / ""
    char body_head[520];        // 响应体前 512 字节 + NUL
    unsigned int body_len;      // 响应体实际长度
    char location[256];         // 3xx 重定向 Location（若有）
    int parse_fail_reason;      // 0=无/成功；1=无逗号非JSON；2=段空；3=段超容量；4=含非法字符；5=响应结构异常
    int parse_fail_pos;         // 失败位置（字符索引，-1 无）
    char body_struct[520];      // body 结构指纹：alnum→'A'，其他可打印原样，不可打印→'.'
} kp_fetch_diag;

static inline void kp_fetch_diag_init(kp_fetch_diag *d) {
    if (!d) return;
    d->status_line[0] = '\0';
    d->content_encoding[0] = '\0';
    d->body_head[0] = '\0';
    d->body_len = 0;
    d->location[0] = '\0';
    d->parse_fail_reason = 0;
    d->parse_fail_pos = -1;
    d->body_struct[0] = '\0';
}

// ---------- 纯函数（可单测） ----------

/// 解析 "GUID,TOKEN" 响应体；容错 \r\n/空白；支持 JSON 形式 {"guid":"..","token":".."}。成功返回 0。
int kp_parse_guid_token(const char *body, size_t len,
                        char *guid, size_t guid_cap,
                        char *token, size_t token_cap);

/// 构造魔改域名 host："{guid}.{token}.iikira.com.token"。成功返回 0。
int kp_build_login_host(const char *guid, const char *token,
                        char *out, size_t out_cap);

/// 严格校验 guid/token 可安全拼入域名 Host（仅字母数字 - _）。合法返回 0。
int kp_validate_creds_for_host(const char *guid, const char *token);

/// 生成 body 结构指纹 + 解析失败原因分析（供诊断日志，不泄露内容）。
void kp_analyze_body(const char *body, size_t len,
                     size_t guid_cap, size_t token_cap,
                     char *struct_out, size_t struct_cap,
                     int *fail_reason, int *fail_pos);

/// 解析 HTTP 代理绝对 URI 请求行："GET http://host[:port]/path HTTP/1.1"。成功返回 0。
int kp_parse_absolute_uri(const char *line, size_t len,
                          char *method, size_t method_cap,
                          char *host, size_t host_cap, int *port,
                          char *path, size_t path_cap);

/// 重建请求：绝对 URI 行 → path 形式 + 补 Host + Connection: close（过滤原 Host 行）。
/// 成功返回字节数，失败 -1。
int kp_rebuild_proxy_request(const char *reqbuf, size_t reqlen,
                             const char *method, const char *host, int port,
                             const char *path,
                             char *out, size_t out_cap);

/// 经上游代理 CONNECT 隧道 GET http 目标，取响应体（供出口 IP 检测等）。
/// 成功返回 0，out 回填响应体（NUL 结尾）。
int kp_http_get_via_proxy(const char *upstream_host, int upstream_port,
                          const char *target_host, int target_port, const char *path,
                          const char *guid, const char *token,
                          int timeout_ms, char *out, size_t out_cap);

/// 经带用户名密码认证的 SOCKS5 代理 GET HTTP 目标，取响应体。
int kp_http_get_via_socks5(const char *proxy_host, int proxy_port,
                           const char *username, const char *password,
                           const char *target_host, int target_port, const char *path,
                           int timeout_ms, char *out, size_t out_cap);

/// 直连 GET http 目标（无代理），取响应体（供出口 IP 检测等）。
/// 成功返回 0，out 回填响应体（NUL 结尾）。
int kp_http_get_direct(const char *target_host, int target_port, const char *path,
                       int timeout_ms, char *out, size_t out_cap);

/// 构造发往上游代理的 CONNECT 请求（含 Q-GUID/Q-Token/User-Agent 头，CRLF 结尾）。成功返回 0。
int kp_build_connect_request(const char *target_host, int target_port,
                             const char *guid, const char *token,
                             char *out, size_t out_cap);

/// 解析客户端 CONNECT 行 "CONNECT host:port HTTP/1.1"。成功返回 0。
int kp_parse_connect_line(const char *line, size_t len,
                          char *host, size_t host_cap, int *port);

/// 简单 HTTP 状态行解析：返回 1=2xx。
int kp_response_is_2xx(const char *buf, size_t len);

/// 解析 HTTP 响应（buf 为完整响应）：提取状态行/Content-Encoding，body 解 gzip 后输出。
/// 成功返回 0；diag 始终填充（状态行/编码/body 前 512 字节）。
int kp_parse_http_response(const char *buf, size_t len,
                           char *body, size_t body_cap, size_t *body_len,
                           kp_fetch_diag *diag);

// ---------- 网络操作（真机/宿主均可用，宿主测试仅编译/本地回环） ----------

/// 直连取号：GET refresh_url。返回 0 成功，-1 网络错，-2 解析错。
int kp_fetch_guid_token(const char *refresh_url,
                        char *guid, size_t guid_cap,
                        char *token, size_t token_cap,
                        int timeout_ms, kp_fetch_diag *diag);

/// 经上游代理取号：CONNECT refresh_host:port（带可选 hints）→ 隧道内 GET。返回同上。
int kp_fetch_guid_token_via_proxy(const char *upstream_host, int upstream_port,
                                  const char *refresh_url,
                                  const char *guid_hint, const char *token_hint,
                                  char *guid, size_t guid_cap,
                                  char *token, size_t token_cap,
                                  int timeout_ms, kp_fetch_diag *diag);

/// 综合取号链：先经上游代理、失败则直连，整体重试 attempts 次（间隔 backoff_ms）。
/// last_source 输出最终成功来源（"proxy"/"direct"/""）。返回最后一次 rc。
int kp_fetch_guid_token_best(const char *refresh_url,
                             const char *upstream_host, int upstream_port,
                             const char *guid_hint, const char *token_hint,
                             int attempts, int backoff_ms, int timeout_ms,
                             char *guid, size_t guid_cap,
                             char *token, size_t token_cap,
                             kp_fetch_diag *diag, char *last_source, size_t last_source_cap);

/// 经上游代理直发绝对 URI 完成免流激活（与 boxjs 一致：不 CONNECT、不解析魔改域名，
/// 网关本地识别；不要求特定状态码，收到响应即成功）。diag_status 可空，回填状态行前 128B。
int kp_login_via_proxy(const char *upstream_host, int upstream_port,
                       const char *login_host, const char *guid, const char *token,
                       int timeout_ms, char *diag_status, size_t diag_cap);

/// 直连（socket 层 bypass，不经本进程代理劫持）发起 HTTP POST。
/// 仅供凭证取号等基础设施流量使用：这类请求若被劫持回本进程 forwarder，
/// 会在凭证过期时形成"刷新请求依赖已失效凭证"的循环死锁。
/// 仅支持 http:// URL；headers 为 "Name: Value" 字符串数组，NULL 结尾。
/// 返回 0=收到完整响应（out 填充原始响应报文），-1=网络/参数错误，-2=URL 非 http。
/// 同 kp_http_post_direct，另通过 out_len 回填响应真实字节数（响应体可能含 \0）。
int kp_http_post_direct_len(const char *url,
                            const char *const headers[],
                            const char *body, size_t body_len,
                            int timeout_ms,
                            char *out, size_t out_cap,
                            size_t *out_len);
int kp_http_post_direct(const char *url,
                        const char *const headers[],
                        const char *body, size_t body_len,
                        int timeout_ms,
                        char *out, size_t out_cap);

/// 探活：经上游代理 CONNECT www.gstatic.com:80 + GET /generate_204。返回 1 通。
int kp_probe_generate204(const char *upstream_host, int upstream_port,
                         const char *guid, const char *token, int timeout_ms);

// ---------- 转发器服务器（POSIX sockets + pthread） ----------

typedef struct kp_forwarder kp_forwarder;

/// 凭证刷新回调：宿主实现取号链+登录激活；返回 0=已更新可重试，非 0=刷新失败。
typedef int (*kp_refresh_fn)(void *ctx);

/// 新建转发器（listen_host 如 "127.0.0.1"，listen_port 如 18080）。
kp_forwarder *kp_forwarder_new(const char *listen_host, int listen_port,
                               const char *upstream_host, int upstream_port);

/// 更新凭证（线程安全，内部拷贝）。
void kp_forwarder_set_creds(kp_forwarder *fw, const char *guid, const char *token);

/// 更新 Queen/King 完整状态（凭证 + HTTP/HTTPS 代理池）。所有入参内部拷贝。
void kp_forwarder_set_king_state(kp_forwarder *fw,
                                 const char *guid,
                                 const char *qua2,
                                 const char *token,
                                 const char *qkey,
                                 const char *qtype,
                                 const char *const http_proxies[], size_t http_count,
                                 const char *const https_proxies[], size_t https_count);

/// 设置事件驱动刷新回调：上游 CONNECT 非 200/连接失败时调用，成功后重试一次。
void kp_forwarder_set_refresh_hook(kp_forwarder *fw, kp_refresh_fn fn, void *ctx);

/// 启动监听线程。返回 0 成功。
int kp_forwarder_start(kp_forwarder *fw);

/// 停止并关闭。
void kp_forwarder_stop(kp_forwarder *fw);

/// 释放。
void kp_forwarder_free(kp_forwarder *fw);

/// 当前是否在监听。
int kp_forwarder_is_running(kp_forwarder *fw);

/// 监听端口。
int kp_forwarder_port(kp_forwarder *fw);

/// 转发器诊断统计。
typedef struct {
    uint64_t http_requests;
    uint64_t https_connects;
    uint64_t direct_fallbacks;
    uint64_t refresh_calls;
    uint64_t proxy_errors;
} kp_forwarder_stats;

void kp_forwarder_get_stats(kp_forwarder *fw, kp_forwarder_stats *stats);

/// 最近触发直连兜底的目标域名（环形缓冲，最多 16 条）。
int kp_forwarder_direct_host_count(kp_forwarder *fw);
int kp_forwarder_get_direct_host(kp_forwarder *fw, int index,
                                 char *out, size_t out_cap);

// ---------- 调试日志 ----------
/// 宿主注册日志回调（每步网络操作都会输出，真机调试用）
void kp_set_debug_logger(void (*fn)(const char *line));

/// 开关详细调试日志（默认关闭，避免频繁写日志）
void kp_set_debug_enabled(int enabled);
int kp_debug_enabled(void);

/// 取近期诊断（环形缓冲，最近 8 条，换行分隔；API 失败时回传给前端）
void kp_debug_recent(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* KPKIngCore_h */
