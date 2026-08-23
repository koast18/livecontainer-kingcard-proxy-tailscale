//
//  KPKIngCore.c
//  LCProxyTweak
//
#include "KPKIngCore.h"
#include "KPKCrypto.h"

extern void proxychains_write_log(char *str, ...);
#include "Version.h"
#include "KPSocketHook.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <poll.h>
#include <time.h>

// 王卡网关/代理期望的 UA（参考 https://ss.y4cc.cc/txwk 的 wanka 配置）
#define KP_KING_UA "okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 13; Redmi K50 5G Build/RKQ1.200826.002)"

// 转发器活跃客户端/线程上限：防止高速下载并发连接风暴创建过量线程
// （iOS 对线程数/栈内存有硬限制，超限会整个 App 闪退）。
#define KP_FORWARDER_MAX_CLIENTS 64

// ---------- 调试日志（宿主注册回调，真机可逐行定位） ----------
static void (*g_kp_dbg_log)(const char *line) = NULL;
static char g_kp_dbg_recent[8][512];   // 近期诊断环形缓冲（API 失败时回传）
static int g_kp_dbg_recent_n = 0;
static volatile int g_kp_dbg_enabled = 0; // 默认关闭，避免频繁写日志；热路径读取不加锁
static pthread_mutex_t g_kp_dbg_lock = PTHREAD_MUTEX_INITIALIZER;  // 多线程安全

void kp_set_debug_logger(void (*fn)(const char *line)) {
    pthread_mutex_lock(&g_kp_dbg_lock);
    g_kp_dbg_log = fn;
    pthread_mutex_unlock(&g_kp_dbg_lock);
}

void kp_set_debug_enabled(int enabled) {
    g_kp_dbg_enabled = enabled ? 1 : 0;
}

int kp_debug_enabled(void) {
    return g_kp_dbg_enabled;
}

void kp_debug_recent(char *out, size_t cap) {
    if (!out || cap == 0) return;
    pthread_mutex_lock(&g_kp_dbg_lock);
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < g_kp_dbg_recent_n && used < cap - 1; i++) {
        const char *line = g_kp_dbg_recent[i];
        size_t l = strlen(line);
        if (used + l + 2 > cap - 1) break;
        memcpy(out + used, line, l);
        used += l;
        out[used++] = '\n';
        out[used] = '\0';
    }
    pthread_mutex_unlock(&g_kp_dbg_lock);
}

void kp_dbg(const char *fmt, ...) {
    if (!kp_debug_enabled()) return;
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    localtime_r(&tv.tv_sec, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    char line[768];
    snprintf(line, sizeof(line), "[%s.%03d] %s", ts, (int)(tv.tv_usec / 1000), msg);

    proxychains_write_log("%s\n", line);

    pthread_mutex_lock(&g_kp_dbg_lock);
    if (g_kp_dbg_log) g_kp_dbg_log(line);
    // 环形缓冲：存最近 8 条（满则整体前移）
    int idx = g_kp_dbg_recent_n < 8 ? g_kp_dbg_recent_n++ : 7;
    if (g_kp_dbg_recent_n > 8) {
        for (int i = 1; i < 8; i++) memcpy(g_kp_dbg_recent[i - 1], g_kp_dbg_recent[i], 512);
        g_kp_dbg_recent_n = 8;
    }
    snprintf(g_kp_dbg_recent[idx], 512, "%s", line);
    pthread_mutex_unlock(&g_kp_dbg_lock);
}

#if defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>
#define KP_CLOSESOCK(fd) close(fd)
#else
#error "KPKIngCore supports POSIX only"
#endif

// ---------- 小工具 ----------

static void kp_trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void kp_trim_crlf(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\r' || s[n - 1] == '\n' || isspace((unsigned char)s[n - 1]))) {
        s[--n] = '\0';
    }
}

static int kp_snprintf_checked(char *out, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, cap, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

// ---------- 纯函数 ----------

// JSON 形式 {"guid":"...","token":"..."} 兜底提取
static int kp_parse_guid_token_json(const char *body, size_t len,
                                    char *guid, size_t guid_cap,
                                    char *token, size_t token_cap) {
    char tmp[1024];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, body, n);
    tmp[n] = '\0';
    char *g = strstr(tmp, "\"guid\"");
    char *t = strstr(tmp, "\"token\"");
    if (!g || !t) return -1;
    char *gv = strchr(g + 6, ':');
    char *tv = strchr(t + 7, ':');
    if (!gv || !tv) return -1;
    gv++; tv++;
    while (*gv && isspace((unsigned char)*gv)) gv++;
    while (*tv && isspace((unsigned char)*tv)) tv++;
    if (*gv != '"' || *tv != '"') return -1;
    gv++; tv++;
    char *ge = strchr(gv, '"');
    char *te = strchr(tv, '"');
    if (!ge || !te) return -1;
    size_t gl = (size_t)(ge - gv), tl = (size_t)(te - tv);
    if (gl == 0 || tl == 0 || gl >= guid_cap || tl >= token_cap) return -1;
    memcpy(guid, gv, gl); guid[gl] = '\0';
    memcpy(token, tv, tl); token[tl] = '\0';
    return 0;
}

int kp_parse_guid_token(const char *body, size_t len, char *guid, size_t guid_cap,
                        char *token, size_t token_cap) {
    if (!body || !guid || !token || guid_cap < 1 || token_cap < 1) return -1;
    char tmp[512];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, body, n);
    tmp[n] = '\0';
    kp_trim(tmp);

    // 逗号分隔形式 "GUID,TOKEN"（字符校验宽松：字母数字及常见 token 符号；
    // 拼接魔改域名 Host 时再做严格校验 kp_validate_creds_for_host）
    char *comma = strchr(tmp, ',');
    if (comma) {
        *comma = '\0';
        char *g = tmp;
        char *t = comma + 1;
        kp_trim_crlf(g);
        kp_trim_crlf(t);
        if (strlen(g) > 0 && strlen(t) > 0 &&
            strlen(g) < guid_cap && strlen(t) < token_cap) {
            for (const char *p = g; *p; p++) if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.' && *p != '+' && *p != '/' && *p != '=') goto not_comma;
            for (const char *p = t; *p; p++) if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.' && *p != '+' && *p != '/' && *p != '=') goto not_comma;
            strcpy(guid, g);
            strcpy(token, t);
            return 0;
        }
    }
not_comma:
    // JSON 形式兜底
    if (kp_parse_guid_token_json(body, len, guid, guid_cap, token, token_cap) == 0) {
        return 0;
    }
    return -1;
}

int kp_validate_creds_for_host(const char *guid, const char *token) {
    if (!guid || !token || guid[0] == '\0' || token[0] == '\0') return -1;
    for (const char *p = guid; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') return -1;
    }
    for (const char *p = token; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') return -1;
    }
    return 0;
}

// 生成 body 结构指纹（不泄露内容）：alnum→'A'，可打印原样，不可打印→'.'
// 同时分析逗号解析失败原因。原因码：1=无逗号非JSON 2=段空 3=段超容量 4=含非法字符 5=其他
void kp_analyze_body(const char *body, size_t len,
                     size_t guid_cap, size_t token_cap,
                     char *struct_out, size_t struct_cap,
                     int *fail_reason, int *fail_pos) {
    if (struct_out && struct_cap > 0) struct_out[0] = '\0';
    if (fail_reason) *fail_reason = 0;
    if (fail_pos) *fail_pos = -1;
    if (!body) {
        if (fail_reason) *fail_reason = 5;
        return;
    }
    size_t so = 0;
    if (struct_out) {
        for (size_t i = 0; i < len && so + 1 < struct_cap; i++) {
            unsigned char c = (unsigned char)body[i];
            if (isalnum(c)) struct_out[so++] = 'A';
            else if (c >= 0x20 && c <= 0x7E) struct_out[so++] = (char)c;
            else struct_out[so++] = '.';
        }
        struct_out[so] = '\0';
    }
    // 失败原因分析（与 kp_parse_guid_token 相同的判定路径）
    char tmp[512];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, body, n);
    tmp[n] = '\0';
    kp_trim(tmp);
    char *comma = strchr(tmp, ',');
    if (!comma) {
        if (fail_reason) *fail_reason = 1;
        return;
    }
    *comma = '\0';
    char *g = tmp;
    char *t = comma + 1;
    kp_trim_crlf(g);
    kp_trim_crlf(t);
    size_t gl = strlen(g), tl = strlen(t);
    if (gl == 0 || tl == 0) {
        if (fail_reason) *fail_reason = 2;
        if (fail_pos) *fail_pos = (int)(gl == 0 ? 0 : 1 + (int)gl);
        return;
    }
    if (gl >= guid_cap || tl >= token_cap) {
        if (fail_reason) *fail_reason = 3;
        if (fail_pos) *fail_pos = (int)(gl >= guid_cap ? gl : 1 + gl + tl);
        return;
    }
    for (size_t i = 0; i < gl; i++) {
        unsigned char c = (unsigned char)g[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '+' && c != '/' && c != '=') {
            if (fail_reason) *fail_reason = 4;
            if (fail_pos) *fail_pos = (int)i;
            return;
        }
    }
    for (size_t i = 0; i < tl; i++) {
        unsigned char c = (unsigned char)t[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '+' && c != '/' && c != '=') {
            if (fail_reason) *fail_reason = 4;
            if (fail_pos) *fail_pos = (int)(1 + gl + i);
            return;
        }
    }
    // 全部通过则不应有失败
    if (fail_reason) *fail_reason = 0;
}

int kp_build_login_host(const char *guid, const char *token, char *out, size_t out_cap) {
    if (!guid || !token || !out) return -1;
    if (kp_validate_creds_for_host(guid, token) != 0) return -1; // 拼 Host 前必须 hostname 安全
    // 2026：魔改域名 {guid}.{token}.iikira.com.token 已被网关淘汰（CONNECT 静默挂起）；
    // 现网网关识别 iikira.com 裸域名 + Q-GUID/Q-Token 头即完成会话激活（本地实测 CONNECT 200）。
    return kp_snprintf_checked(out, out_cap, "iikira.com");
}

int kp_build_connect_request(const char *target_host, int target_port,
                             const char *guid, const char *token,
                             char *out, size_t out_cap) {
    if (!target_host || !out) return -1;
    // 标准 CONNECT + Q-GUID/Q-Token/User-Agent 头（代理校验/免流识别）
    return kp_snprintf_checked(out, out_cap,
        "CONNECT %s:%d HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Q-GUID: %s\r\n"
        "Q-Token: %s\r\n"
        "User-Agent: " KP_KING_UA "\r\n"
        "\r\n",
        target_host, target_port, target_host, target_port, guid, token);
}

int kp_parse_connect_line(const char *line, size_t len, char *host, size_t host_cap, int *port) {
    if (!line || !host || !port) return -1;
    size_t n = len < 512 ? len : 511;
    char tmp[512];
    memcpy(tmp, line, n);
    tmp[n] = '\0';
    // 只解析第一行，避免把 Host:/Q-GUID:/Q-Token: 等 header 里的冒号算进去。
    char *eol = strchr(tmp, '\r');
    if (eol) *eol = '\0';
    eol = strchr(tmp, '\n');
    if (eol) *eol = '\0';
    kp_trim(tmp);
    if (strncmp(tmp, "CONNECT ", 8) != 0) return -1;

    const char *rest = tmp + 8;
    const char *space = strchr(rest, ' ');
    size_t alen = space ? (size_t)(space - rest) : strlen(rest);
    if (alen == 0 || alen >= 256 || alen >= host_cap) return -1;

    char authority[256];
    memcpy(authority, rest, alen);
    authority[alen] = '\0';

    const char *colon = strrchr(authority, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - authority);
    if (hl >= host_cap) return -1;
    memcpy(host, authority, hl);
    host[hl] = '\0';
    if (hl > 2 && host[0] == '[' && host[hl - 1] == ']') {
        host[hl - 1] = '\0';
        memmove(host, host + 1, hl - 1);
    }
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port = p;
    return 0;
}

int kp_response_is_2xx(const char *buf, size_t len) {
    if (!buf || len < 12) return 0;
    if (strncmp(buf, "HTTP/", 5) != 0) return 0;
    const char *sp = strchr(buf, ' ');
    if (!sp) return 0;
    sp++;
    if (sp[0] == '2') return 1;
    return 0;
}

// gzip/zlib 解压（自动识别 gzip 头）
static int kp_gunzip(const char *src, size_t srclen, char *dst, size_t dstcap, size_t *dstlen) {
    if (!src || !dst || !dstlen) return -1;
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return -1; // 15+32 = 自动 gzip/zlib
    zs.next_in = (Bytef *)(uintptr_t)src;
    zs.avail_in = (uInt)srclen;
    zs.next_out = (Bytef *)dst;
    zs.avail_out = (uInt)dstcap;
    int rc = inflate(&zs, Z_FINISH);
    *dstlen = dstcap - zs.avail_out;
    inflateEnd(&zs);
    return (rc == Z_OK || rc == Z_STREAM_END) ? 0 : -1;
}

// 从响应头中取指定头字段（小写比较）
static void kp_header_value(const char *buf, size_t len, const char *name,
                            char *out, size_t out_cap) {
    out[0] = '\0';
    if (!buf) return;
    size_t namelen = strlen(name);
    const char *end = buf + (len < 65536 ? len : 65536);
    const char *p = buf;
    while (p < end) {
        const char *eol = strstr(p, "\r\n");
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (linelen >= namelen && strncasecmp(p, name, namelen) == 0 && p[namelen] == ':') {
            const char *v = p + namelen + 1;
            size_t vlen = linelen - namelen - 1;
            while (vlen > 0 && isspace((unsigned char)v[0])) { v++; vlen--; }
            while (vlen > 0 && (v[vlen - 1] == '\r' || isspace((unsigned char)v[vlen - 1]))) vlen--;
            size_t cp = vlen < out_cap - 1 ? vlen : out_cap - 1;
            memcpy(out, v, cp);
            out[cp] = '\0';
            return;
        }
        if (!eol) break;
        p = eol + 2;
    }
}

int kp_parse_http_response(const char *buf, size_t len,
                           char *body, size_t body_cap, size_t *body_len,
                           kp_fetch_diag *diag) {
    if (diag) kp_fetch_diag_init(diag);
    if (!buf) return -1;
    // 状态行
    if (diag) {
        const char *eol = strstr(buf, "\r\n");
        size_t sl = eol ? (size_t)(eol - buf) : (len < 127 ? len : 127);
        if (sl >= sizeof(diag->status_line)) sl = sizeof(diag->status_line) - 1;
        memcpy(diag->status_line, buf, sl);
        diag->status_line[sl] = '\0';
    }
    // Content-Encoding + Location
    if (diag) {
        kp_header_value(buf, len, "content-encoding", diag->content_encoding,
                        sizeof(diag->content_encoding));
        kp_header_value(buf, len, "location", diag->location, sizeof(diag->location));
    }
    // 分离 header/body
    char *sep = strstr(buf, "\r\n\r\n");
    if (!sep) return -1;
    const char *raw = sep + 4;
    size_t rawlen = len - (size_t)(raw - buf);
    if (diag) {
        size_t bh = rawlen < sizeof(diag->body_head) - 1 ? rawlen : sizeof(diag->body_head) - 1;
        memcpy(diag->body_head, raw, bh);
        diag->body_head[bh] = '\0';
        diag->body_len = (unsigned int)rawlen;
    }
    char enc[64] = {0};
    kp_header_value(buf, len, "content-encoding", enc, sizeof(enc));
    if (enc[0] != '\0' && strstr(enc, "gzip")) {
        size_t dl = 0;
        if (kp_gunzip(raw, rawlen, body, body_cap, &dl) != 0) return -1;
        *body_len = dl;
    } else {
        size_t cp = rawlen < body_cap ? rawlen : body_cap;
        memcpy(body, raw, cp);
        *body_len = cp;
    }
    return 0;
}

// ---------- POSIX socket 工具 ----------

static int kp_connect_host(const char *host, int port, int timeout_ms) {
    kp_dbg("[conn] 开始连接 %s:%d timeout=%dms", host, port, timeout_ms);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    // 自身连接绕过 socket 层代理劫持（保持直连/上游豁免语义）。
    // 必须在 getaddrinfo 之前开启：否则 proxy_dns 会先返回内部假 IP，
    // 随后 bypass 的 connect 会去连 224.x.x.x 而失败。
    kp_socket_set_bypass(1);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        kp_socket_set_bypass(0);
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (timeout_ms > 0) {
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        KP_CLOSESOCK(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    kp_socket_set_bypass(0);
    kp_dbg("[conn] %s:%d -> fd=%d", host, port, fd);
    return fd;
}

static int kp_send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, buf + off, len - off, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int kp_recv_until(int fd, char *buf, size_t cap, size_t *got, int timeout_ms) {
    (void)timeout_ms;
    size_t off = 0;
    while (off < cap - 1) {
        ssize_t r = recv(fd, buf + off, cap - 1 - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    buf[off] = '\0';
    *got = off;
    return off > 0 ? 0 : -1;
}

// 读完整响应（含 body，直到连接关闭或 Content-Length 满足）
static int kp_recv_response(int fd, char *buf, size_t cap, size_t *got) {
    size_t off = 0;
    int header_done = 0;
    size_t content_length = (size_t)-1;
    while (off < cap - 1) {
        ssize_t r = recv(fd, buf + off, cap - 1 - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
        buf[off] = '\0';
        if (!header_done) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                header_done = 1;
                char cl[32] = {0};
                kp_header_value(buf, off, "content-length", cl, sizeof(cl));
                if (cl[0]) content_length = (size_t)atol(cl);
            }
        }
        if (header_done && content_length != (size_t)-1) {
            char *sep = strstr(buf, "\r\n\r\n");
            size_t body_off = (size_t)(sep - buf) + 4;
            if (off - body_off >= content_length) break;
        }
    }
    buf[off] = '\0';
    *got = off;
    return off > 0 ? 0 : -1;
}

// 解析 http://host:port/path
static int kp_parse_url(const char *url, char *host, size_t host_cap,
                        int *port, const char **path) {
    if (!url || strncmp(url, "http://", 7) != 0) return -1;
    const char *rest = url + 7;
    const char *slash = strchr(rest, '/');
    size_t hostlen = slash ? (size_t)(slash - rest) : strlen(rest);
    if (hostlen >= host_cap) return -1;
    memcpy(host, rest, hostlen);
    host[hostlen] = '\0';
    *port = 80;
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        *port = atoi(colon + 1);
        if (*port <= 0) *port = 80;
    }
    *path = slash ? slash : "/";
    return 0;
}

// ---------- 取号 ----------

static int kp_do_fetch(int fd, const char *host, const char *path,
                       char *guid, size_t guid_cap, char *token, size_t token_cap,
                       int timeout_ms, kp_fetch_diag *diag,
                       int *status_out) {
    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\n"
             "Host: %s\r\n"
             "User-Agent: " KP_KING_UA "\r\n"
             "Accept-Encoding: identity\r\n"
             "Connection: close\r\n\r\n",
             path, host);
    int rc = -1;
    if (kp_send_all(fd, req, strlen(req)) == 0) {
        char buf[8192];
        size_t got = 0;
        if (kp_recv_response(fd, buf, sizeof(buf), &got) == 0) {
            int code = 0;
            if (strncmp(buf, "HTTP/", 5) == 0 && strchr(buf, ' ')) {
                code = atoi(strchr(buf, ' ') + 1);
            }
            kp_dbg("[fetch] GET %s %s -> HTTP %d, recv=%zu bytes", path, host, code, got);
            if (status_out) *status_out = code;
            char body[4096];
            size_t bodylen = 0;
            if (kp_parse_http_response(buf, got, body, sizeof(body), &bodylen, diag) == 0) {
                if (kp_parse_guid_token(body, bodylen, guid, guid_cap, token, token_cap) == 0) {
                    rc = 0;
                } else {
                    rc = -2;
                    if (diag) {
                        kp_analyze_body(body, bodylen, guid_cap, token_cap,
                                        diag->body_struct, sizeof(diag->body_struct),
                                        &diag->parse_fail_reason, &diag->parse_fail_pos);
                    }
                }
            } else {
                rc = -2;
            }
        }
    }
    return rc;
}

// 处理单次 GET（经已建立连接），含重定向跟随（≤4 跳）。diag 记录最后一次响应。
// base_host 用于相对 Location 拼接。返回 0=取号成功；-1 网络/重定向失败；-2 解析失败。
static int kp_fetch_with_redirects(int (*open_conn)(const char *host, int port, int timeout_ms, void *ctx),
                                   void *ctx, const char *initial_url,
                                   char *guid, size_t guid_cap, char *token, size_t token_cap,
                                   int timeout_ms, kp_fetch_diag *diag) {
    char url[512];
    snprintf(url, sizeof(url), "%s", initial_url ? initial_url : "");
    int last_rc = -1;
    for (int hop = 0; hop < 4; hop++) {
        char host[256];
        int port = 0;
        const char *path = NULL;
        if (kp_parse_url(url, host, sizeof(host), &port, &path) != 0) return -1;
        kp_fetch_diag d;
        kp_fetch_diag_init(&d);
        int fd = open_conn(host, port, timeout_ms, ctx);
        if (fd < 0) {
            if (diag) *diag = d;
            return -1;
        }
        int status = 0;
        int rc = kp_do_fetch(fd, host, path, guid, guid_cap, token, token_cap,
                             timeout_ms, &d, &status);
        if (fd >= 0) KP_CLOSESOCK(fd);
        last_rc = rc;
        if (rc == 0 || status == 0 || status < 300 || status >= 400) {
            if (diag) *diag = d;
            return rc;
        }
        // 3xx 重定向
        if (d.location[0] == '\0') {
            if (diag) *diag = d;
            return -1;
        }
        if (strncmp(d.location, "https://", 8) == 0) {
            // 不支持 TLS，无法跟随 https 重定向
            if (diag) *diag = d;
            return -1;
        }
        if (strncmp(d.location, "http://", 7) == 0) {
            snprintf(url, sizeof(url), "%s", d.location);
        } else if (d.location[0] == '/') {
            snprintf(url, sizeof(url), "http://%s%s", host, d.location);
        } else {
            snprintf(url, sizeof(url), "http://%s/%.200s", host, d.location);
        }
        if (diag) *diag = d;
    }
    return last_rc;
}

static int kp_open_direct(const char *host, int port, int timeout_ms, void *ctx) {
    (void)ctx;
    return kp_connect_host(host, port, timeout_ms);
}

int kp_fetch_guid_token(const char *refresh_url,
                        char *guid, size_t guid_cap,
                        char *token, size_t token_cap,
                        int timeout_ms, kp_fetch_diag *diag) {
    return kp_fetch_with_redirects(kp_open_direct, NULL, refresh_url,
                                   guid, guid_cap, token, token_cap, timeout_ms, diag);
}

struct proxy_ctx {
    const char *upstream_host;
    int upstream_port;
    const char *guid_hint;
    const char *token_hint;
};

// 经上游代理建立到目标 host:port 的 CONNECT 隧道
static int kp_open_via_proxy(const char *host, int port, int timeout_ms, void *ctxp) {
    struct proxy_ctx *ctx = ctxp;
    int fd = kp_connect_host(ctx->upstream_host, ctx->upstream_port, timeout_ms);
    if (fd < 0) return -1;
    char creq[1024];
    if (kp_build_connect_request(host, port,
                                 ctx->guid_hint ? ctx->guid_hint : "",
                                 ctx->token_hint ? ctx->token_hint : "",
                                 creq, sizeof(creq)) != 0 ||
        kp_send_all(fd, creq, strlen(creq)) != 0) {
        KP_CLOSESOCK(fd);
        return -1;
    }
    kp_dbg("[proxy] CONNECT %s:%d 已发送，等待响应…", host, port);
    char rbuf[2048];
    size_t rgot = 0;
    if (kp_recv_until(fd, rbuf, sizeof(rbuf), &rgot, timeout_ms) != 0 ||
        !kp_response_is_2xx(rbuf, rgot)) {
        kp_dbg("[proxy] CONNECT %s:%d 失败: recv=%zu resp=%.80s", host, port, rgot, rgot ? rbuf : "(无响应/超时)");
        KP_CLOSESOCK(fd);
        return -1;
    }
    kp_dbg("[proxy] CONNECT %s:%d 隧道建立: %.60s", host, port, rbuf);
    return fd;
}

int kp_fetch_guid_token_via_proxy(const char *upstream_host, int upstream_port,
                                  const char *refresh_url,
                                  const char *guid_hint, const char *token_hint,
                                  char *guid, size_t guid_cap,
                                  char *token, size_t token_cap,
                                  int timeout_ms, kp_fetch_diag *diag) {
    struct proxy_ctx ctx = { upstream_host, upstream_port, guid_hint, token_hint };
    return kp_fetch_with_redirects(kp_open_via_proxy, &ctx, refresh_url,
                                   guid, guid_cap, token, token_cap, timeout_ms, diag);
}

static int kp_parse_status_code(const char *buf, size_t len);

int kp_http_get_via_proxy(const char *upstream_host, int upstream_port,
                          const char *target_host, int target_port, const char *path,
                          const char *guid, const char *token,
                          int timeout_ms, char *out, size_t out_cap) {
    kp_dbg("[ipcheck] 入口: 上游=%s:%d 目标=%s:%d%s guid=%c… token=%c…",
           upstream_host ? upstream_host : "(null)", upstream_port,
           target_host ? target_host : "(null)", target_port, path ? path : "",
           guid && guid[0] ? guid[0] : '?', token && token[0] ? token[0] : '?');
    if (!upstream_host || !target_host) { kp_dbg("[ipcheck] 参数缺失"); return -1; }
    if (out && out_cap > 0) out[0] = '\0';

    char cur_host[256];
    int cur_port = target_port;
    char cur_path[512];
    snprintf(cur_host, sizeof(cur_host), "%s", target_host);
    snprintf(cur_path, sizeof(cur_path), "%s", path ? path : "/");

    for (int hop = 0; hop < 4; hop++) {
        struct proxy_ctx ctx = { upstream_host, upstream_port, guid, token };
        int fd = kp_open_via_proxy(cur_host, cur_port, timeout_ms, &ctx);
        if (fd < 0) return -1;
        char req[512];
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: " KPTWEAK_UA "\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
                 cur_path, cur_host);
        int rc = -1;
        if (kp_send_all(fd, req, strlen(req)) == 0) {
            char buf[4096];
            size_t got = 0;
            if (kp_recv_response(fd, buf, sizeof(buf), &got) == 0) {
                int code = kp_parse_status_code(buf, got);
                if (code >= 200 && code < 300) {
                    char body[2048];
                    size_t blen = 0;
                    kp_fetch_diag d;
                    kp_fetch_diag_init(&d);
                    if (kp_parse_http_response(buf, got, body, sizeof(body), &blen, &d) == 0) {
                        if (out && out_cap > 0) {
                            size_t cp = blen < out_cap - 1 ? blen : out_cap - 1;
                            memcpy(out, body, cp);
                            out[cp] = '\0';
                        }
                        rc = 0;
                    }
                } else if (code >= 300 && code < 400) {
                    char loc[256];
                    kp_header_value(buf, got, "location", loc, sizeof(loc));
                    if (strncmp(loc, "http://", 7) == 0) {
                        char rhost[256];
                        int rport = 80;
                        const char *rpath = NULL;
                        if (kp_parse_url(loc, rhost, sizeof(rhost), &rport, &rpath) == 0) {
                            snprintf(cur_host, sizeof(cur_host), "%s", rhost);
                            cur_port = rport;
                            snprintf(cur_path, sizeof(cur_path), "%s", rpath ? rpath : "/");
                            KP_CLOSESOCK(fd);
                            continue;
                        }
                    }
                }
            }
        }
        KP_CLOSESOCK(fd);
        kp_dbg("[ipcheck] 完成: rc=%d out=%.40s", rc, out && out[0] ? out : "(空)");
        return rc;
    }
    kp_dbg("[ipcheck] 完成: 重定向过多");
    return -1;
}

int kp_http_get_direct(const char *target_host, int target_port, const char *path,
                       int timeout_ms, char *out, size_t out_cap) {
    kp_dbg("[ipcheck/direct] 入口: 目标=%s:%d%s", target_host ? target_host : "(null)", target_port, path ? path : "");
    if (!target_host) { kp_dbg("[ipcheck/direct] 参数缺失"); return -1; }
    if (out && out_cap > 0) out[0] = '\0';

    char cur_host[256];
    int cur_port = target_port;
    char cur_path[512];
    snprintf(cur_host, sizeof(cur_host), "%s", target_host);
    snprintf(cur_path, sizeof(cur_path), "%s", path ? path : "/");

    for (int hop = 0; hop < 4; hop++) {
        int fd = kp_connect_host(cur_host, cur_port, timeout_ms);
        if (fd < 0) return -1;
        char req[512];
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: " KPTWEAK_UA "\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
                 cur_path, cur_host);
        int rc = -1;
        if (kp_send_all(fd, req, strlen(req)) == 0) {
            char buf[4096];
            size_t got = 0;
            if (kp_recv_response(fd, buf, sizeof(buf), &got) == 0) {
                int code = kp_parse_status_code(buf, got);
                if (code >= 200 && code < 300) {
                    char body[2048];
                    size_t blen = 0;
                    kp_fetch_diag d;
                    kp_fetch_diag_init(&d);
                    if (kp_parse_http_response(buf, got, body, sizeof(body), &blen, &d) == 0) {
                        if (out && out_cap > 0) {
                            size_t cp = blen < out_cap - 1 ? blen : out_cap - 1;
                            memcpy(out, body, cp);
                            out[cp] = '\0';
                        }
                        rc = 0;
                    }
                } else if (code >= 300 && code < 400) {
                    char loc[256];
                    kp_header_value(buf, got, "location", loc, sizeof(loc));
                    if (strncmp(loc, "http://", 7) == 0) {
                        char rhost[256];
                        int rport = 80;
                        const char *rpath = NULL;
                        if (kp_parse_url(loc, rhost, sizeof(rhost), &rport, &rpath) == 0) {
                            snprintf(cur_host, sizeof(cur_host), "%s", rhost);
                            cur_port = rport;
                            snprintf(cur_path, sizeof(cur_path), "%s", rpath ? rpath : "/");
                            KP_CLOSESOCK(fd);
                            continue;
                        }
                    }
                }
            }
        }
        KP_CLOSESOCK(fd);
        kp_dbg("[ipcheck/direct] 完成: rc=%d out=%.40s", rc, out && out[0] ? out : "(空)");
        return rc;
    }
    kp_dbg("[ipcheck/direct] 完成: 重定向过多");
    return -1;
}

int kp_http_post_direct_len(const char *url,
                            const char *const headers[],
                            const char *body, size_t body_len,
                            int timeout_ms,
                            char *out, size_t out_cap,
                            size_t *out_len) {
    if (!url || !out || out_cap == 0) return -1;
    out[0] = '\0';
    char host[256];
    int port = 80;
    const char *path = NULL;
    if (kp_parse_url(url, host, sizeof(host), &port, &path) != 0) {
        kp_dbg("[post-direct] 非 http URL: %s", url);
        return -2;
    }
    int fd = kp_connect_host(host, port, timeout_ms);
    if (fd < 0) {
        kp_dbg("[post-direct] 连接失败 %s:%d", host, port);
        return -1;
    }
    // 手拼请求：固定头 + 调用方头 + Content-Length/Body。
    size_t hdrs_len = 0;
    for (int i = 0; headers && headers[i]; i++) hdrs_len += strlen(headers[i]) + 2;
    size_t need = strlen(path) + strlen(host) + hdrs_len + body_len + 256;
    char *req = (char *)malloc(need);
    if (!req) { KP_CLOSESOCK(fd); return -1; }
    size_t off = (size_t)snprintf(req, need,
                                  "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\n",
                                  path, host, body_len);
    for (int i = 0; headers && headers[i]; i++)
        off += (size_t)snprintf(req + off, need - off, "%s\r\n", headers[i]);
    off += (size_t)snprintf(req + off, need - off, "\r\n");
    if (body && body_len) { memcpy(req + off, body, body_len); off += body_len; }

    int rc = -1;
    if (kp_send_all(fd, req, off) == 0) {
        size_t got = 0;
        if (kp_recv_response(fd, out, out_cap, &got) == 0 && got > 0) {
            rc = 0;
            // 响应体可能含 \0（protobuf），调用方必须用真实长度而非 strlen。
            if (out_len) *out_len = got;
        }
    }
    free(req);
    KP_CLOSESOCK(fd);
    kp_dbg("[post-direct] %s -> rc=%d len=%zu", url, rc, rc == 0 ? (out_len ? *out_len : 0) : 0);
    return rc;
}

int kp_http_post_direct(const char *url,
                        const char *const headers[],
                        const char *body, size_t body_len,
                        int timeout_ms,
                        char *out, size_t out_cap) {
    return kp_http_post_direct_len(url, headers, body, body_len,
                                   timeout_ms, out, out_cap, NULL);
}

int kp_fetch_guid_token_best(const char *refresh_url,
                             const char *upstream_host, int upstream_port,
                             const char *guid_hint, const char *token_hint,
                             int attempts, int backoff_ms, int timeout_ms,
                             char *guid, size_t guid_cap,
                             char *token, size_t token_cap,
                             kp_fetch_diag *diag, char *last_source, size_t last_source_cap) {
    if (last_source && last_source_cap > 0) last_source[0] = '\0';
    if (attempts < 1) attempts = 1;
    int last_rc = -1;
    for (int i = 0; i < attempts; i++) {
        kp_fetch_diag d;
        kp_fetch_diag_init(&d);
        // 第 1 级：经上游代理
        int rc = kp_fetch_guid_token_via_proxy(upstream_host, upstream_port, refresh_url,
                                               guid_hint, token_hint,
                                               guid, guid_cap, token, token_cap,
                                               timeout_ms, &d);
        last_rc = rc;
        if (rc == 0) {
            if (last_source && last_source_cap > 0) snprintf(last_source, last_source_cap, "proxy");
            if (diag) *diag = d;
            return 0;
        }
        // 第 2 级：直连
        int rc2 = kp_fetch_guid_token(refresh_url, guid, guid_cap, token, token_cap,
                                      timeout_ms, &d);
        last_rc = rc2;
        if (rc2 == 0) {
            if (last_source && last_source_cap > 0) snprintf(last_source, last_source_cap, "direct");
            if (diag) *diag = d;
            return 0;
        }
        if (diag) *diag = d;
        if (i + 1 < attempts && backoff_ms > 0) {
            struct timespec ts = { backoff_ms / 1000, (backoff_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    return last_rc; // 返回真实最后一次 rc（-1 网络/重定向，-2 解析）
}

// 尝试 1：CONNECT 魔改域名:80（PLAN 原方案；隧道建立即激活信号）
static int kp_login_via_connect(const char *upstream_host, int upstream_port,
                                const char *login_host, const char *guid, const char *token,
                                int timeout_ms, char *diag_status, size_t diag_cap) {
    if (diag_status && diag_cap > 0) diag_status[0] = '\0';
    int fd = kp_connect_host(upstream_host, upstream_port, timeout_ms);
    if (fd < 0) {
        if (diag_status && diag_cap > 0) snprintf(diag_status, diag_cap, "(connect upstream failed)");
        return -1;
    }
    int rc = -1;
    char creq[1024];
    if (kp_build_connect_request(login_host, 80, guid, token, creq, sizeof(creq)) == 0 &&
        kp_send_all(fd, creq, strlen(creq)) == 0) {
        char buf[2048];
        size_t got = 0;
        if (kp_recv_until(fd, buf, sizeof(buf), &got, timeout_ms) == 0) {
            if (diag_status && diag_cap > 0) {
                size_t sl = got < diag_cap - 1 ? got : diag_cap - 1;
                memcpy(diag_status, buf, sl);
                diag_status[sl] = '\0';
            }
            // 网关 2xx = 隧道建立 = 免流激活成功
            if (kp_response_is_2xx(buf, got)) rc = 0;
        } else if (diag_status && diag_cap > 0) {
            snprintf(diag_status, diag_cap, "(no response)");
        }
    }
    KP_CLOSESOCK(fd);
    return rc;
}

// 尝试 2：绝对 URI 直发网关（boxjs fetch 行为；不要求特定状态码，收到响应即算激活）
static int kp_login_via_absuri(const char *upstream_host, int upstream_port,
                               const char *login_host, const char *guid, const char *token,
                               int timeout_ms, char *diag_status, size_t diag_cap) {
    if (!upstream_host || !login_host || !guid || !token) return -1;
    if (diag_status && diag_cap > 0) diag_status[0] = '\0';
    int fd = kp_connect_host(upstream_host, upstream_port, timeout_ms);
    if (fd < 0) {
        if (diag_status && diag_cap > 0) snprintf(diag_status, diag_cap, "(connect upstream failed)");
        return -1;
    }
    int rc = -1;
    char get[512];
    snprintf(get, sizeof(get),
             "GET http://%s/ HTTP/1.0\r\n"
             "Host: %s\r\n"
             "User-Agent: " KP_KING_UA "\r\n"
             "Connection: close\r\n\r\n",
             login_host, login_host);
    if (kp_send_all(fd, get, strlen(get)) == 0) {
        char buf[2048];
        size_t got = 0;
        if (kp_recv_until(fd, buf, sizeof(buf), &got, timeout_ms) == 0) {
            rc = 0;
            if (diag_status && diag_cap > 0) {
                size_t sl = got < diag_cap - 1 ? got : diag_cap - 1;
                memcpy(diag_status, buf, sl);
                diag_status[sl] = '\0';
            }
        } else if (diag_status && diag_cap > 0) {
            snprintf(diag_status, diag_cap, "(no response)");
        }
    }
    KP_CLOSESOCK(fd);
    return rc;
}

int kp_login_via_proxy(const char *upstream_host, int upstream_port,
                       const char *login_host, const char *guid, const char *token,
                       int timeout_ms, char *diag_status, size_t diag_cap) {
    // 先 CONNECT（PLAN 方案），失败再绝对 URI（boxjs 方案）；diag 记录最后一次尝试
    int rc = kp_login_via_connect(upstream_host, upstream_port, login_host, guid, token,
                                  timeout_ms, diag_status, diag_cap);
    if (rc == 0) return 0;
    return kp_login_via_absuri(upstream_host, upstream_port, login_host, guid, token,
                               timeout_ms, diag_status, diag_cap);
}

int kp_probe_generate204(const char *upstream_host, int upstream_port,
                         const char *guid, const char *token, int timeout_ms) {
    if (!upstream_host || !guid || !token) return 0;
    int fd = kp_connect_host(upstream_host, upstream_port, timeout_ms);
    if (fd < 0) return 0;
    int ok = 0;
    char req[1024];
    if (kp_build_connect_request("www.gstatic.com", 80, guid, token, req, sizeof(req)) != 0) {
        KP_CLOSESOCK(fd);
        return 0;
    }
    if (kp_send_all(fd, req, strlen(req)) == 0) {
        char buf[2048];
        size_t got = 0;
        if (kp_recv_until(fd, buf, sizeof(buf), &got, timeout_ms) == 0 && kp_response_is_2xx(buf, got)) {
            char get[512];
            snprintf(get, sizeof(get), "GET /generate_204 HTTP/1.0\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n");
            if (kp_send_all(fd, get, strlen(get)) == 0) {
                char rbuf[1024];
                size_t rg = 0;
                if (kp_recv_until(fd, rbuf, sizeof(rbuf), &rg, timeout_ms) == 0) {
                    if (strstr(rbuf, " 204 ")) ok = 1;
                }
            }
        }
    }
    KP_CLOSESOCK(fd);
    return ok;
}

// ---------- 转发器服务器 ----------

#define KP_MAX_PROXY_POOL 32
typedef struct {
    char items[KP_MAX_PROXY_POOL][64];
    int count;
    int rr;
} kp_proxy_pool;

#define KP_DIRECT_HOST_LOG_MAX 16

struct kp_forwarder {
    char listen_host[64];
    int listen_port;
    char upstream_host[128];
    int upstream_port;

    char guid[128];
    char token[128];
    char qua2[256];
    char qkey[128];
    char qtype[32];

    kp_proxy_pool http_pool;   // queen_http（iptype 15）
    kp_proxy_pool https_pool;  // queen_https（iptype 16）
    pthread_mutex_t cred_mutex;

    uint64_t stat_http_requests;
    uint64_t stat_https_connects;
    uint64_t stat_direct_fallbacks;
    uint64_t stat_refresh_calls;
    uint64_t stat_proxy_errors;

    char direct_host_log[KP_DIRECT_HOST_LOG_MAX][128];
    int direct_host_log_count;
    int direct_host_log_rr;

    kp_refresh_fn refresh_fn;
    void *refresh_ctx;

    int listen_fd;
    int running;
    pthread_t thread;
    // 活跃客户端/转发线程计数：防止高速下载并发连接风暴瞬间创建过量线程，
    // 耗尽系统线程/栈内存导致整个 App 闪退。达到上限时拒绝新连接（503）。
    // client_fds 记录当前活跃连接，kp_forwarder_stop 会 shutdown 它们让阻塞的
    // recv/poll 返回，然后等待 active_clients 归零再释放，避免 use-after-free。
    pthread_mutex_t client_lock;
    pthread_cond_t client_cond;
    int active_clients;
    int client_fds[KP_FORWARDER_MAX_CLIENTS];
    int client_fd_count;
};

struct client_arg {
    kp_forwarder *fw;
    int fd;
};

static void kp_forwarder_creds(kp_forwarder *fw, char *guid, size_t gc, char *token, size_t tc);
static void kp_forwarder_record_direct_host(kp_forwarder *fw, const char *host) {
    if (!fw || !host || host[0] == '\0') return;
    int idx = fw->direct_host_log_rr % KP_DIRECT_HOST_LOG_MAX;
    fw->direct_host_log_rr++;
    snprintf(fw->direct_host_log[idx], sizeof(fw->direct_host_log[idx]), "%s", host);
    if (fw->direct_host_log_count < KP_DIRECT_HOST_LOG_MAX) fw->direct_host_log_count++;
}

static void kp_forwarder_snapshot(kp_forwarder *fw,
                                  char *guid, size_t gc,
                                  char *token, size_t tc,
                                  char *qua2, size_t q2c,
                                  char *qkey, size_t qkc,
                                  char *qtype, size_t qtc);
static int kp_forwarder_refresh(kp_forwarder *fw);
static int kp_forwarder_refresh_retry(kp_forwarder *fw, int attempts, int backoff_ms);

// 解析 HTTP 代理绝对 URI 请求行："GET http://host[:port]/path HTTP/1.1"。成功返回 0。
int kp_parse_absolute_uri(const char *line, size_t len,
                                 char *method, size_t method_cap,
                                 char *host, size_t host_cap, int *port,
                                 char *path, size_t path_cap) {
    char tmp[1024];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, line, n);
    tmp[n] = '\0';
    char *eol = strchr(tmp, '\r');
    if (eol) *eol = '\0';
    char *sp = strchr(tmp, ' ');
    if (!sp) return -1;
    *sp = '\0';
    const char *m = tmp;
    const char *url = sp + 1;
    if (strncmp(url, "http://", 7) != 0) return -1;
    const char *rest = url + 7;
    const char *slash = strchr(rest, '/');
    const char *auth_end = slash ? slash : rest + strlen(rest);
    size_t hostlen = (size_t)(auth_end - rest);
    if (hostlen == 0 || hostlen >= host_cap) return -1;
    memcpy(host, rest, hostlen);
    host[hostlen] = '\0';
    *port = 80;
    char *colon = strrchr(host, ':');
    if (colon && colon[1] >= '0' && colon[1] <= '9' && strchr(colon + 1, ':') == NULL) {
        *port = atoi(colon + 1);
        *colon = '\0';
    }
    if (host[0] == '[') { // [::1]:port 形式
        char *close_b = strchr(host, ']');
        if (close_b) {
            memmove(host, host + 1, (size_t)(close_b - host - 1));
            host[close_b - host - 1] = '\0';
        }
    }
    const char *p = slash ? slash : "/";
    // path 截断到空格（去掉 " HTTP/1.1" 等）
    const char *psp = strchr(p, ' ');
    size_t plen = psp ? (size_t)(psp - p) : strlen(p);
    if (plen >= path_cap) plen = path_cap - 1;
    memcpy(path, p, plen);
    path[plen] = '\0';
    snprintf(method, method_cap, "%s", m);
    return 0;
}

// 重建请求：绝对 URI 行 → path 形式 + 补 Host + Connection: close
int kp_rebuild_proxy_request(const char *reqbuf, size_t reqlen,
                                    const char *method, const char *host, int port,
                                    const char *path,
                                    char *out, size_t out_cap) {
    const char *body = NULL;
    size_t bodylen = 0;
    const char *sep = strstr(reqbuf, "\r\n\r\n");
    if (sep) {
        body = sep + 4;
        bodylen = reqlen - (size_t)(body - reqbuf);
    }
    int n = snprintf(out, out_cap,
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Connection: close\r\n",
                     method, path, host, port);
    if (n <= 0 || (size_t)n >= out_cap) return -1;
    // 追加原始 headers（跳过第一行），过滤掉原 Host 行（避免重复，保留我们补的 host:port）
    const char *eol1 = strchr(reqbuf, '\r');
    if (eol1 && eol1[1] == '\n') {
        const char *h = eol1 + 2;
        const char *hend = sep ? sep : reqbuf + reqlen;
        const char *line = h;
        while (line < hend) {
            const char *le = strstr(line, "\r\n");
            const char *le2 = (le && le + 2 <= hend) ? le + 2 : hend;
            size_t ll = (size_t)(le2 - line);
            if (ll > 6 && strncasecmp(line, "Host:", 5) == 0) {
                line = le2;
                continue;
            }
            if ((size_t)n + ll + 2 >= out_cap) break;
            memcpy(out + n, line, ll);
            n += (int)ll;
            line = le2;
        }
    }
    if ((size_t)n + 2 + bodylen + 1 >= out_cap) return -1;
    out[n++] = '\r';
    out[n++] = '\n';
    if (body && bodylen > 0) {
        memcpy(out + n, body, bodylen);
        n += (int)bodylen;
    }
    out[n] = '\0';
    return n;
}

// 隧道内转发重建请求并泵响应
static void kp_http_forward(int up, int client, const char *req, size_t reqlen) {
    if (kp_send_all(up, req, reqlen) != 0) return;
    char buf[16384];
    ssize_t r;
    while ((r = recv(up, buf, sizeof(buf), 0)) > 0) {
        if (kp_send_all(client, buf, (size_t)r) != 0) break;
    }
}

// 单线程双向泵：用 poll 同时监听两个方向，避免每条 CONNECT 隧道创建 2 个线程。
// a_to_b/b_to_a 可为 NULL；计数器仅统计成功转发字节数。
static void kp_pipe_bidirectional_counted(int a, int b,
                                          uint64_t *a_to_b,
                                          uint64_t *b_to_a) {
    char buf[16384];
    struct pollfd pfds[2];
    int a_open = 1, b_open = 1;

    while (a_open || b_open) {
        pfds[0].fd = a_open ? a : -1;
        pfds[0].events = POLLIN;
        pfds[1].fd = b_open ? b : -1;
        pfds[1].events = POLLIN;
        int n = poll(pfds, 2, -1);
        if (n <= 0) break;

        if (pfds[0].fd >= 0 && (pfds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv(a, buf, sizeof(buf), 0);
            if (r > 0) {
                if (kp_send_all(b, buf, (size_t)r) != 0) {
                    a_open = 0;
                    b_open = 0;
                    break;
                }
                if (a_to_b) *a_to_b += (uint64_t)r;
            } else {
                a_open = 0;
                shutdown(b, SHUT_WR);
            }
        }
        if (pfds[1].fd >= 0 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = recv(b, buf, sizeof(buf), 0);
            if (r > 0) {
                if (kp_send_all(a, buf, (size_t)r) != 0) {
                    a_open = 0;
                    b_open = 0;
                    break;
                }
                if (b_to_a) *b_to_a += (uint64_t)r;
            } else {
                b_open = 0;
                shutdown(a, SHUT_WR);
            }
        }
    }
    // 双向结束后确保对端不再等待。
    shutdown(a, SHUT_RDWR);
    shutdown(b, SHUT_RDWR);
}

// ---------- Queen 代理池与请求构造 ----------

static void kp_proxy_pool_set(kp_proxy_pool *pool, const char *const items[], size_t count) {
    if (!pool) return;
    pool->count = 0;
    pool->rr = 0;
    if (!items) return;
    for (size_t i = 0; i < count && i < KP_MAX_PROXY_POOL; i++) {
        if (!items[i] || items[i][0] == '\0') continue;
        snprintf(pool->items[pool->count], sizeof(pool->items[pool->count]), "%s", items[i]);
        pool->count++;
    }
}

static int kp_proxy_pool_pick_index(kp_proxy_pool *pool, int index,
                                    char *host, size_t host_cap, int *port) {
    if (!pool || pool->count <= 0 || !host || !port) return -1;
    if (index < 0 || index >= pool->count) return -1;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", pool->items[index]);
    char *colon = strrchr(tmp, ':');
    if (!colon) return -1;
    *colon = '\0';
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    if (strlen(tmp) >= host_cap) return -1;
    strcpy(host, tmp);
    *port = p;
    return 0;
}

static void kp_forwarder_snapshot(kp_forwarder *fw,
                                  char *guid, size_t gc,
                                  char *token, size_t tc,
                                  char *qua2, size_t q2c,
                                  char *qkey, size_t qkc,
                                  char *qtype, size_t qtc) {
    pthread_mutex_lock(&fw->cred_mutex);
    if (guid) snprintf(guid, gc, "%s", fw->guid);
    if (token) snprintf(token, tc, "%s", fw->token);
    if (qua2) snprintf(qua2, q2c, "%s", fw->qua2);
    if (qkey) snprintf(qkey, qkc, "%s", fw->qkey);
    if (qtype) snprintf(qtype, qtc, "%s", fw->qtype);
    pthread_mutex_unlock(&fw->cred_mutex);
}

static int kp_parse_status_code(const char *buf, size_t len) {
    if (!buf || len < 12 || strncmp(buf, "HTTP/", 5) != 0) return -1;
    const char *sp = strchr(buf, ' ');
    if (!sp) return -1;
    return atoi(sp + 1);
}

// 这些状态码通常表示 Q-Token/Q-Key 失效或代理池需要刷新。
// 820/821/823 是现有刷新码；800/801 经确认不是凭证失效信号，不在这里处理。
static int kp_code_needs_credential_refresh(int code) {
    switch (code) {
        case 820:
        case 821:
        case 823:
            return 1;
        default:
            return 0;
    }
}

// 有些 HTTPS 代理会在 CONNECT 200 后直接返回一段 HTTP 错误文本而不是 TLS 数据，
// 这通常也意味着凭证已失效。这里用“多余字节以 HTTP/ 开头”作为保守判据。
static int kp_extra_is_http_error(const char *buf, size_t len) {
    return len >= 5 && strncasecmp(buf, "HTTP/", 5) == 0;
}

static void kp_millis_string(char *out, size_t out_cap) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long ms = (long long)tv.tv_sec * 1000 + (long long)(tv.tv_usec / 1000);
    snprintf(out, out_cap, "%lld", ms);
}

static void kp_build_http_url(const char *host, int port, const char *path,
                              char *url, size_t url_cap) {
    if (port == 80) snprintf(url, url_cap, "http://%s%s", host, path ? path : "/");
    else snprintf(url, url_cap, "http://%s:%d%s", host, port, path ? path : "/");
}

static void kp_build_https_url(const char *host, int port, char *url, size_t url_cap) {
    if (port == 443) snprintf(url, url_cap, "https://%s/", host);
    else snprintf(url, url_cap, "https://%s:%d/", host, port);
}

static size_t kp_append_origin_headers(const char *reqbuf, size_t reqlen,
                                       char *out, size_t out_cap, size_t off) {
    const char *eol1 = strstr(reqbuf, "\r\n");
    if (!eol1) return off;
    const char *h = eol1 + 2;
    const char *sep = strstr(reqbuf, "\r\n\r\n");
    const char *hend = sep ? sep : reqbuf + reqlen;
    while (h < hend) {
        const char *le = strstr(h, "\r\n");
        if (!le || le > hend) break;
        size_t ll = (size_t)(le - h);
        int skip = 0;
        if (ll >= 5 && strncasecmp(h, "Host:", 5) == 0) skip = 1;
        else if (ll >= 7 && strncasecmp(h, "Q-GUID:", 7) == 0) skip = 1;
        else if (ll >= 6 && strncasecmp(h, "Q-UA2:", 6) == 0) skip = 1;
        else if (ll >= 8 && strncasecmp(h, "Q-Token:", 8) == 0) skip = 1;
        else if (ll >= 7 && strncasecmp(h, "Q-Type:", 7) == 0) skip = 1;
        else if (ll >= 6 && strncasecmp(h, "Q-Key:", 6) == 0) skip = 1;
        else if (ll >= 12 && strncasecmp(h, "Q-RequestId:", 12) == 0) skip = 1;
        else if (ll >= 11 && strncasecmp(h, "User-Agent:", 11) == 0) skip = 1;
        else if (ll >= 7 && strncasecmp(h, "Accept:", 7) == 0) skip = 1;
        else if (ll >= 11 && strncasecmp(h, "Connection:", 11) == 0) skip = 1;
        else if (ll >= 17 && strncasecmp(h, "Proxy-Connection:", 17) == 0) skip = 1;
        else if (ll >= 19 && strncasecmp(h, "Proxy-Authorization:", 19) == 0) skip = 1;
        if (!skip) {
            if (off + ll + 2 >= out_cap) break;
            memcpy(out + off, h, ll);
            off += ll;
            out[off++] = '\r';
            out[off++] = '\n';
        }
        h = le + 2;
    }
    return off;
}

static int kp_build_queen_http_request(kp_forwarder *fw,
                                       const char *method,
                                       const char *host, int port,
                                       const char *path,
                                       const char *reqbuf, size_t reqlen,
                                       char *out, size_t out_cap,
                                       char *qkey_out, size_t qkey_out_cap) {
    char guid[128], token[128], qua2[256], qkey[128], qtype[32];
    kp_forwarder_snapshot(fw, guid, sizeof(guid), token, sizeof(token),
                          qua2, sizeof(qua2), qkey, sizeof(qkey), qtype, sizeof(qtype));
    if (token[0] == '\0' || qkey[0] == '\0') return -1;

    char url[1024];
    kp_build_http_url(host, port, path, url, sizeof(url));
    char reqid[24];
    kp_millis_string(reqid, sizeof(reqid));
    if (kpk_build_qkey_header(guid, host, url, reqid, qkey, qkey_out, qkey_out_cap) != 0) return -1;

    int n = snprintf(out, out_cap,
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Q-GUID: %s\r\n"
                     "Q-UA2: %s\r\n"
                     "Q-Token: %s\r\n"
                     "Q-Type: %s\r\n"
                     "Q-Key: %s\r\n"
                     "Q-RequestId: %s\r\n"
                     "User-Agent: MQQBrowser\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n",
                     method, url, host, port, guid, qua2, token, qtype,
                     qkey_out, reqid);
    if (n <= 0 || (size_t)n >= out_cap) return -1;
    size_t off = (size_t)n;
    off = kp_append_origin_headers(reqbuf, reqlen, out, out_cap, off);
    if (off + 2 >= out_cap) return -1;
    out[off++] = '\r';
    out[off++] = '\n';

    const char *sep = strstr(reqbuf, "\r\n\r\n");
    if (sep) {
        const char *body = sep + 4;
        size_t bodylen = reqlen - (size_t)(body - reqbuf);
        if (bodylen > 0) {
            if (off + bodylen >= out_cap) return -1;
            memcpy(out + off, body, bodylen);
            off += bodylen;
        }
    }
    out[off] = '\0';
    return (int)off;
}

static int kp_build_queen_connect_request(kp_forwarder *fw,
                                          const char *host, int port,
                                          char *out, size_t out_cap,
                                          char *qkey_out, size_t qkey_out_cap) {
    char guid[128], token[128], qua2[256], qkey[128], qtype[32];
    kp_forwarder_snapshot(fw, guid, sizeof(guid), token, sizeof(token),
                          qua2, sizeof(qua2), qkey, sizeof(qkey), qtype, sizeof(qtype));
    if (token[0] == '\0' || qkey[0] == '\0') return -1;

    char url[1024];
    kp_build_https_url(host, port, url, sizeof(url));
    char reqid[24];
    kp_millis_string(reqid, sizeof(reqid));
    if (kpk_build_qkey_header(guid, host, url, reqid, qkey, qkey_out, qkey_out_cap) != 0) return -1;

    int n = snprintf(out, out_cap,
                     "CONNECT %s:%d HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Proxy-Authorization: Q-GUID|%s,Q-UA2|%s,Q-Token|%s,Q-Key|%s,Q-RequestId|%s,Q-Type|%s\r\n"
                     "User-Agent: MQQBrowser\r\n"
                     "\r\n",
                     host, port, host, port, guid, qua2, token, qkey_out, reqid, qtype);
    if (n <= 0 || (size_t)n >= out_cap) return -1;
    return (int)strlen(out);
}

static void kp_send_simple_response(int client, int code, const char *text) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "HTTP/1.1 %d %s\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n",
             code, text ? text : "Error");
    kp_send_all(client, buf, strlen(buf));
}

// 客户端请求读取器：recv 大块，再从内存缓冲区消费，避免逐字节 recv。
typedef struct {
    int fd;
    char buf[16384 + 1];
    size_t start;
    size_t end;
} kp_reader;

static void kp_reader_init(kp_reader *r, int fd) {
    r->fd = fd;
    r->start = 0;
    r->end = 0;
}

static int kp_reader_fill(kp_reader *r) {
    if (r->start < r->end) return 0;
    r->start = 0;
    r->end = 0;
    ssize_t n = recv(r->fd, r->buf, sizeof(r->buf) - 1, 0);
    if (n <= 0) return -1;
    r->end = (size_t)n;
    r->buf[r->end] = '\0';
    return 0;
}

// 读取 HTTP 头（到 \r\n\r\n 为止），只消费头部，不消费头部之后的字节。
// 成功返回 0，header_len 回填头长；失败返回 -1。
static int kp_reader_read_header(kp_reader *r, char *out, size_t cap, size_t *header_len) {
    size_t off = 0;
    while (off + 1 < cap) {
        if (r->start >= r->end && kp_reader_fill(r) != 0) return -1;
        char *hay = r->buf + r->start;
        size_t haylen = r->end - r->start;
        r->buf[r->end] = '\0';
        char *sep = strstr(hay, "\r\n\r\n");
        if (sep) {
            size_t n = (size_t)(sep - hay) + 4;
            if (off + n >= cap) return -1;
            memcpy(out + off, hay, n);
            r->start += n;
            *header_len = off + n;
            return 0;
        }
        if (off + haylen >= cap - 1) return -1;
        memcpy(out + off, hay, haylen);
        off += haylen;
        r->start = r->end;
    }
    return -1;
}

static size_t kp_reader_copy(kp_reader *r, char *out, size_t len) {
    size_t got = 0;
    while (got < len) {
        if (r->start >= r->end && kp_reader_fill(r) != 0) break;
        size_t avail = r->end - r->start;
        size_t take = len - got;
        if (take > avail) take = avail;
        memcpy(out + got, r->buf + r->start, take);
        r->start += take;
        got += take;
    }
    return got;
}

// 把 reader 中已缓冲的剩余字节（例如 CONNECT 头之后提前到达的 TLS 数据）发给 fd。
static int kp_reader_send_available(kp_reader *r, int fd, uint64_t *counter) {
    size_t avail = r->end - r->start;
    if (avail == 0) return 0;
    if (kp_send_all(fd, r->buf + r->start, avail) != 0) return -1;
    if (counter) *counter += (uint64_t)avail;
    r->start = r->end;
    return 0;
}


static void kp_handle_client(kp_forwarder *fw, int client) {
    char reqbuf[4096];
    kp_reader reader;
    kp_reader_init(&reader, client);

    size_t header_len = 0;
    if (kp_reader_read_header(&reader, reqbuf, sizeof(reqbuf), &header_len) != 0) {
        KP_CLOSESOCK(client);
        return;
    }
    size_t off = header_len;

    // Content-Length body：从 reader 缓冲/套接字补齐到 reqbuf，避免逐字节 recv。
    {
        char *cl = strstr(reqbuf, "Content-Length:");
        if (!cl) cl = strstr(reqbuf, "content-length:");
        if (cl) {
            int clen = atoi(cl + 15);
            if (clen > 0 && off + (size_t)clen < sizeof(reqbuf)) {
                size_t got = kp_reader_copy(&reader, reqbuf + off, (size_t)clen);
                off += got;
            }
        }
    }
    reqbuf[off] = '\0';

    char method[16];
    char host[256];
    int port = 0;
    char path[1024];

    if (kp_parse_absolute_uri(reqbuf, off, method, sizeof(method),
                              host, sizeof(host), &port, path, sizeof(path)) == 0) {
        fw->stat_http_requests++;
        kp_dbg("[fw] HTTP absolute URI: %s http://%s:%d%s", method, host, port, path);

        if (strncmp(host, "127.", 4) == 0 || strcmp(host, "localhost") == 0 ||
            strcmp(host, "::1") == 0) {
            char rebuilt[4096];
            int rn = kp_rebuild_proxy_request(reqbuf, off, method, host, port, path,
                                              rebuilt, sizeof(rebuilt));
            if (rn <= 0) { kp_send_simple_response(client, 400, "Bad Request"); KP_CLOSESOCK(client); return; }
            int up = kp_connect_host(host, port, 8000);
            if (up < 0) { kp_send_simple_response(client, 502, "Bad Gateway"); KP_CLOSESOCK(client); return; }
            kp_http_forward(up, client, rebuilt, (size_t)rn);
            KP_CLOSESOCK(up);
            KP_CLOSESOCK(client);
            return;
        }

        int http_pool_count = 0;
        int http_refreshed = 0;
        pthread_mutex_lock(&fw->cred_mutex);
        http_pool_count = fw->http_pool.count;
        pthread_mutex_unlock(&fw->cred_mutex);

    http_retry:
        for (int attempt = 0; attempt < http_pool_count; attempt++) {
            char proxy_host[128];
            int proxy_port = 0;
            pthread_mutex_lock(&fw->cred_mutex);
            int pick_rc = kp_proxy_pool_pick_index(&fw->http_pool, attempt,
                                                   proxy_host, sizeof(proxy_host), &proxy_port);
            pthread_mutex_unlock(&fw->cred_mutex);
            if (pick_rc != 0) {
                continue;
            }

            int up = kp_connect_host(proxy_host, proxy_port, 10000);
            if (up < 0) {
                continue;
            }

            char qreq[8192];
            char qkey_val[512];
            int qn = kp_build_queen_http_request(fw, method, host, port, path,
                                                 reqbuf, off, qreq, sizeof(qreq),
                                                 qkey_val, sizeof(qkey_val));
            if (qn <= 0 || kp_send_all(up, qreq, (size_t)qn) != 0) {
                KP_CLOSESOCK(up);
                continue;
            }

            char resp[4096];
            size_t rgot = 0;
            if (kp_recv_until(up, resp, sizeof(resp), &rgot, 10000) != 0) {
                KP_CLOSESOCK(up);
                continue;
            }
            int code = kp_parse_status_code(resp, rgot);
            kp_dbg("[fw] queen_http %s:%d -> code=%d", proxy_host, proxy_port, code);

            if (kp_code_needs_credential_refresh(code)) {
                KP_CLOSESOCK(up);
                continue;
            }
            if (code == 822 || code == 824) {
                KP_CLOSESOCK(up);
                fw->stat_direct_fallbacks++;
                kp_forwarder_record_direct_host(fw, host);
                char rebuilt[4096];
                int rn = kp_rebuild_proxy_request(reqbuf, off, method, host, port, path,
                                                  rebuilt, sizeof(rebuilt));
                int dup = kp_connect_host(host, port, 8000);
                if (rn <= 0 || dup < 0) {
                    if (dup >= 0) KP_CLOSESOCK(dup);
                    kp_send_simple_response(client, 502, "Bad Gateway");
                    KP_CLOSESOCK(client);
                    return;
                }
                kp_http_forward(dup, client, rebuilt, (size_t)rn);
                KP_CLOSESOCK(dup);
                KP_CLOSESOCK(client);
                return;
            }
            if (code >= 200 && code < 600) {
                struct timeval zero = {0, 0};
                setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
                setsockopt(up, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
                uint64_t up_recv = (uint64_t)rgot;
                if (kp_send_all(client, resp, rgot) == 0) {
                    char buf[16384];
                    ssize_t r;
                    while ((r = recv(up, buf, sizeof(buf), 0)) > 0) {
                        if (kp_send_all(client, buf, (size_t)r) != 0) break;
                        up_recv += (uint64_t)r;
                    }
                }
                kp_dbg("[fw] HTTP conn done host=%s:%d client_bytes=%zu up_sent=%zu up_recv=%llu",
                       host, port, off, (size_t)qn, (unsigned long long)up_recv);
                KP_CLOSESOCK(up);
                KP_CLOSESOCK(client);
                return;
            }
            KP_CLOSESOCK(up);
            continue;
        }
        if (!http_refreshed && kp_forwarder_refresh_retry(fw, 3, 500) == 0) {
            http_refreshed = 1;
            pthread_mutex_lock(&fw->cred_mutex);
            http_pool_count = fw->http_pool.count;
            pthread_mutex_unlock(&fw->cred_mutex);
            goto http_retry;
        }
        kp_send_simple_response(client, 502, "Bad Gateway");
        KP_CLOSESOCK(client);
        return;
    }

    host[0] = '\0';
    port = 0;
    if (kp_parse_connect_line(reqbuf, off, host, sizeof(host), &port) != 0) {
        kp_send_simple_response(client, 400, "Bad Request");
        KP_CLOSESOCK(client);
        return;
    }
    fw->stat_https_connects++;
    kp_dbg("[fw] CONNECT target %s:%d", host, port);

    if (strncmp(host, "127.", 4) == 0 || strcmp(host, "localhost") == 0 ||
        strcmp(host, "::1") == 0 || strcmp(host, "[::1]") == 0) {
        int up = kp_connect_host(host, port, 8000);
        if (up < 0) { kp_send_simple_response(client, 502, "Bad Gateway"); KP_CLOSESOCK(client); return; }
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (kp_send_all(client, ok, strlen(ok)) == 0) {
            if (kp_reader_send_available(&reader, up, NULL) == 0) {
                kp_pipe_bidirectional_counted(up, client, NULL, NULL);
            }
        }
        KP_CLOSESOCK(up);
        KP_CLOSESOCK(client);
        return;
    }

    int https_pool_count = 0;
    int https_refreshed = 0;
    pthread_mutex_lock(&fw->cred_mutex);
    https_pool_count = fw->https_pool.count;
    pthread_mutex_unlock(&fw->cred_mutex);

https_retry:
    for (int attempt = 0; attempt < https_pool_count; attempt++) {
        char proxy_host[128];
        int proxy_port = 0;
        pthread_mutex_lock(&fw->cred_mutex);
        int pick_rc = kp_proxy_pool_pick_index(&fw->https_pool, attempt,
                                               proxy_host, sizeof(proxy_host), &proxy_port);
        pthread_mutex_unlock(&fw->cred_mutex);
        if (pick_rc != 0) {
            continue;
        }

        int up = kp_connect_host(proxy_host, proxy_port, 10000);
        if (up < 0) {
            continue;
        }

        char creq[2048];
        char qkey_val[512];
        int cn = kp_build_queen_connect_request(fw, host, port, creq, sizeof(creq),
                                                qkey_val, sizeof(qkey_val));
        if (cn <= 0 || kp_send_all(up, creq, (size_t)cn) != 0) {
            KP_CLOSESOCK(up);
            continue;
        }

        char resp[2048];
        size_t rgot = 0;
        if (kp_recv_until(up, resp, sizeof(resp), &rgot, 10000) != 0) {
            KP_CLOSESOCK(up);
            continue;
        }
        int code = kp_parse_status_code(resp, rgot);
        kp_dbg("[fw] queen_https %s:%d CONNECT -> code=%d", proxy_host, proxy_port, code);

        if (kp_code_needs_credential_refresh(code)) {
            KP_CLOSESOCK(up);
            continue;
        }
        if (code == 822 || code == 824) {
            KP_CLOSESOCK(up);
            fw->stat_direct_fallbacks++;
            kp_forwarder_record_direct_host(fw, host);
            int dup = kp_connect_host(host, port, 10000);
            if (dup < 0) { kp_send_simple_response(client, 502, "Bad Gateway"); KP_CLOSESOCK(client); return; }
            const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (kp_send_all(client, ok, strlen(ok)) != 0) {
                KP_CLOSESOCK(dup);
                KP_CLOSESOCK(client);
                return;
            }
            if (kp_reader_send_available(&reader, dup, NULL) != 0) {
                KP_CLOSESOCK(dup);
                KP_CLOSESOCK(client);
                return;
            }
            kp_pipe_bidirectional_counted(dup, client, NULL, NULL);
            KP_CLOSESOCK(dup);
            KP_CLOSESOCK(client);
            return;
        }
        if (code == 200) {
            char *body = strstr(resp, "\r\n\r\n");
            size_t consumed = body ? (size_t)(body - resp + 4) : rgot;
            size_t extra_len = rgot - consumed;
            // 部分 HTTPS 代理在 token 失效时仍会回 200，但后面跟的是 HTTP 错误文本
            // 而不是 TLS 数据。这里在把 200 转发给客户端之前先识别这种伪成功。
            if (extra_len > 0 && kp_extra_is_http_error(resp + consumed, extra_len)) {
                kp_dbg("[fw] queen_https CONNECT 200 but extra data is HTTP error (likely token invalid)");
                KP_CLOSESOCK(up);
                continue;
            }
            struct timeval zero = {0, 0};
            setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
            setsockopt(up, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
            const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (kp_send_all(client, ok, strlen(ok)) != 0) {
                KP_CLOSESOCK(up);
                KP_CLOSESOCK(client);
                return;
            }
            uint64_t up_recv_extra = 0;
            if (consumed < rgot) {
                kp_send_all(client, resp + consumed, extra_len);
                up_recv_extra = (uint64_t)extra_len;
            }
            uint64_t client_to_up = 0;
            uint64_t up_to_client = up_recv_extra;
            if (kp_reader_send_available(&reader, up, &client_to_up) != 0) {
                KP_CLOSESOCK(up);
                KP_CLOSESOCK(client);
                return;
            }
            kp_pipe_bidirectional_counted(up, client, &up_to_client, &client_to_up);
            kp_dbg("[fw] CONNECT conn done host=%s:%d client_to_up=%llu up_to_client=%llu",
                   host, port, (unsigned long long)client_to_up, (unsigned long long)up_to_client);
            // 隧道已建立但客户端发了数据后上游一个字节都没回就关闭，常见于：
            // Q-Token 已失效/代理节点异常导致 TLS handshake 被对端直接终止。
            // 这里主动触发一次强制刷新，让后续连接有机会用新凭证恢复。
            if (up_to_client == 0 && client_to_up > 0) {
                kp_dbg("[fw] CONNECT closed before upstream data (likely handshake failure), refreshing credentials");
                kp_forwarder_refresh_retry(fw, 2, 300);
            }
            KP_CLOSESOCK(up);
            KP_CLOSESOCK(client);
            return;
        }
        KP_CLOSESOCK(up);
        continue;
    }
    if (!https_refreshed && kp_forwarder_refresh_retry(fw, 3, 500) == 0) {
        https_refreshed = 1;
        pthread_mutex_lock(&fw->cred_mutex);
        https_pool_count = fw->https_pool.count;
        pthread_mutex_unlock(&fw->cred_mutex);
        goto https_retry;
    }
    kp_send_simple_response(client, 502, "Bad Gateway");
    KP_CLOSESOCK(client);
}


static int kp_forwarder_refresh(kp_forwarder *fw) {
    if (!fw || !fw->refresh_fn) return -1;
    fw->stat_refresh_calls++;
    return fw->refresh_fn(fw->refresh_ctx);
}

// 带有限重试的被动刷新：瞬时失败（取号接口抖动等）不应直接判死回 502。
// 共尝试 attempts 次，间隔 backoff_ms。任一次成功立即返回 0。
static int kp_forwarder_refresh_retry(kp_forwarder *fw, int attempts, int backoff_ms) {
    if (!fw) return -1;
    for (int i = 0; i < attempts; i++) {
        if (i > 0) {
            struct timespec ts = { backoff_ms / 1000, (backoff_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        }
        if (kp_forwarder_refresh(fw) == 0) return 0;
    }
    return -1;
}

static void *kp_client_thread(void *arg) {
    struct client_arg *ca = arg;
    kp_forwarder *fw = ca->fw;
    int fd = ca->fd;
    kp_handle_client(fw, fd);
    free(ca);
    pthread_mutex_lock(&fw->client_lock);
    for (int i = 0; i < fw->client_fd_count; i++) {
        if (fw->client_fds[i] == fd) {
            fw->client_fds[i] = fw->client_fds[fw->client_fd_count - 1];
            fw->client_fd_count--;
            break;
        }
    }
    if (fw->active_clients > 0) fw->active_clients--;
    pthread_cond_broadcast(&fw->client_cond);
    pthread_mutex_unlock(&fw->client_lock);
    return NULL;
}

static void *kp_forwarder_run(void *arg) {
    kp_forwarder *fw = arg;
    while (fw->running) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int client = accept(fw->listen_fd, (struct sockaddr *)&peer, &plen);
        if (client < 0) {
            if (!fw->running) break;
            continue;
        }
        // 高速下载并发上限：超出则立即拒绝，避免线程风暴耗尽进程资源。
        pthread_mutex_lock(&fw->client_lock);
        int over = fw->active_clients >= KP_FORWARDER_MAX_CLIENTS;
        if (!over) {
            fw->active_clients++;
            fw->client_fds[fw->client_fd_count++] = client;
        }
        pthread_mutex_unlock(&fw->client_lock);
        if (over) {
            char *msg = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
            (void)send(client, msg, (int)strlen(msg), 0);
            KP_CLOSESOCK(client);
            continue;
        }
        struct client_arg *ca = malloc(sizeof(*ca));
        if (!ca) {
            pthread_mutex_lock(&fw->client_lock);
            if (fw->active_clients > 0) fw->active_clients--;
            for (int i = 0; i < fw->client_fd_count; i++) {
                if (fw->client_fds[i] == client) {
                    fw->client_fds[i] = fw->client_fds[fw->client_fd_count - 1];
                    fw->client_fd_count--;
                    break;
                }
            }
            pthread_mutex_unlock(&fw->client_lock);
            KP_CLOSESOCK(client);
            continue;
        }
        ca->fw = fw;
        ca->fd = client;
        pthread_t t;
        if (pthread_create(&t, NULL, kp_client_thread, ca) != 0) {
            pthread_mutex_lock(&fw->client_lock);
            if (fw->active_clients > 0) fw->active_clients--;
            for (int i = 0; i < fw->client_fd_count; i++) {
                if (fw->client_fds[i] == client) {
                    fw->client_fds[i] = fw->client_fds[fw->client_fd_count - 1];
                    fw->client_fd_count--;
                    break;
                }
            }
            pthread_mutex_unlock(&fw->client_lock);
            free(ca);
            KP_CLOSESOCK(client);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

kp_forwarder *kp_forwarder_new(const char *listen_host, int listen_port,
                               const char *upstream_host, int upstream_port) {
    kp_forwarder *fw = calloc(1, sizeof(*fw));
    if (!fw) return NULL;
    snprintf(fw->listen_host, sizeof(fw->listen_host), "%s", listen_host ? listen_host : "127.0.0.1");
    fw->listen_port = listen_port;
    snprintf(fw->upstream_host, sizeof(fw->upstream_host), "%s", upstream_host ? upstream_host : "");
    fw->upstream_port = upstream_port;
    fw->listen_fd = -1;
    fw->guid[0] = '\0';
    fw->token[0] = '\0';
    fw->refresh_fn = NULL;
    fw->refresh_ctx = NULL;
    fw->active_clients = 0;
    fw->client_fd_count = 0;
    pthread_mutex_init(&fw->cred_mutex, NULL);
    pthread_mutex_init(&fw->client_lock, NULL);
    pthread_cond_init(&fw->client_cond, NULL);
    return fw;
}

void kp_forwarder_set_creds(kp_forwarder *fw, const char *guid, const char *token) {
    if (!fw) return;
    pthread_mutex_lock(&fw->cred_mutex);
    snprintf(fw->guid, sizeof(fw->guid), "%s", guid ? guid : "");
    snprintf(fw->token, sizeof(fw->token), "%s", token ? token : "");
    pthread_mutex_unlock(&fw->cred_mutex);
}

void kp_forwarder_set_king_state(kp_forwarder *fw,
                                 const char *guid,
                                 const char *qua2,
                                 const char *token,
                                 const char *qkey,
                                 const char *qtype,
                                 const char *const http_proxies[], size_t http_count,
                                 const char *const https_proxies[], size_t https_count) {
    if (!fw) return;
    pthread_mutex_lock(&fw->cred_mutex);
    snprintf(fw->guid, sizeof(fw->guid), "%s", guid ? guid : "");
    snprintf(fw->qua2, sizeof(fw->qua2), "%s", qua2 ? qua2 : "");
    snprintf(fw->token, sizeof(fw->token), "%s", token ? token : "");
    snprintf(fw->qkey, sizeof(fw->qkey), "%s", qkey ? qkey : "");
    snprintf(fw->qtype, sizeof(fw->qtype), "%s", qtype && qtype[0] ? qtype : "httpcom");
    kp_proxy_pool_set(&fw->http_pool, http_proxies, http_count);
    kp_proxy_pool_set(&fw->https_pool, https_proxies, https_count);
    pthread_mutex_unlock(&fw->cred_mutex);
}

void kp_forwarder_set_refresh_hook(kp_forwarder *fw, kp_refresh_fn fn, void *ctx) {
    if (!fw) return;
    fw->refresh_fn = fn;
    fw->refresh_ctx = ctx;
}

static void kp_forwarder_creds(kp_forwarder *fw, char *guid, size_t gc, char *token, size_t tc) {
    pthread_mutex_lock(&fw->cred_mutex);
    snprintf(guid, gc, "%s", fw->guid);
    snprintf(token, tc, "%s", fw->token);
    pthread_mutex_unlock(&fw->cred_mutex);
}

int kp_forwarder_start(kp_forwarder *fw) {
    if (!fw || fw->running) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)fw->listen_port);
    if (inet_pton(AF_INET, fw->listen_host, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        KP_CLOSESOCK(fd);
        return -1;
    }
    struct sockaddr_storage bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(fd, (struct sockaddr *)&bound_addr, &bound_len) == 0) {
        if (bound_addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&bound_addr;
            fw->listen_port = ntohs(sin->sin_port);
        } else if (bound_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&bound_addr;
            fw->listen_port = ntohs(sin6->sin6_port);
        }
    }
    fw->listen_fd = fd;
    fw->running = 1;
    if (pthread_create(&fw->thread, NULL, kp_forwarder_run, fw) != 0) {
        fw->running = 0;
        KP_CLOSESOCK(fd);
        fw->listen_fd = -1;
        return -1;
    }
    kp_dbg("[fw] forwarder listening on %s:%d", fw->listen_host, fw->listen_port);
    return 0;
}

void kp_forwarder_stop(kp_forwarder *fw) {
    if (!fw) return;
    if (fw->running) {
        fw->running = 0;
        if (fw->listen_fd >= 0) {
            // shutdown 先唤醒阻塞的 accept（Linux 上 close 不唤醒；macOS 无副作用）
            shutdown(fw->listen_fd, SHUT_RDWR);
            KP_CLOSESOCK(fw->listen_fd);
            fw->listen_fd = -1;
        }
    }
    // 先 join 主 accept 线程：确保 accept 循环完全停止，不会再登记新 client fd。
    // 否则 stop 遍历 client_fds 之后若有新连接被 accept 但尚未登记，其 fd 不会被
    // shutdown，对应 client 线程永不退出，stop 会死锁。
    if (fw->thread) {
        pthread_join(fw->thread, NULL);
        fw->thread = 0;
    }

    // shutdown 所有活跃 client fd，让阻塞在 recv/poll 的转发线程返回。
    pthread_mutex_lock(&fw->client_lock);
    for (int i = 0; i < fw->client_fd_count; i++) {
        int fd = fw->client_fds[i];
        if (fd >= 0) shutdown(fd, SHUT_RDWR);
    }
    // 等待所有 client 线程结束，避免 kp_forwarder_free 后线程仍访问 fw（UAF）。
    while (fw->active_clients > 0) {
        pthread_cond_wait(&fw->client_cond, &fw->client_lock);
    }
    fw->client_fd_count = 0;
    pthread_mutex_unlock(&fw->client_lock);
}

void kp_forwarder_free(kp_forwarder *fw) {
    if (!fw) return;
    kp_forwarder_stop(fw);
    pthread_mutex_destroy(&fw->cred_mutex);
    pthread_mutex_destroy(&fw->client_lock);
    pthread_cond_destroy(&fw->client_cond);
    free(fw);
}

int kp_forwarder_is_running(kp_forwarder *fw) { return fw ? fw->running : 0; }
int kp_forwarder_port(kp_forwarder *fw) { return fw ? fw->listen_port : 0; }

void kp_forwarder_get_stats(kp_forwarder *fw, kp_forwarder_stats *stats) {
    if (!stats) return;
    memset(stats, 0, sizeof(*stats));
    if (!fw) return;
    stats->http_requests = fw->stat_http_requests;
    stats->https_connects = fw->stat_https_connects;
    stats->direct_fallbacks = fw->stat_direct_fallbacks;
    stats->refresh_calls = fw->stat_refresh_calls;
    stats->proxy_errors = fw->stat_proxy_errors;
}

int kp_forwarder_direct_host_count(kp_forwarder *fw) {
    return fw ? fw->direct_host_log_count : 0;
}

int kp_forwarder_get_direct_host(kp_forwarder *fw, int index,
                                 char *out, size_t out_cap) {
    if (!fw || !out || out_cap == 0) return -1;
    if (index < 0 || index >= fw->direct_host_log_count) return -1;
    int start = (fw->direct_host_log_rr - fw->direct_host_log_count + index) % KP_DIRECT_HOST_LOG_MAX;
    if (start < 0) start += KP_DIRECT_HOST_LOG_MAX;
    snprintf(out, out_cap, "%s", fw->direct_host_log[start]);
    return 0;
}
