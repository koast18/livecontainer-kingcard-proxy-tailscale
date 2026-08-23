//
//  KPKQueenCore.c
//  LCProxyTweak
//
//  极简 HTTP POST 客户端（POSIX socket，绕过 ATS / 系统代理）。
//
#include "KPKQueenCore.h"
#include "KPSocketHook.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int kpq_connect_host(const char *host, int port, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    kp_socket_set_bypass(1);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        kp_socket_set_bypass(0);
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        // 用非阻塞 connect + poll 真正限制连接耗时。以前直接阻塞 connect，
        // 超时不受 timeout_ms 控制，遇到不可达代理/IP 可能卡到系统 TCP 超时。
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int pr = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 10000);
            if (pr <= 0 || (pfd.revents & (POLLERR | POLLHUP))) {
                close(fd);
                fd = -1;
                continue;
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        } else if (rc != 0) {
            close(fd);
            fd = -1;
            continue;
        }

        // 恢复阻塞模式，后续 send/recv 继续依赖 SO_RCVTIMEO/SO_SNDTIMEO。
        fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        if (timeout_ms > 0) {
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        break;
    }
    freeaddrinfo(res);
    kp_socket_set_bypass(0);
    return fd;
}

static int kpq_send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, buf + off, len - off, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int kpq_recv_all(int fd, uint8_t *buf, size_t cap, size_t *got) {
    size_t off = 0;
    int header_done = 0;
    size_t content_length = (size_t)-1;
    while (off < cap - 1) {
        ssize_t r = recv(fd, buf + off, cap - 1 - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
        buf[off] = '\0';

        // 服务端可能在返回完整 body 后不立刻关闭连接。Python requests 会按
        // Content-Length 提前返回，而这里以前一直 recv 到 EOF/超时，导致每次
        // WUP 请求最多白等一个 timeout（15s）。这里改为按 Content-Length 收完就停。
        if (!header_done) {
            char *sep = strstr((char *)buf, "\r\n\r\n");
            if (sep) {
                header_done = 1;
                char cl[32] = {0};
                if (kpq_http_header(buf, off, "content-length", cl, sizeof(cl))) {
                    content_length = (size_t)strtoull(cl, NULL, 10);
                }
            }
        }
        if (header_done && content_length != (size_t)-1) {
            char *sep = strstr((char *)buf, "\r\n\r\n");
            if (sep) {
                size_t body_off = (size_t)((char *)sep - (char *)buf) + 4;
                if (off - body_off >= content_length) break;
            }
        }
    }
    buf[off] = '\0';
    *got = off;
    return off > 0 ? 0 : -1;
}

int kpq_http_post(const char *host, int port, const char *path_and_query,
                  const char *const headers[], size_t header_count,
                  const uint8_t *body, size_t body_len,
                  uint8_t *resp, size_t resp_cap, size_t *resp_len,
                  int timeout_ms) {
    if (!host || !path_and_query || !resp || !resp_len) return -1;
    if (port <= 0 || port > 65535) port = 80;

    int fd = kpq_connect_host(host, port, timeout_ms);
    if (fd < 0) return 0;

    // 请求头
    char head[4096];
    size_t off = 0;
    int n = snprintf(head, sizeof(head),
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n",
                     path_and_query, host, port);
    if (n <= 0 || (size_t)n >= sizeof(head)) {
        close(fd);
        return -1;
    }
    off = (size_t)n;

    for (size_t i = 0; i < header_count; i++) {
        if (!headers[i]) continue;
        size_t hl = strlen(headers[i]);
        if (off + hl + 2 >= sizeof(head)) {
            close(fd);
            return -1;
        }
        memcpy(head + off, headers[i], hl);
        off += hl;
        head[off++] = '\r';
        head[off++] = '\n';
    }
    n = snprintf(head + off, sizeof(head) - off,
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 body_len);
    if (n <= 0 || off + (size_t)n >= sizeof(head)) {
        close(fd);
        return -1;
    }
    off += (size_t)n;

    if (kpq_send_all(fd, head, off) != 0 ||
        (body_len > 0 && kpq_send_all(fd, (const char *)body, body_len) != 0)) {
        close(fd);
        return -1;
    }

    size_t got = 0;
    int rc = kpq_recv_all(fd, resp, resp_cap, &got);
    close(fd);
    *resp_len = got;
    if (rc != 0) return 0;

    // 解析状态码
    if (got < 12 || strncmp((const char *)resp, "HTTP/", 5) != 0) return 0;
    const char *sp = strchr((const char *)resp, ' ');
    if (!sp) return 0;
    return atoi(sp + 1);
}

int kpq_http_header(const uint8_t *resp, size_t resp_len,
                    const char *name, char *out, size_t out_cap) {
    if (!resp || !name || !out || out_cap == 0) return 0;
    out[0] = '\0';
    const char *p = (const char *)resp;
    const char *end = p + resp_len;
    size_t name_len = strlen(name);
    while (p < end) {
        const char *eol = memchr(p, '\r', (size_t)(end - p));
        if (!eol) break;
        size_t line_len = (size_t)(eol - p);
        if (line_len >= name_len && strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            const char *ve = eol;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            size_t cp = (size_t)(ve - v);
            if (cp >= out_cap) cp = out_cap - 1;
            memcpy(out, v, cp);
            out[cp] = '\0';
            return 1;
        }
        p = eol + 1;
        if (p < end && *p == '\n') p++;
        if (p < end && *p == '\r') break; // 空行 = header 结束
    }
    return 0;
}

int kpq_http_body_offset(const uint8_t *resp, size_t resp_len) {
    if (!resp || resp_len < 4) return -1;
    const char *p = (const char *)resp;
    const char *end = p + resp_len;
    while (p + 3 < end) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            return (int)(p - (const char *)resp) + 4;
        }
        p++;
    }
    return -1;
}


int kpq_tcp_connect_ms(const char *host, int port, int timeout_ms) {
    if (!host || port <= 0 || port > 65535) return -1;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    int fd = kpq_connect_host(host, port, timeout_ms);
    gettimeofday(&end, NULL);
    if (fd < 0) return -1;
    close(fd);
    long long ms = ((long long)end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    if (ms < 0) ms = 0;
    return (int)ms;
}
