#include "KPKIngCore.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* KPKIngCore's unrelated Queen paths are not exercised by this local test. */
void proxychains_write_log(char *str, ...) { (void)str; }
void kp_socket_set_bypass(int on) { (void)on; }
int kpk_build_qkey_header(const char *guid, const char *domain, const char *url,
                          const char *request_id, const char *qkey,
                          char *out, size_t out_cap) {
    (void)guid; (void)domain; (void)url; (void)request_id; (void)qkey; (void)out; (void)out_cap;
    return -1;
}

enum server_mode {
    SERVER_SUCCESS_DOMAIN,
    SERVER_SUCCESS_IPV4,
    SERVER_SUCCESS_IPV6,
    SERVER_REJECT_METHOD,
    SERVER_REJECT_AUTH,
    SERVER_UNSUPPORTED_ADDRESS_TYPE,
};

static int read_exact(int fd, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int send_fragmented(int fd, const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (send(fd, buf + i, 1, 0) != 1) return -1;
    }
    return 0;
}

static int read_http_headers(int fd) {
    char buffer[1024];
    size_t len = 0;
    while (len + 1 < sizeof(buffer)) {
        ssize_t n = recv(fd, buffer + len, 1, 0);
        if (n <= 0) return -1;
        len += (size_t)n;
        buffer[len] = '\0';
        if (len >= 4 && memcmp(buffer + len - 4, "\r\n\r\n", 4) == 0) return 0;
    }
    return -1;
}

static int serve_client(int fd, enum server_mode mode) {
    unsigned char greeting[4];
    if (read_exact(fd, greeting, sizeof(greeting)) != 0) return -1;
    if (mode == SERVER_REJECT_METHOD) {
        const unsigned char reply[] = {0x05, 0x00};
        return send_fragmented(fd, reply, sizeof(reply));
    }
    const unsigned char auth_method[] = {0x05, 0x02};
    if (send_fragmented(fd, auth_method, sizeof(auth_method)) != 0) return -1;

    unsigned char auth_header[2];
    if (read_exact(fd, auth_header, sizeof(auth_header)) != 0) return -1;
    unsigned char credentials[510];
    size_t credential_len = auth_header[1] + 1;
    if (credential_len > sizeof(credentials) || read_exact(fd, credentials, credential_len) != 0) return -1;
    size_t password_len = credentials[auth_header[1]];
    if (password_len + credential_len > sizeof(credentials) ||
        read_exact(fd, credentials + credential_len, password_len) != 0) return -1;
    if (mode == SERVER_REJECT_AUTH) {
        const unsigned char reply[] = {0x01, 0x01};
        return send_fragmented(fd, reply, sizeof(reply));
    }
    const unsigned char auth_ok[] = {0x01, 0x00};
    if (send_fragmented(fd, auth_ok, sizeof(auth_ok)) != 0) return -1;

    unsigned char connect_header[5];
    if (read_exact(fd, connect_header, sizeof(connect_header)) != 0) return -1;
    size_t connect_len = connect_header[4] + 2;
    if (connect_len > sizeof(credentials) || read_exact(fd, credentials, connect_len) != 0) return -1;
    if (mode == SERVER_UNSUPPORTED_ADDRESS_TYPE) {
        const unsigned char reply[] = {0x05, 0x00, 0x00, 0x02};
        return send_fragmented(fd, reply, sizeof(reply));
    }

    const unsigned char connect_ok_domain[] = {0x05, 0x00, 0x00, 0x03, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00, 0x50};
    const unsigned char connect_ok_ipv4[] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};
    const unsigned char connect_ok_ipv6[] = {0x05, 0x00, 0x00, 0x04,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                                               0x00, 0x50};
    if (mode == SERVER_SUCCESS_IPV4 && send_fragmented(fd, connect_ok_ipv4, sizeof(connect_ok_ipv4)) != 0) return -1;
    if (mode == SERVER_SUCCESS_IPV6 && send_fragmented(fd, connect_ok_ipv6, sizeof(connect_ok_ipv6)) != 0) return -1;
    if (mode == SERVER_SUCCESS_DOMAIN && send_fragmented(fd, connect_ok_domain, sizeof(connect_ok_domain)) != 0) return -1;
    if (read_http_headers(fd) != 0) return -1;
    const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n203.0.113.7";
    return send(fd, response, sizeof(response) - 1, 0) == (ssize_t)(sizeof(response) - 1) ? 0 : -1;
}

static int make_listener(int *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    return fd;
}

static int run_case(enum server_mode mode, int expected_result) {
    int port = 0;
    int listener = make_listener(&port);
    if (listener < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(listener);
        return -1;
    }
    if (pid == 0) {
        int client = accept(listener, NULL, NULL);
        int result = client >= 0 ? serve_client(client, mode) : -1;
        if (client >= 0) close(client);
        close(listener);
        _exit(result == 0 ? 0 : 1);
    }
    close(listener);
    char output[64];
    int result = kp_http_get_via_socks5("127.0.0.1", port, "tsnet", "credential",
                                        "example.test", 80, "/ip", 2000,
                                        output, sizeof(output));
    int child_status = 0;
    waitpid(pid, &child_status, 0);
    if (result != expected_result || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return -1;
    if (expected_result == 0 && strcmp(output, "203.0.113.7") != 0) return -1;
    return 0;
}

int main(void) {
    if (run_case(SERVER_SUCCESS_DOMAIN, 0) != 0 ||
        run_case(SERVER_SUCCESS_IPV4, 0) != 0 ||
        run_case(SERVER_SUCCESS_IPV6, 0) != 0 ||
        run_case(SERVER_REJECT_METHOD, -1) != 0 ||
        run_case(SERVER_REJECT_AUTH, -1) != 0 ||
        run_case(SERVER_UNSUPPORTED_ADDRESS_TYPE, -1) != 0) {
        fprintf(stderr, "SOCKS5 probe regression test failed\n");
        return 1;
    }
    puts("SOCKS5 probe regression test passed");
    return 0;
}
