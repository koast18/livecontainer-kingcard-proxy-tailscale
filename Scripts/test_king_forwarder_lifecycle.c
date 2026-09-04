#include "KPKIngCore.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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

struct reader_context {
    kp_forwarder *forwarder;
    atomic_int stop;
};

struct lifecycle_context {
    kp_forwarder *forwarder;
    atomic_int start;
};

static void *race_start(void *arg) {
    struct lifecycle_context *context = arg;
    while (!atomic_load(&context->start)) sched_yield();
    for (int i = 0; i < 500; i++) {
        (void)kp_forwarder_start(context->forwarder);
        sched_yield();
    }
    return NULL;
}

static void *race_stop(void *arg) {
    struct lifecycle_context *context = arg;
    while (!atomic_load(&context->start)) sched_yield();
    for (int i = 0; i < 500; i++) {
        kp_forwarder_stop(context->forwarder);
        sched_yield();
    }
    return NULL;
}

static int test_concurrent_lifecycle_transitions(void) {
    kp_forwarder *forwarder = kp_forwarder_new("127.0.0.1", 0, "", 0);
    if (!forwarder) return -1;
    struct lifecycle_context context = { forwarder, ATOMIC_VAR_INIT(0) };
    pthread_t starter;
    pthread_t stopper;
    if (pthread_create(&starter, NULL, race_start, &context) != 0) {
        kp_forwarder_free(forwarder);
        return -1;
    }
    if (pthread_create(&stopper, NULL, race_stop, &context) != 0) {
        atomic_store(&context.start, 1);
        pthread_join(starter, NULL);
        kp_forwarder_free(forwarder);
        return -1;
    }
    atomic_store(&context.start, 1);
    pthread_join(starter, NULL);
    pthread_join(stopper, NULL);
    kp_forwarder_stop(forwarder);
    int stopped = !kp_forwarder_is_running(forwarder);
    kp_forwarder_free(forwarder);
    return stopped ? 0 : -1;
}

static void *read_forwarder_state(void *arg) {
    struct reader_context *context = arg;
    while (!atomic_load_explicit(&context->stop, memory_order_relaxed)) {
        kp_forwarder_stats stats;
        (void)kp_forwarder_is_running(context->forwarder);
        (void)kp_forwarder_port(context->forwarder);
        kp_forwarder_get_stats(context->forwarder, &stats);
        (void)kp_forwarder_direct_host_count(context->forwarder);
    }
    return NULL;
}

struct upstream_context {
    int listener;
    atomic_int received_expected_body;
};

static int read_headers_and_body(int fd, char *out, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = recv(fd, out + used, cap - used - 1, 0);
        if (n <= 0) return -1;
        used += (size_t)n;
        out[used] = '\0';
        char *headers_end = strstr(out, "\r\n\r\n");
        if (!headers_end) continue;
        char *content_length = strstr(out, "Content-Length:");
        int body_len = content_length ? atoi(content_length + 15) : 0;
        size_t total = (size_t)(headers_end + 4 - out) + (size_t)body_len;
        while (used < total && used + 1 < cap) {
            n = recv(fd, out + used, cap - used - 1, 0);
            if (n <= 0) return -1;
            used += (size_t)n;
            out[used] = '\0';
        }
        return used == total ? 0 : -1;
    }
    return -1;
}

static void *serve_upstream(void *arg) {
    struct upstream_context *context = arg;
    int client = accept(context->listener, NULL, NULL);
    if (client >= 0) {
        char request[4096];
        if (read_headers_and_body(client, request, sizeof(request)) == 0 &&
            strstr(request, "POST /upload HTTP/1.1") && strstr(request, "payload=OK")) {
            atomic_store(&context->received_expected_body, 1);
        }
        const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        (void)send(client, response, sizeof(response) - 1, 0);
        close(client);
    }
    close(context->listener);
    return NULL;
}

static int make_listener(int *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &address_len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(address.sin_port);
    return fd;
}

static int connect_loopback(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int request_status(int forwarder_port, const char *request, int expected_status) {
    int fd = connect_loopback(forwarder_port);
    if (fd < 0 || send(fd, request, strlen(request), 0) != (ssize_t)strlen(request)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char response[256];
    ssize_t n = recv(fd, response, sizeof(response) - 1, 0);
    close(fd);
    if (n <= 0) return -1;
    response[n] = '\0';
    char status[32];
    snprintf(status, sizeof(status), "HTTP/1.1 %d ", expected_status);
    return strncmp(response, status, strlen(status)) == 0 ? 0 : -1;
}

static int test_request_body_boundaries(void) {
    int upstream_port = 0;
    struct upstream_context upstream = { make_listener(&upstream_port), ATOMIC_VAR_INIT(0) };
    if (upstream.listener < 0) return -1;
    pthread_t upstream_thread;
    if (pthread_create(&upstream_thread, NULL, serve_upstream, &upstream) != 0) {
        close(upstream.listener);
        return -1;
    }
    kp_forwarder *forwarder = kp_forwarder_new("127.0.0.1", 0, "", 0);
    if (!forwarder || kp_forwarder_start(forwarder) != 0) return -1;
    int forwarder_port = kp_forwarder_port(forwarder);
    char request[512];
    int request_len = snprintf(request, sizeof(request),
                               "POST http://127.0.0.1:%d/upload HTTP/1.1\r\nContent-Length: 10\r\n\r\npayload=OK",
                               upstream_port);
    int ok = request_len > 0 && (size_t)request_len < sizeof(request) &&
             request_status(forwarder_port, request, 200) == 0;
    pthread_join(upstream_thread, NULL);
    int body_forwarded = atomic_load(&upstream.received_expected_body);
    int oversize_rejected = request_status(forwarder_port,
                                           "POST http://127.0.0.1:80/upload HTTP/1.1\r\nContent-Length: 4096\r\n\r\n", 413) == 0;
    int chunked_rejected = request_status(forwarder_port,
                                          "POST http://127.0.0.1:80/upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 501) == 0;
    int ambiguous_rejected = request_status(forwarder_port,
                                            "POST http://127.0.0.1:80/upload HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", 400) == 0;
    ok = ok && body_forwarded && oversize_rejected && chunked_rejected && ambiguous_rejected;
    kp_forwarder_free(forwarder);
    return ok ? 0 : -1;
}

int main(void) {
    if (test_concurrent_lifecycle_transitions() != 0) {
        fprintf(stderr, "concurrent forwarder lifecycle test failed\n");
        return 1;
    }
    for (int iteration = 0; iteration < 100; iteration++) {
        kp_forwarder *forwarder = kp_forwarder_new("127.0.0.1", 0, "", 0);
        if (!forwarder || kp_forwarder_start(forwarder) != 0 ||
            !kp_forwarder_is_running(forwarder) || kp_forwarder_port(forwarder) <= 0) {
            fprintf(stderr, "forwarder startup failed at iteration %d\n", iteration);
            return 1;
        }
        struct reader_context context = { forwarder, ATOMIC_VAR_INIT(0) };
        pthread_t reader;
        if (pthread_create(&reader, NULL, read_forwarder_state, &context) != 0) {
            fprintf(stderr, "reader creation failed\n");
            kp_forwarder_free(forwarder);
            return 1;
        }
        struct timespec delay = { 0, 1000000L };
        nanosleep(&delay, NULL);
        kp_forwarder_stop(forwarder);
        atomic_store_explicit(&context.stop, 1, memory_order_relaxed);
        pthread_join(reader, NULL);
        if (kp_forwarder_is_running(forwarder) || kp_forwarder_port(forwarder) <= 0) {
            fprintf(stderr, "forwarder did not retain a safe stopped state\n");
            kp_forwarder_free(forwarder);
            return 1;
        }
        kp_forwarder_free(forwarder);
    }
    if (test_request_body_boundaries() != 0) {
        fprintf(stderr, "forwarder request body boundary test failed\n");
        return 1;
    }
    puts("King forwarder lifecycle regression test passed");
    return 0;
}
