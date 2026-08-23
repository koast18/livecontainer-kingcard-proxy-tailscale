#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../vendor/proxychains-ng/src/common.h"
#include "proxy_override.h"

extern void proxychains_write_log(char *str, ...);

static nw_proxy_config_t g_lc_proxy_config;
// WKWebsiteDataStore.setProxyConfigurations: 接收 nw_proxy_config 数组时通常不
// 为其元素做强引用（nw_proxy_config 是 CF 类型）。因此 reload 时若立即
// nw_release 旧 config，WebKit 下载/网络栈仍可能持有已释放指针 → UAF 崩溃
// （症状：调起系统下载组件、或高速下载时闪退）。
// 只延迟一代仍不够：短时间内连续 reload 时，WebKit 的多个 data store / 多个下载
// 可能分别持有不同代的 config。这里保留最多 3 个旧 config，超过后才释放最旧一个，
// 显著降低多代 UAF 风险。
#define LC_WEBKIT_MAX_OLD_PROXY_CONFIGS 3
static nw_proxy_config_t g_lc_proxy_config_old[LC_WEBKIT_MAX_OLD_PROXY_CONFIGS];
static int g_lc_proxy_config_old_count = 0;

static void lc_release_oldest_proxy_config(void) {
    if (g_lc_proxy_config_old_count < LC_WEBKIT_MAX_OLD_PROXY_CONFIGS)
        return;
    if (g_lc_proxy_config_old[0]) {
        nw_release(g_lc_proxy_config_old[0]);
        proxychains_write_log("[proxychains] webkit proxy: released oldest stale proxy config\n");
    }
    for (int i = 1; i < LC_WEBKIT_MAX_OLD_PROXY_CONFIGS; i++) {
        g_lc_proxy_config_old[i - 1] = g_lc_proxy_config_old[i];
        g_lc_proxy_config_old[i] = NULL;
    }
    g_lc_proxy_config_old_count--;
}

static void lc_retire_current_proxy_config(void) {
    if (!g_lc_proxy_config)
        return;
    lc_release_oldest_proxy_config();
    if (g_lc_proxy_config_old_count < LC_WEBKIT_MAX_OLD_PROXY_CONFIGS) {
        g_lc_proxy_config_old[g_lc_proxy_config_old_count++] = g_lc_proxy_config;
    }
    g_lc_proxy_config = NULL;
}

static int lc_parse_proxy(char *host, size_t hostlen,
                          char *port, size_t portlen,
                          char *user, size_t userlen,
                          char *pass, size_t passlen) {
    char buf[1024];
    char path[1024];
    const char *conf = get_config_path(getenv("PROXYCHAINS_CONF_FILE"), path, sizeof(path));
    FILE *f;
    int in_list = 0;
    int found = 0;

    if (!conf) {
        proxychains_write_log("[proxychains] webkit proxy: config file NOT found (LCProxy relative path)\n");
        return 0;
    }
    f = fopen(conf, "r");
    if (!f) {
        proxychains_write_log("[proxychains] webkit proxy: failed to open config file: %s\n", conf);
        return 0;
    }

    while (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        char *nl;
        char type[32] = {0};
        char h[256] = {0};
        char pt[16] = {0};
        char u[128] = {0};
        char pw[128] = {0};
        int n;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\n' || *p == '\r' || *p == '\0' || *p == '#')
            continue;

        nl = strchr(p, '\n');
        if (nl) *nl = 0;
        nl = strchr(p, '\r');
        if (nl) *nl = 0;

        if (!in_list) {
            if (strcmp(p, "[ProxyList]") == 0)
                in_list = 1;
            continue;
        }

        n = sscanf(p, "%31s %255s %15s %127s %127s", type, h, pt, u, pw);
        if (n >= 3 && strcmp(type, "http") == 0) {
            snprintf(host, hostlen, "%s", h);
            snprintf(port, portlen, "%s", pt);
            if (n >= 4)
                snprintf(user, userlen, "%s", u);
            else
                user[0] = 0;
            if (n >= 5)
                snprintf(pass, passlen, "%s", pw);
            else
                pass[0] = 0;
            proxychains_write_log("[proxychains] webkit proxy: parsed http proxy %s:%s\n", h, pt);
            found = 1;
            break;
        }
    }

    if (!found)
        proxychains_write_log("[proxychains] webkit proxy: no http proxy found in [ProxyList]\n");

    fclose(f);
    return found;
}

static int lc_create_proxy_config(void) {
    char host[256];
    char port[16];
    char user[128];
    char pass[128];
    nw_endpoint_t ep;

    if (g_lc_proxy_config)
        return 1;

    int overridePort = 0;
    if (lcproxy_control_get_proxy_override(host, sizeof(host), &overridePort)) {
        snprintf(port, sizeof(port), "%d", overridePort);
        user[0] = 0;
        pass[0] = 0;
        proxychains_write_log("[proxychains] webkit proxy: using per-process override %s:%s\n", host, port);
    } else if (!lc_parse_proxy(host, sizeof(host), port, sizeof(port),
                               user, sizeof(user), pass, sizeof(pass))) {
        proxychains_write_log("[proxychains] webkit proxy: no http proxy parsed\n");
        return 0;
    }
    if (!@available(iOS 17.0, *)) {
        proxychains_write_log("[proxychains] webkit proxy: requires iOS 17+ for WKWebsiteDataStore proxyConfigurations\n");
        return 0;
    }

    proxychains_write_log("[proxychains] webkit proxy: creating nw_proxy_config for %s:%s\n", host, port);
    ep = nw_endpoint_create_host(host, port);
    if (!ep) {
        proxychains_write_log("[proxychains] webkit proxy: nw_endpoint_create_host failed\n");
        return 0;
    }

    g_lc_proxy_config = nw_proxy_config_create_http_connect(ep, NULL);
    nw_release(ep);
    if (!g_lc_proxy_config) {
        proxychains_write_log("[proxychains] webkit proxy: nw_proxy_config_create_http_connect failed\n");
        return 0;
    }
    proxychains_write_log("[proxychains] webkit proxy: nw_proxy_config created\n");

    if (user[0])
        nw_proxy_config_set_username_and_password(g_lc_proxy_config, user, pass[0] ? pass : NULL);

    return 1;
}

static void lc_clear_proxy_from_store(id store) {
    if (!store) {
        proxychains_write_log("[proxychains] webkit proxy: clear store is nil, skip\n");
        return;
    }
    if (![store respondsToSelector:@selector(setProxyConfigurations:)]) {
        proxychains_write_log("[proxychains] webkit proxy: store %s does not support setProxyConfigurations:\n", object_getClassName(store));
        return;
    }
    if (@available(iOS 17.0, *)) {
        proxychains_write_log("[proxychains] webkit proxy: clearing proxy configs for store %s\n", object_getClassName(store));
        [store setProxyConfigurations:@[]];
        proxychains_write_log("[proxychains] webkit proxy: clear setProxyConfigurations sent to store %s\n", object_getClassName(store));
    }
}

static void lc_apply_proxy_to_store(id store) {
    NSArray *configs;

    if (!store) {
        proxychains_write_log("[proxychains] webkit proxy: store is nil, skip\n");
        return;
    }
    if (![store respondsToSelector:@selector(setProxyConfigurations:)]) {
        proxychains_write_log("[proxychains] webkit proxy: store %s does not support setProxyConfigurations:\n", object_getClassName(store));
        return;
    }
    if (!lc_create_proxy_config()) {
        // No proxy configured (direct mode): make sure any previously applied
        // WKWebView proxy configuration is cleared so traffic really goes direct.
        lc_clear_proxy_from_store(store);
        return;
    }

    if (@available(iOS 17.0, *)) {
        configs = [NSArray arrayWithObjects:(id)g_lc_proxy_config, nil];
        proxychains_write_log("[proxychains] webkit proxy: applying proxy configs to store %s\n", object_getClassName(store));
        [store setProxyConfigurations:configs];
        proxychains_write_log("[proxychains] webkit proxy: setProxyConfigurations sent to store %s\n", object_getClassName(store));
    }
}
static IMP orig_setWebsiteDataStore;
static void lc_setWebsiteDataStore(id self, SEL _cmd, id store) {
    ((void (*)(id, SEL, id))orig_setWebsiteDataStore)(self, _cmd, store);
    lc_apply_proxy_to_store(store);
}

static IMP orig_nonPersistentDataStore;
static id lc_nonPersistentDataStore(id self, SEL _cmd) {
    id store = ((id (*)(id, SEL))orig_nonPersistentDataStore)(self, _cmd);
    lc_apply_proxy_to_store(store);
    return store;
}

void livecontainer_install_webkit_proxy(void) {
    Class wds;
    Class cfg;
    Method m;
    id (*msg)(id, SEL) = (id (*)(id, SEL))objc_msgSend;

    proxychains_write_log("[proxychains] webkit proxy: install begin\n");

    if (!lc_create_proxy_config()) {
        proxychains_write_log("[proxychains] webkit proxy: no usable HTTP proxy found at install, WKWebView proxy will be cleared\n");
    }

    wds = NSClassFromString(@"WKWebsiteDataStore");
    if (wds) {
        proxychains_write_log("[proxychains] webkit proxy: WKWebsiteDataStore class found\n");
        id defaultStore = msg(wds, sel_registerName("defaultDataStore"));
        proxychains_write_log("[proxychains] webkit proxy: defaultDataStore=%s\n", object_getClassName(defaultStore));
        lc_apply_proxy_to_store(defaultStore);

        m = class_getClassMethod(wds, sel_registerName("nonPersistentDataStore"));
        if (m) {
            orig_nonPersistentDataStore = method_getImplementation(m);
            method_setImplementation(m, (IMP)lc_nonPersistentDataStore);
            proxychains_write_log("[proxychains] webkit proxy: nonPersistentDataStore swizzled\n");
        } else {
            proxychains_write_log("[proxychains] webkit proxy: nonPersistentDataStore method NOT found\n");
        }
    }

    if (!wds)
        proxychains_write_log("[proxychains] webkit proxy: WKWebsiteDataStore unavailable\n");

    cfg = NSClassFromString(@"WKWebViewConfiguration");
    if (cfg) {
        m = class_getInstanceMethod(cfg, sel_registerName("setWebsiteDataStore:"));
        if (m) {
            orig_setWebsiteDataStore = method_getImplementation(m);
            method_setImplementation(m, (IMP)lc_setWebsiteDataStore);
            proxychains_write_log("[proxychains] webkit proxy: setWebsiteDataStore: swizzled\n");
        } else {
            proxychains_write_log("[proxychains] webkit proxy: setWebsiteDataStore: method NOT found\n");
        }
    } else {
        proxychains_write_log("[proxychains] webkit proxy: WKWebViewConfiguration class NOT found\n");
    }
}

void livecontainer_reload_webkit_proxy(void) {
    proxychains_write_log("[proxychains] webkit proxy reload: begin\n");
    // 当前 g_lc_proxy_config 降级为 old 保留——WebKit 极可能仍持有它。
    // 只有当保留的旧 config 超过 3 个时，才释放最旧的一个。
    lc_retire_current_proxy_config();
    if (!lc_create_proxy_config()) {
        proxychains_write_log("[proxychains] webkit proxy reload: no usable HTTP proxy found\n");
        Class wds = NSClassFromString(@"WKWebsiteDataStore");
        if (wds) {
            id (*msg)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id defaultStore = msg(wds, sel_registerName("defaultDataStore"));
            proxychains_write_log("[proxychains] webkit proxy reload: defaultDataStore=%s\n", object_getClassName(defaultStore));
            lc_clear_proxy_from_store(defaultStore);
        } else {
            proxychains_write_log("[proxychains] webkit proxy reload: WKWebsiteDataStore unavailable\n");
        }
        return;
    }
    Class wds = NSClassFromString(@"WKWebsiteDataStore");
    if (wds) {
        id (*msg)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id defaultStore = msg(wds, sel_registerName("defaultDataStore"));
        proxychains_write_log("[proxychains] webkit proxy reload: defaultDataStore=%s\n", object_getClassName(defaultStore));
        lc_apply_proxy_to_store(defaultStore);
        proxychains_write_log("[proxychains] webkit proxy reloaded\n");
    } else {
        proxychains_write_log("[proxychains] webkit proxy reload: WKWebsiteDataStore unavailable\n");
    }
}
