#import "LCProxyServer.h"
#import "LCProxyConfig.h"
#import "LCProxyStats.h"
#import "LCProxyPaths.h"
#import "ConsoleHTML.h"
#import "lcproxy_bridge.h"
#import "LCProxyKing.h"
#import "LCTailscaleManager.h"
#import "KPKIngCore.h"
#include "webkit_proxy.h"
#include <arpa/inet.h>
#import "GCDWebServer.h"
#import "GCDWebServerDataRequest.h"
#import "GCDWebServerDataResponse.h"
#import "GCDWebServerRequest.h"

static NSString *const LCProxyVersion = @"0.5.22";
static const NSUInteger LCProxyDefaultPort = 19092;

@interface LCProxyServer ()
@property (nonatomic, strong) GCDWebServer *server;
@end

@implementation LCProxyServer

+ (instancetype)shared {
    static LCProxyServer *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        instance = [[LCProxyServer alloc] init];
    });
    return instance;
}

- (BOOL)isRunning {
    return _server != nil && _server.isRunning;
}

- (int)port {
    return (int)_server.port;
}

#pragma mark - JSON helpers

- (GCDWebServerResponse *)json:(id)obj {
    NSData *data = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    GCDWebServerDataResponse *resp = [GCDWebServerDataResponse responseWithData:data contentType:@"application/json; charset=utf-8"];
    return resp;
}

- (GCDWebServerResponse *)jsonError:(NSString *)msg statusCode:(NSInteger)code {
    GCDWebServerDataResponse *resp = [GCDWebServerDataResponse responseWithData:
        [NSJSONSerialization dataWithJSONObject:@{@"error": msg ?: @""} options:0 error:nil]
        contentType:@"application/json; charset=utf-8"];
    resp.statusCode = code;
    return resp;
}

- (NSDictionary *)jsonBody:(GCDWebServerRequest *)request {
    NSData *data = nil;
    if ([request isKindOfClass:[GCDWebServerDataRequest class]]) {
        data = [(GCDWebServerDataRequest *)request data];
    }
    if (!data) return @{};
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
}

- (NSDictionary *)configPayload {
    NSDictionary *cfg = [[LCProxyConfig shared] load];
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:cfg];
    d[@"cellular"] = @(lcproxy_stats_is_cellular() != 0);
    d[@"effectiveMode"] = [[LCProxyConfig shared] effectiveProxyModeForSettings:cfg];
    d[@"proxyCount"] = @(lcproxy_control_get_proxy_count());
    d[@"serverPort"] = @(self.port);
    d[@"version"] = LCProxyVersion;
    d[@"dataDirectory"] = LCProxyDataDirectory();
    d[@"proxychainsConfPath"] = [[LCProxyConfig shared] proxychainsConfPath];
    d[@"proxychainsConfExists"] = @([[NSFileManager defaultManager] fileExistsAtPath:[[LCProxyConfig shared] proxychainsConfPath]]);
    d[@"settingsPath"] = [[LCProxyConfig shared] settingsPath];
    d[@"settingsExists"] = @([[NSFileManager defaultManager] fileExistsAtPath:[[LCProxyConfig shared] settingsPath]]);
    d[@"king"] = [[LCProxyKing shared] status];
    d[@"tailscale"] = @{
        @"running": @([[LCTailscaleManager shared] isRunning]),
        @"starting": @([[LCTailscaleManager shared] isStarting]),
        @"proxyPort": @([[LCTailscaleManager shared] localProxyPort]),
        @"backendState": [[LCTailscaleManager shared] backendState] ?: @"",
        @"authURL": [[LCTailscaleManager shared] authURL] ?: @"",
        @"exitNodes": [[LCTailscaleManager shared] exitNodes] ?: @[],
        @"selectedExitNodeID": [[LCTailscaleManager shared] selectedExitNodeID] ?: @"",
        @"exitNodeEnabled": @([[LCTailscaleManager shared] exitNodeEnabled]),
        @"lastError": [[LCTailscaleManager shared] lastError] ?: @""
    };
    NSDictionary *stats = [[LCProxyStats shared] aggregate];
    d[@"kingAggregate"] = stats[@"forwarder"] ?: @{};
    return d;
}

#pragma mark - Proxy exit IP test

- (NSString *)extractIPFromString:(NSString *)text {
    if (!text.length) return nil;
    NSCharacterSet *separators = [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n,;"];
    NSArray *tokens = [text componentsSeparatedByCharactersInSet:separators];
    for (NSString *token in tokens) {
        NSString *t = [token stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]:"]];
        if (!t.length) continue;
        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET, t.UTF8String, &addr4) == 1) return t;
        if (inet_pton(AF_INET6, t.UTF8String, &addr6) == 1) return t;
    }
    return nil;
}

- (NSString *)plainTextFromHTML:(NSString *)html {
    if (!html.length) return @"";
    NSError *err = nil;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"<[^>]+>" options:0 error:&err];
    NSString *s = err ? html : [re stringByReplacingMatchesInString:html options:0 range:NSMakeRange(0, html.length) withTemplate:@" "];
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return s ?: @"";
}

- (NSDictionary *)proxyTestOne:(NSString *)urlString {
    NSDictionary *settings = [[LCProxyConfig shared] load];
    BOOL enabled = [settings[@"proxyEnabled"] boolValue];
    NSString *mode = [settings[@"proxyMode"] isKindOfClass:[NSString class]] ? settings[@"proxyMode"] : @"custom";
    NSString *effectiveMode = [[LCProxyConfig shared] effectiveProxyModeForSettings:settings];

    NSString *upstreamHost = nil;
    NSInteger upstreamPort = 0;
    BOOL direct = NO;
    if (enabled && [effectiveMode isEqualToString:@"direct"]) {
        direct = YES;
    } else if (enabled && [effectiveMode isEqualToString:@"kingcard"]) {
        upstreamHost = @"127.0.0.1";
        upstreamPort = [[LCProxyKing shared] localForwarderPort];
    } else if (enabled) {
        upstreamHost = [settings[@"proxyHost"] isKindOfClass:[NSString class]] && [settings[@"proxyHost"] length] ? settings[@"proxyHost"] : nil;
        upstreamPort = [settings[@"proxyPort"] respondsToSelector:@selector(integerValue)] ? [settings[@"proxyPort"] integerValue] : 0;
    }
    if (!direct && (!upstreamHost.length || (upstreamPort <= 0 && ![effectiveMode isEqualToString:@"kingcard"]))) {
        return @{@"url": urlString ?: @"", @"rc": @(-1), @"ip": @"", @"body": @"代理未启用或代理地址无效", @"ok": @NO};
    }

    // 王卡模式：确保转发器运行且凭证已加载。最多等 8 秒，避免测试接口被网络刷新阻塞。
    if (enabled && [mode isEqualToString:@"kingcard"] && ![effectiveMode isEqualToString:@"direct"]) {
        if (![[LCProxyKing shared] ensureCredentialsReadyWithTimeout:8.0]) {
            return @{@"url": urlString ?: @"", @"rc": @(-1), @"ip": @"", @"body": @"王卡凭证正在刷新或暂不可用，请稍后重试", @"ok": @NO, @"effectiveMode": effectiveMode};
        }
        upstreamPort = [[LCProxyKing shared] localForwarderPort];
        if (upstreamPort <= 0) {
            return @{@"url": urlString ?: @"", @"rc": @(-1), @"ip": @"", @"body": @"王卡转发器未就绪", @"ok": @NO, @"effectiveMode": effectiveMode};
        }
    }

    NSURL *url = [NSURL URLWithString:urlString];
    if (!url.host.length) {
        return @{@"url": urlString ?: @"", @"rc": @(-1), @"ip": @"", @"body": @"无效 URL", @"ok": @NO};
    }
    NSString *host = url.host;
    NSInteger port = url.port ? url.port.integerValue : 80;
    NSString *path = url.path.length ? url.path : @"/";
    if (url.query.length) path = [path stringByAppendingFormat:@"?%@", url.query];

    char body[2048] = {0};
    int rc;
    if (direct) {
        rc = kp_http_get_direct(host.UTF8String, (int)port, path.UTF8String,
                                6000, body, sizeof(body));
    } else {
        rc = kp_http_get_via_proxy(upstreamHost.UTF8String, (int)upstreamPort,
                                   host.UTF8String, (int)port, path.UTF8String,
                                   "", "", 6000,
                                   body, sizeof(body));
    }
    NSString *text = rc == 0 ? [NSString stringWithUTF8String:body] : nil;
    NSString *ip = [self extractIPFromString:text];
    NSMutableDictionary *item = [NSMutableDictionary dictionary];
    item[@"url"] = urlString ?: @"";
    item[@"rc"] = @(rc);
    item[@"ip"] = ip ?: @"";
    NSString *bodyText = [self plainTextFromHTML:text];
    item[@"body"] = bodyText.length > 120 ? [bodyText substringToIndex:120] : bodyText;
    item[@"ok"] = @(ip.length > 0);
    item[@"effectiveMode"] = effectiveMode;
    return item;
}

- (NSDictionary *)proxyTestResult {
    NSDictionary *settings = [[LCProxyConfig shared] load];
    BOOL enabled = [settings[@"proxyEnabled"] boolValue];
    NSString *mode = [settings[@"proxyMode"] isKindOfClass:[NSString class]] ? settings[@"proxyMode"] : @"custom";
    NSString *effectiveMode = [[LCProxyConfig shared] effectiveProxyModeForSettings:settings];

    NSString *upstreamHost = nil;
    NSInteger upstreamPort = 0;
    BOOL direct = NO;
    if (enabled && [effectiveMode isEqualToString:@"direct"]) {
        direct = YES;
    } else if (enabled && [effectiveMode isEqualToString:@"kingcard"]) {
        upstreamHost = @"127.0.0.1";
        upstreamPort = [[LCProxyKing shared] localForwarderPort];
    } else if (enabled) {
        upstreamHost = [settings[@"proxyHost"] isKindOfClass:[NSString class]] && [settings[@"proxyHost"] length] ? settings[@"proxyHost"] : nil;
        upstreamPort = [settings[@"proxyPort"] respondsToSelector:@selector(integerValue)] ? [settings[@"proxyPort"] integerValue] : 0;
    }
    if (!direct && (!upstreamHost.length || (upstreamPort <= 0 && ![effectiveMode isEqualToString:@"kingcard"]))) {
        return @{@"ok": @NO, @"error": @"代理未启用或代理地址无效", @"results": @[]};
    }

    // 王卡模式：确保转发器运行且凭证已加载。最多等 8 秒，避免测试接口被网络刷新阻塞。
    if (enabled && [mode isEqualToString:@"kingcard"] && ![effectiveMode isEqualToString:@"direct"]) {
        if (![[LCProxyKing shared] ensureCredentialsReadyWithTimeout:8.0]) {
            return @{@"ok": @NO, @"error": @"王卡凭证正在刷新或暂不可用，请稍后重试", @"results": @[], @"mode": mode, @"effectiveMode": effectiveMode};
        }
        upstreamPort = [[LCProxyKing shared] localForwarderPort];
        if (upstreamPort <= 0) {
            return @{@"ok": @NO, @"error": @"王卡转发器未就绪", @"results": @[], @"mode": mode, @"effectiveMode": effectiveMode};
        }
    }

    NSArray<NSString *> *sources = @[
        @"http://ip.3322.net",
        @"http://ifconfig.me/ip",
        @"http://icanhazip.com",
        @"http://members.3322.org/dyndns/getip",
        @"http://ip-api.com/line/?fields=query",
        @"http://myip.ipip.net",
    ];

    NSMutableArray *results = [NSMutableArray array];
    NSString *firstIP = nil;
    NSString *firstSource = nil;
    for (NSString *urlString in sources) {
        NSURL *url = [NSURL URLWithString:urlString];
        if (!url.host.length) continue;
        NSString *host = url.host;
        NSInteger port = url.port ? url.port.integerValue : 80;
        NSString *path = url.path.length ? url.path : @"/";
        if (url.query.length) path = [path stringByAppendingFormat:@"?%@", url.query];

        char body[2048] = {0};
        int rc;
        if (direct) {
            rc = kp_http_get_direct(host.UTF8String, (int)port, path.UTF8String,
                                    8000, body, sizeof(body));
        } else {
            rc = kp_http_get_via_proxy(upstreamHost.UTF8String, (int)upstreamPort,
                                       host.UTF8String, (int)port, path.UTF8String,
                                       "", "", 8000,
                                       body, sizeof(body));
        }
        NSString *text = rc == 0 ? [NSString stringWithUTF8String:body] : nil;
        NSString *ip = [self extractIPFromString:text];
        if (ip.length && !firstIP) {
            firstIP = ip;
            firstSource = urlString;
        }
        NSMutableDictionary *item = [NSMutableDictionary dictionary];
        item[@"url"] = urlString;
        item[@"rc"] = @(rc);
        item[@"ip"] = ip ?: @"";
        NSString *bodyText = [self plainTextFromHTML:text];
        item[@"body"] = bodyText.length > 120 ? [bodyText substringToIndex:120] : bodyText;
        [results addObject:item];
    }

    NSMutableDictionary *resp = [NSMutableDictionary dictionary];
    resp[@"results"] = results;
    resp[@"mode"] = mode;
    resp[@"effectiveMode"] = effectiveMode;
    if (firstIP.length) {
        resp[@"ok"] = @YES;
        resp[@"ip"] = firstIP;
        resp[@"source"] = firstSource ?: @"";
    } else {
        resp[@"ok"] = @NO;
        resp[@"error"] = @"所有 IP 源均失败，请检查代理/转发器";
        if ([mode isEqualToString:@"kingcard"]) {
            resp[@"king"] = [[LCProxyKing shared] status];
        }
    }
    return resp;
}

#pragma mark - Start

- (BOOL)start {
    if (self.isRunning) return YES;
    GCDWebServer *server = [[GCDWebServer alloc] init];

    [server addDefaultHandlerForMethod:@"GET"
                         requestClass:[GCDWebServerRequest class]
                         processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        return [GCDWebServerDataResponse responseWithHTML:[NSString stringWithUTF8String:kLCProxyConsoleHTML]];
    }];

    [server addHandlerForMethod:@"GET" path:@"/api/status" requestClass:[GCDWebServerRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        return [self json:[self configPayload]];
    }];

    [server addHandlerForMethod:@"GET" path:@"/api/stats" requestClass:[GCDWebServerRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        return [self json:[[LCProxyStats shared] aggregate]];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/config" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        NSDictionary *body = [self jsonBody:request];
        NSMutableDictionary *merged = [NSMutableDictionary dictionaryWithDictionary:[[LCProxyConfig shared] load]];
        for (NSString *key in @[@"proxyEnabled", @"blockNonTcp", @"debugLogging", @"showProxyBanner", @"proxyMode", @"proxyType", @"proxyHost", @"proxyPort",
                                 @"kingUpstreamHost", @"kingUpstreamPort", @"kingRefreshURL", @"kingAutoDirectOnNonCellular",
                                 @"kingGuidOverride", @"kingTokenOverride", @"kingKeyOverride", @"kingPhone", @"kingQType",
                                 @"kingApn", @"kingTypeName", @"kingSubtype", @"kingExtraInfo", @"kingMccmnc", @"kingCardType",
                                 @"tailscaleHostname", @"tailscaleAuthKey", @"tailscaleControlURL", @"tailscaleStateDir",
                                 @"tailscaleEphemeral", @"tailscaleForceDerpOnly", @"tailscaleExitNodeID", @"tailscaleExitNodeEnabled"]) {
            if (body[key] != nil) merged[key] = body[key];
        }
        if (![[LCProxyConfig shared] saveSettings:merged]) {
            return [self jsonError:@"保存配置失败" statusCode:500];
        }
        [[LCProxyConfig shared] applyToRuntime];
        return [self json:[self configPayload]];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/king/refresh" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        // 手动“立即刷新凭证”：强制真实请求上游，不走本地缓存。
        BOOL ok = [[LCProxyKing shared] refreshCredentialsForce];
        NSMutableDictionary *resp = [NSMutableDictionary dictionaryWithDictionary:[[LCProxyKing shared] status]];
        resp[@"ok"] = @(ok);
        return [self json:resp];
    }];

    [server addHandlerForMethod:@"GET" path:@"/api/tailscale/status" requestClass:[GCDWebServerRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        NSMutableDictionary *resp = [NSMutableDictionary dictionary];
        resp[@"running"] = @([[LCTailscaleManager shared] isRunning]);
        resp[@"starting"] = @([[LCTailscaleManager shared] isStarting]);
        resp[@"proxyPort"] = @([[LCTailscaleManager shared] localProxyPort]);
        resp[@"backendState"] = [[LCTailscaleManager shared] backendState] ?: @"";
        resp[@"authURL"] = [[LCTailscaleManager shared] authURL] ?: @"";
        resp[@"exitNodes"] = [[LCTailscaleManager shared] exitNodes] ?: @[];
        resp[@"selectedExitNodeID"] = [[LCTailscaleManager shared] selectedExitNodeID] ?: @"";
        resp[@"exitNodeEnabled"] = @([[LCTailscaleManager shared] exitNodeEnabled]);
        resp[@"status"] = [[LCTailscaleManager shared] status] ?: @{};
        return [self json:resp];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/tailscale/exit-node" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        NSDictionary *body = [self jsonBody:request];
        NSString *exitID = [body[@"id"] isKindOfClass:[NSString class]] ? body[@"id"] : @"";
        BOOL enabled = [body[@"enabled"] boolValue];
        BOOL ok = [[LCTailscaleManager shared] setExitNode:exitID enabled:enabled];
        NSMutableDictionary *resp = [NSMutableDictionary dictionary];
        resp[@"ok"] = @(ok);
        resp[@"selectedExitNodeID"] = [[LCTailscaleManager shared] selectedExitNodeID] ?: @"";
        resp[@"exitNodeEnabled"] = @([[LCTailscaleManager shared] exitNodeEnabled]);
        if (!ok) resp[@"error"] = @"设置 exit node 失败";
        return [self json:resp];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/proxy-test-one" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        NSDictionary *body = [self jsonBody:request];
        NSString *url = [body[@"url"] isKindOfClass:[NSString class]] ? body[@"url"] : @"";
        return [self json:[self proxyTestOne:url]];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/proxy-test" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        return [self json:[self proxyTestResult]];
    }];

    [server addHandlerForMethod:@"POST" path:@"/api/reset-stats" requestClass:[GCDWebServerDataRequest class]
                   processBlock:^GCDWebServerResponse *(GCDWebServerRequest *request) {
        NSString *dir = [LCProxyDataDirectory() stringByAppendingPathComponent:@"stats"];
        NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *f in files) {
            if ([f hasSuffix:@".json"]) {
                [[NSFileManager defaultManager] removeItemAtPath:[dir stringByAppendingPathComponent:f] error:nil];
            }
        }
        return [self json:@{@"ok": @YES}];
    }];

    NSError *err = nil;
    BOOL ok = [server startWithOptions:@{
        GCDWebServerOption_Port: @(LCProxyDefaultPort),
        GCDWebServerOption_BindToLocalhost: @YES,
        GCDWebServerOption_AutomaticallySuspendInBackground: @NO,
    } error:&err];
    if (!ok) {
        NSLog(@"[LCProxy] web server start failed: %@", err.localizedDescription ?: @"?");
        return NO;
    }
    _server = server;
    return YES;
}

@end
