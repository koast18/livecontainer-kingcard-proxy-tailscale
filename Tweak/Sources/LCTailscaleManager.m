#import "LCTailscaleManager.h"
#import "LCProxyPaths.h"
#import "LCProxyKing.h"
#import "LCProxyConfig.h"
#import "tailscale.h"
#import <netinet/in.h>
#import <arpa/inet.h>
#import <errno.h>
#import <string.h>

static const NSTimeInterval LCTailscaleStatusCacheInterval = 1.0;
static const size_t LCTailscaleJSONInitialCapacity = 64 * 1024;
static const size_t LCTailscaleJSONMaximumCapacity = 4 * 1024 * 1024;

@interface LCTailscaleManager ()
@property (nonatomic, strong) NSLock *lock;
@property (nonatomic, assign) int sd;
@property (nonatomic, assign) BOOL running;
@property (nonatomic, assign) BOOL starting;
@property (nonatomic, assign) int proxyPort;
@property (nonatomic, copy) NSString *proxyUser;
@property (nonatomic, copy) NSString *proxyPassword;
@property (nonatomic, copy) NSString *lastError;
@property (nonatomic, copy) NSString *lastSettingsSignature;
@property (nonatomic, strong) NSDictionary *lastStatus;
@property (nonatomic, strong) NSArray<NSDictionary *> *lastExitNodes;
@property (nonatomic, copy) NSString *lastSelectedExitNodeID;
@property (nonatomic, assign) BOOL lastExitNodeEnabled;
@property (nonatomic, assign) int generation;
@property (nonatomic, copy) NSString *authURL;
@property (nonatomic, copy) NSString *backendState;
@property (nonatomic, strong) NSDate *lastStatusRefresh;
- (void)startWithSettings:(NSDictionary *)settings;
- (NSDictionary *)statusForSD:(int)sd;
- (NSData *)jsonDataForSD:(int)sd fetch:(int (*)(tailscale, char *, size_t))fetch;
- (void)stop;
- (NSString *)settingsSignature:(NSDictionary *)settings;
- (NSString *)instanceIdentifier;
- (NSString *)stateDirectoryForSettings:(NSDictionary *)settings;
- (NSString *)hostnameForSettings:(NSDictionary *)settings;
- (void)finishStartForGeneration:(int)generation error:(NSString *)error;
@end

@implementation LCTailscaleManager

+ (instancetype)shared {
    static LCTailscaleManager *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        instance = [[LCTailscaleManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _lock = [[NSLock alloc] init];
        _sd = -1;
        _proxyUser = @"tsnet";
    }
    return self;
}

- (NSString *)settingsSignature:(NSDictionary *)settings {
    NSArray *keys = @[
        @"proxyEnabled", @"proxyMode",
        @"tailscaleHostname", @"tailscaleAuthKey", @"tailscaleControlURL",
        @"tailscaleStateDir", @"tailscaleEphemeral",
        @"tailscaleForceDerpOnly", @"tailscaleExitNodeID", @"tailscaleExitNodeEnabled",
        @"kingUpstreamHost", @"kingUpstreamPort", @"kingRefreshURL",
        @"kingPhone", @"kingQType", @"kingMccmnc", @"kingApn", @"kingTypeName",
        @"kingSubtype", @"kingExtraInfo", @"kingCardType",
        @"kingGuidOverride", @"kingTokenOverride", @"kingKeyOverride"
    ];
    NSMutableString *sig = [NSMutableString string];
    for (NSString *key in keys) {
        id v = settings[key];
        if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSNumber class]]) {
            [sig appendFormat:@"%@=%@|", key, v];
        } else if ([v isKindOfClass:[NSNull class]]) {
            [sig appendFormat:@"%@=null|", key];
        } else {
            [sig appendFormat:@"%@=|", key];
        }
    }
    return sig;
}

- (NSString *)instanceIdentifier {
    NSString *raw = [[NSBundle mainBundle] bundleIdentifier];
    if (!raw.length) raw = [[NSProcessInfo processInfo] processName];
    if (!raw.length) raw = @"unknown";
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"];
    NSMutableString *identifier = [NSMutableString string];
    for (NSUInteger i = 0; i < raw.length; i++) {
        unichar c = [raw characterAtIndex:i];
        [identifier appendFormat:@"%C", [allowed characterIsMember:c] ? c : '-'];
    }
    while ([identifier containsString:@"--"]) {
        [identifier replaceOccurrencesOfString:@"--" withString:@"-" options:0 range:NSMakeRange(0, identifier.length)];
    }
    if (!identifier.length) return @"unknown";
    return identifier.length > 40 ? [identifier substringToIndex:40] : identifier;
}

- (NSString *)stateDirectoryForSettings:(NSDictionary *)settings {
    NSString *base = [LCProxyDataDirectory() stringByAppendingPathComponent:@"tailscale"];
    NSString *configured = [settings[@"tailscaleStateDir"] isKindOfClass:[NSString class]] ? settings[@"tailscaleStateDir"] : nil;
    if (configured.length) base = configured;
    // Every injected app is a separate tsnet node; never let two processes mutate one state file.
    return [base stringByAppendingPathComponent:[self instanceIdentifier]];
}

- (NSString *)hostnameForSettings:(NSDictionary *)settings {
    NSString *base = [settings[@"tailscaleHostname"] isKindOfClass:[NSString class]] && [settings[@"tailscaleHostname"] length] ? settings[@"tailscaleHostname"] : @"lc-tailscale";
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"];
    NSMutableString *clean = [NSMutableString string];
    for (NSUInteger i = 0; i < base.length; i++) {
        unichar c = [base characterAtIndex:i];
        [clean appendFormat:@"%C", [allowed characterIsMember:c] ? c : '-'];
    }
    NSString *suffix = [self instanceIdentifier];
    NSUInteger prefixLimit = 63 - suffix.length - 1;
    if (prefixLimit < 1) return [suffix substringToIndex:MIN((NSUInteger)63, suffix.length)];
    if (clean.length > prefixLimit) clean = [[clean substringToIndex:prefixLimit] mutableCopy];
    return [NSString stringWithFormat:@"%@-%@", clean.length ? clean : @"lc", suffix];
}

- (void)applyConfig:(NSDictionary *)settings {
    // applyConfig may be called from network and console queues concurrently.
    // Keep the signature, stop/start decision, and generation invalidation atomic.
    @synchronized (self) {
        NSString *mode = [settings[@"proxyMode"] isKindOfClass:[NSString class]] ? settings[@"proxyMode"] : @"custom";
        BOOL enabled = [settings[@"proxyEnabled"] boolValue];
        BOOL shouldRun = enabled && [mode isEqualToString:@"tailscale"];
        NSString *signature = [self settingsSignature:settings];

        [self.lock lock];
        BOOL alreadyRunning = self.running && self.sd >= 0;
        BOOL starting = self.starting;
        BOOL configChanged = !self.lastSettingsSignature || ![signature isEqualToString:self.lastSettingsSignature];
        [self.lock unlock];

        if (!shouldRun) {
            if (alreadyRunning || starting) {
                [self stop];
            }
            [self.lock lock];
            self.lastSettingsSignature = signature;
            [self.lock unlock];
            return;
        }

        if (alreadyRunning && !configChanged) {
            [self.lock lock];
            self.lastSettingsSignature = signature;
            [self.lock unlock];
            [self refreshStatus];
            return;
        }

        if (alreadyRunning || starting) {
            [self stop];
        }

        [self.lock lock];
        self.lastSettingsSignature = signature;
        [self.lock unlock];
        [self startWithSettings:settings];
    }
}

- (void)startWithSettings:(NSDictionary *)settings {
    [self.lock lock];
    if (self.starting || self.running) {
        [self.lock unlock];
        return;
    }
    self.starting = YES;
    self.lastError = nil;
    self.generation++;
    int generation = self.generation;
    [self.lock unlock];

    NSString *stateDir = [self stateDirectoryForSettings:settings];
    NSString *hostname = [self hostnameForSettings:settings];
    NSString *authKey = [settings[@"tailscaleAuthKey"] isKindOfClass:[NSString class]] ? settings[@"tailscaleAuthKey"] : @"";
    NSString *controlURL = [settings[@"tailscaleControlURL"] isKindOfClass:[NSString class]] ? settings[@"tailscaleControlURL"] : @"";
    BOOL ephemeral = [settings[@"tailscaleEphemeral"] boolValue];

    // Tailscale outbound (control + DERP) goes through the local KingCard
    // forwarder in this same process.
    int kingPort = [[LCProxyKing shared] localForwarderPort];
    NSString *proxyURL = kingPort > 0 ? [NSString stringWithFormat:@"http://127.0.0.1:%d", kingPort] : @"";

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        int sd = tailscale_new();
        if (sd < 0) {
            [self finishStartForGeneration:generation error:@"tailscale_new failed"];
            return;
        }
        [self.lock lock];
        BOOL generationOK = (self.generation == generation);
        [self.lock unlock];
        if (!generationOK) {
            tailscale_close(sd);
            return;
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:stateDir withIntermediateDirectories:YES attributes:nil error:nil];
        if (tailscale_set_dir(sd, stateDir.UTF8String) != 0 ||
            tailscale_set_hostname(sd, hostname.UTF8String) != 0 ||
            tailscale_set_authkey(sd, authKey.UTF8String) != 0 ||
            (controlURL.length && tailscale_set_control_url(sd, controlURL.UTF8String) != 0) ||
            tailscale_set_ephemeral(sd, ephemeral ? 1 : 0) != 0 ||
            tailscale_set_disable_p2p(sd, [settings[@"tailscaleForceDerpOnly"] boolValue] ? 1 : 0) != 0) {
            char err[1024] = {0};
            tailscale_errmsg(sd, err, sizeof(err));
            [self finishStartForGeneration:generation error:[NSString stringWithUTF8String:err] ?: @"Tailscale 配置失败"];
            tailscale_close(sd);
            return;
        }
        if (proxyURL.length) {
            int prc = tailscale_set_proxy(sd, proxyURL.UTF8String);
            if (prc != 0) {
                char err[1024] = {0};
                tailscale_errmsg(sd, err, sizeof(err));
                [self finishStartForGeneration:generation error:[NSString stringWithUTF8String:err] ?: @"Tailscale 上游代理配置失败"];
                tailscale_close(sd);
                return;
            }
        }
        [self.lock lock];
        BOOL generationOK2 = (self.generation == generation);
        [self.lock unlock];
        if (!generationOK2) {
            tailscale_close(sd);
            return;
        }
        // Start without blocking: this lets us expose the interactive login
        // URL when no auth key is configured. We then poll until Running.
        if (tailscale_start(sd) != 0) {
            char err[1024] = {0};
            tailscale_errmsg(sd, err, sizeof(err));
            [self finishStartForGeneration:generation error:[NSString stringWithUTF8String:err] ?: @"tailscale_start failed"];
            tailscale_close(sd);
            return;
        }

        // Poll BackendState/AuthURL until the node is Running or stopped.
        NSString *lastState = @"";
        for (int i = 0; i < 300; i++) {
            [self.lock lock];
            BOOL genOK = (self.generation == generation);
            [self.lock unlock];
            if (!genOK) {
                tailscale_close(sd);
                return;
            }

            NSDictionary *st = [self statusForSD:sd];
            NSString *state = [st[@"BackendState"] isKindOfClass:[NSString class]] ? st[@"BackendState"] : @"";
            lastState = state;
            NSString *auth = [st[@"AuthURL"] isKindOfClass:[NSString class]] ? st[@"AuthURL"] : @"";
            [self.lock lock];
            if (self.generation == generation) {
                self.backendState = state;
                self.authURL = auth;
            }
            [self.lock unlock];

            if ([state isEqualToString:@"Running"]) {
                break;
            }
            [NSThread sleepForTimeInterval:1.0];
        }

        if (![lastState isEqualToString:@"Running"]) {
            [self finishStartForGeneration:generation error:@"等待 Tailscale 登录超时，请检查 AuthURL 并重新登录"];
            tailscale_close(sd);
            return;
        }

        [self.lock lock];
        BOOL genOK2 = (self.generation == generation);
        [self.lock unlock];
        if (!genOK2) {
            tailscale_close(sd);
            return;
        }

        char addr[128] = {0};
        char pcred[33] = {0};
        char lcred[33] = {0};
        int rc = tailscale_loopback(sd, addr, sizeof(addr), pcred, lcred);
        if (rc != 0) {
            char err[1024] = {0};
            tailscale_errmsg(sd, err, sizeof(err));
            [self finishStartForGeneration:generation error:[NSString stringWithUTF8String:err] ?: @"Tailscale loopback 启动失败"];
            tailscale_close(sd);
            return;
        }
        NSString *addrStr = [NSString stringWithUTF8String:addr];
        NSString *cred = [NSString stringWithUTF8String:pcred];
        int port = 0;
        NSArray *parts = [addrStr componentsSeparatedByString:@":"];
        if (parts.count >= 2) port = [parts.lastObject intValue];
        if (port <= 0 || port > 65535 || !cred.length) {
            [self finishStartForGeneration:generation error:@"Tailscale loopback 返回了无效的 SOCKS5 地址或凭证"];
            tailscale_close(sd);
            return;
        }

        [self.lock lock];
        BOOL finalGenerationOK = self.generation == generation;
        if (finalGenerationOK) {
            self.sd = sd;
            self.running = YES;
            self.starting = NO;
            self.proxyPort = port;
            self.proxyPassword = cred;
            self.lastError = nil;
        }
        [self.lock unlock];
        if (!finalGenerationOK) {
            tailscale_close(sd);
            return;
        }
        NSLog(@"[LCTailscale] started hostname=%@ loopback=%@", hostname, addrStr);
        [self refreshStatus];

        // Now that the SOCKS5 port is known, regenerate the proxychains
        // configuration and runtime override for Tailscale mode.
        [[LCProxyConfig shared] applyToRuntime];

        // Apply persisted exit-node selection after the node is up.
        NSString *exitID = [settings[@"tailscaleExitNodeID"] isKindOfClass:[NSString class]] ? settings[@"tailscaleExitNodeID"] : @"";
        BOOL exitEnabled = [settings[@"tailscaleExitNodeEnabled"] boolValue];
        if (exitID.length || !exitEnabled) {
            [self setExitNode:exitID enabled:exitEnabled];
        }
    });
}

- (void)finishStartForGeneration:(int)generation error:(NSString *)error {
    [self.lock lock];
    if (self.generation == generation) {
        self.running = NO;
        self.starting = NO;
        self.lastError = error;
    }
    [self.lock unlock];
    if (error) NSLog(@"[LCTailscale] start failed: %@", error);
}

- (void)stop {
    [self.lock lock];
    int sd = self.sd;
    self.sd = -1;
    self.running = NO;
    self.starting = NO;
    self.proxyPort = 0;
    self.proxyPassword = nil;
    self.lastStatus = nil;
    self.lastExitNodes = nil;
    self.authURL = nil;
    self.backendState = nil;
    self.lastStatusRefresh = nil;
    self.generation++;
    [self.lock unlock];
    if (sd >= 0) {
        tailscale_close(sd);
    }
}

- (int)localProxyPort {
    [self.lock lock];
    int p = self.proxyPort;
    [self.lock unlock];
    return p;
}

- (NSString *)proxyUser { return @"tsnet"; }
- (NSString *)proxyPassword {
    [self.lock lock];
    NSString *v = _proxyPassword;
    [self.lock unlock];
    return v;
}

- (BOOL)isRunning {
    [self.lock lock];
    BOOL v = self.running;
    [self.lock unlock];
    return v;
}

- (NSString *)lastError {
    [self.lock lock];
    NSString *v = _lastError;
    [self.lock unlock];
    return v;
}

- (BOOL)isStarting {
    [self.lock lock];
    BOOL v = self.starting;
    [self.lock unlock];
    return v;
}

- (NSDictionary *)status {
    [self refreshStatus];
    [self.lock lock];
    NSDictionary *v = self.lastStatus;
    [self.lock unlock];
    return v;
}

- (NSDictionary *)statusForSD:(int)sd {
    NSData *data = [self jsonDataForSD:sd fetch:tailscale_get_status_json];
    if (!data) return nil;
    NSDictionary *status = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [status isKindOfClass:[NSDictionary class]] ? status : nil;
}

- (NSData *)jsonDataForSD:(int)sd fetch:(int (*)(tailscale, char *, size_t))fetch {
    if (sd < 0 || !fetch) return nil;
    for (size_t capacity = LCTailscaleJSONInitialCapacity; capacity <= LCTailscaleJSONMaximumCapacity; capacity *= 2) {
        NSMutableData *buffer = [NSMutableData dataWithLength:capacity];
        int rc = fetch(sd, buffer.mutableBytes, capacity);
        if (rc == ERANGE) continue;
        if (rc != 0) return nil;
        const void *nul = memchr(buffer.bytes, '\0', capacity);
        if (!nul) return nil;
        return [buffer subdataWithRange:NSMakeRange(0, (NSUInteger)((const char *)nul - (const char *)buffer.bytes))];
    }
    return nil;
}

- (NSString *)authURL {
    [self.lock lock];
    NSString *v = _authURL ?: @"";
    [self.lock unlock];
    return v;
}

- (NSString *)backendState {
    [self.lock lock];
    NSString *v = _backendState ?: @"";
    [self.lock unlock];
    return v;
}

- (void)refreshStatus {
    [self.lock lock];
    int sd = self.sd;
    BOOL running = self.running;
    if (!running || sd < 0 || (self.lastStatusRefresh && -[self.lastStatusRefresh timeIntervalSinceNow] < LCTailscaleStatusCacheInterval)) {
        [self.lock unlock];
        return;
    }
    // Keep the handle alive through both LocalAPI reads; stop waits on this lock before close.
    NSData *data = [self jsonDataForSD:sd fetch:tailscale_get_full_status_json];
    if (!data) {
        [self.lock unlock];
        return;
    }
    NSDictionary *status = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![status isKindOfClass:[NSDictionary class]]) {
        [self.lock unlock];
        return;
    }

    NSMutableArray *exitNodes = [NSMutableArray array];
    NSArray *peers = [status[@"Peer"] isKindOfClass:[NSArray class]] ? status[@"Peer"] : nil;
    for (NSDictionary *peer in peers) {
        if (![peer isKindOfClass:[NSDictionary class]]) continue;
        if ([peer[@"ExitNodeOption"] boolValue]) {
            [exitNodes addObject:peer];
        }
    }

    NSString *selectedID = @"";
    BOOL enabled = NO;
    NSData *prefsData = [self jsonDataForSD:sd fetch:tailscale_get_prefs_json];
    if (prefsData) {
        NSDictionary *prefs = [NSJSONSerialization JSONObjectWithData:prefsData options:0 error:nil];
        if ([prefs isKindOfClass:[NSDictionary class]]) {
            id exitID = prefs[@"ExitNodeID"];
            if ([exitID isKindOfClass:[NSString class]] && [exitID length]) {
                selectedID = exitID;
                enabled = YES;
            }
        }
    }

    self.lastStatus = status;
    self.lastExitNodes = exitNodes;
    self.lastSelectedExitNodeID = selectedID;
    self.lastExitNodeEnabled = enabled;
    self.lastStatusRefresh = [NSDate date];
    [self.lock unlock];
}

- (NSArray<NSDictionary *> *)exitNodes {
    [self refreshStatus];
    [self.lock lock];
    NSArray *v = self.lastExitNodes ?: @[];
    [self.lock unlock];
    return v;
}

- (NSString *)selectedExitNodeID {
    [self refreshStatus];
    [self.lock lock];
    NSString *v = self.lastSelectedExitNodeID ?: @"";
    [self.lock unlock];
    return v;
}

- (BOOL)exitNodeEnabled {
    [self refreshStatus];
    [self.lock lock];
    BOOL v = self.lastExitNodeEnabled;
    [self.lock unlock];
    return v;
}

- (BOOL)setExitNode:(NSString *)stableID enabled:(BOOL)enabled {
    [self.lock lock];
    int sd = self.sd;
    BOOL running = self.running;
    if (!running || sd < 0) {
        [self.lock unlock];
        return NO;
    }
    int rc = tailscale_set_exit_node(sd, stableID.UTF8String, enabled ? 1 : 0);
    [self.lock unlock];
    if (rc == 0) {
        [self refreshStatus];
        return YES;
    }
    return NO;
}

@end
