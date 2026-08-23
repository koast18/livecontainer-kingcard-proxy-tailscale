#import "LCTailscaleManager.h"
#import "LCProxyPaths.h"
#import "LCProxyKing.h"
#import "LCProxyConfig.h"
#import "tailscale.h"
#import <netinet/in.h>
#import <arpa/inet.h>
#import <string.h>

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
- (void)startWithSettings:(NSDictionary *)settings;
- (NSDictionary *)statusForSD:(int)sd;
- (void)stop;
- (NSString *)settingsSignature:(NSDictionary *)settings;
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

- (void)applyConfig:(NSDictionary *)settings {
    NSString *mode = [settings[@"proxyMode"] isKindOfClass:[NSString class]] ? settings[@"proxyMode"] : @"custom";
    BOOL enabled = [settings[@"proxyEnabled"] boolValue];
    BOOL shouldRun = enabled && [mode isEqualToString:@"tailscale"];
    NSString *signature = [self settingsSignature:settings];

    [self.lock lock];
    BOOL alreadyRunning = self.running && self.sd >= 0;
    BOOL configChanged = !self.lastSettingsSignature || ![signature isEqualToString:self.lastSettingsSignature];
    [self.lock unlock];

    if (!shouldRun) {
        if (alreadyRunning || self.starting) {
            [self stop];
        }
        self.lastSettingsSignature = signature;
        return;
    }

    if (alreadyRunning && !configChanged) {
        self.lastSettingsSignature = signature;
        [self refreshStatus];
        return;
    }

    if (alreadyRunning || self.starting) {
        [self stop];
    }

    self.lastSettingsSignature = signature;
    [self startWithSettings:settings];
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

    NSString *dataDir = LCProxyDataDirectory();
    NSString *stateDir = [dataDir stringByAppendingPathComponent:@"tailscale"];
    if ([settings[@"tailscaleStateDir"] isKindOfClass:[NSString class]] && [settings[@"tailscaleStateDir"] length]) {
        stateDir = settings[@"tailscaleStateDir"];
    }
    NSString *hostname = [settings[@"tailscaleHostname"] isKindOfClass:[NSString class]] && [settings[@"tailscaleHostname"] length] ? settings[@"tailscaleHostname"] : @"lc-tailscale";
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
            [self finishStart:sd error:@"tailscale_new failed"];
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
        tailscale_set_dir(sd, stateDir.UTF8String);
        tailscale_set_hostname(sd, hostname.UTF8String);
        tailscale_set_authkey(sd, authKey.UTF8String);
        if (controlURL.length) tailscale_set_control_url(sd, controlURL.UTF8String);
        tailscale_set_ephemeral(sd, ephemeral ? 1 : 0);
        tailscale_set_disable_p2p(sd, 1);
        if (proxyURL.length) {
            int prc = tailscale_set_proxy(sd, proxyURL.UTF8String);
            if (prc != 0) NSLog(@"[LCTailscale] set_proxy failed %d", prc);
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
            [self finishStart:-1 error:[NSString stringWithUTF8String:err]];
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
            self.backendState = state;
            self.authURL = auth;
            [self.lock unlock];

            if ([state isEqualToString:@"Running"]) {
                break;
            }
            [NSThread sleepForTimeInterval:1.0];
        }

        if (![lastState isEqualToString:@"Running"]) {
            [self finishStart:-1 error:@"等待 Tailscale 登录超时，请检查 AuthURL 并重新登录"];
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
            [self finishStart:-1 error:[NSString stringWithUTF8String:err]];
            tailscale_close(sd);
            return;
        }
        NSString *addrStr = [NSString stringWithUTF8String:addr];
        NSString *cred = [NSString stringWithUTF8String:pcred];
        int port = 0;
        NSArray *parts = [addrStr componentsSeparatedByString:@":"];
        if (parts.count >= 2) port = [parts.lastObject intValue];

        [self.lock lock];
        self.sd = sd;
        self.running = YES;
        self.starting = NO;
        self.proxyPort = port;
        self.proxyPassword = cred;
        self.lastError = nil;
        [self.lock unlock];
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

- (void)finishStart:(int)sd error:(NSString *)error {
    [self.lock lock];
    if (sd >= 0) self.sd = sd;
    self.running = (sd >= 0);
    self.starting = NO;
    self.lastError = error;
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
    NSString *v = self.proxyPassword;
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
    NSString *v = self.lastError;
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
    if (sd < 0) return nil;
    char buf[1024 * 1024];
    if (tailscale_get_status_json(sd, buf, sizeof(buf)) != 0) return nil;
    NSData *data = [NSData dataWithBytes:buf length:strlen(buf)];
    NSDictionary *status = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [status isKindOfClass:[NSDictionary class]] ? status : nil;
}

- (NSString *)authURL {
    [self.lock lock];
    NSString *v = self.authURL ?: @"";
    [self.lock unlock];
    return v;
}

- (NSString *)backendState {
    [self.lock lock];
    NSString *v = self.backendState ?: @"";
    [self.lock unlock];
    return v;
}

- (void)refreshStatus {
    [self.lock lock];
    int sd = self.sd;
    BOOL running = self.running;
    [self.lock unlock];
    if (!running || sd < 0) return;

    char buf[1024 * 1024];
    int rc = tailscale_get_full_status_json(sd, buf, sizeof(buf));
    if (rc != 0) return;
    NSData *data = [NSData dataWithBytes:buf length:strlen(buf)];
    NSDictionary *status = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![status isKindOfClass:[NSDictionary class]]) return;

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
    char pbuf[1024 * 1024];
    if (tailscale_get_prefs_json(sd, pbuf, sizeof(pbuf)) == 0) {
        NSDictionary *prefs = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:pbuf length:strlen(pbuf)] options:0 error:nil];
        if ([prefs isKindOfClass:[NSDictionary class]]) {
            id exitID = prefs[@"ExitNodeID"];
            if ([exitID isKindOfClass:[NSString class]] && [exitID length]) {
                selectedID = exitID;
                enabled = YES;
            }
        }
    }

    [self.lock lock];
    self.lastStatus = status;
    self.lastExitNodes = exitNodes;
    self.lastSelectedExitNodeID = selectedID;
    self.lastExitNodeEnabled = enabled;
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
    [self.lock unlock];
    if (!running || sd < 0) return NO;
    int rc = tailscale_set_exit_node(sd, stableID.UTF8String, enabled ? 1 : 0);
    if (rc == 0) {
        [self refreshStatus];
        return YES;
    }
    return NO;
}

@end
