#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LCTailscaleManager : NSObject

+ (instancetype)shared;

/// Apply settings; starts/stops/restarts the embedded Tailscale node.
/// Call after LCProxyKing has been configured so Tailscale can use the
/// KingCard local forwarder as its outbound HTTP proxy.
- (void)applyConfig:(NSDictionary *)settings;

/// Current process-local SOCKS5 proxy port, or 0 if not ready.
- (int)localProxyPort;

/// SOCKS5 username/password for the tsnet loopback proxy.
- (NSString *)proxyUser;
- (NSString *)proxyPassword;

- (BOOL)isRunning;
- (BOOL)isStarting;
- (NSString *)lastError;
- (NSString *)authURL;
- (NSString *)backendState;

/// Full status JSON parsed into a dictionary, or nil.
- (NSDictionary *)status;

/// Exit nodes available from the tailnet (peers with ExitNodeOption).
- (NSArray<NSDictionary *> *)exitNodes;

/// Currently selected exit node StableID (empty if none).
- (NSString *)selectedExitNodeID;
- (BOOL)exitNodeEnabled;

- (BOOL)setExitNode:(NSString *)stableID enabled:(BOOL)enabled;

@end

NS_ASSUME_NONNULL_END
