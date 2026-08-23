#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "LCProxyConfig.h"
#import "LCProxyStats.h"
#import "LCProxyServer.h"
#import "LCProxyPaths.h"
#import "lcproxy_bridge.h"

static void LCProxyShowBanner(NSDictionary *settings) {
    if (![settings[@"showProxyBanner"] boolValue]) return;
    BOOL enabled = [settings[@"proxyEnabled"] boolValue];
    NSString *effectiveMode = [[LCProxyConfig shared] effectiveProxyModeForSettings:settings];
    NSString *text = nil;
    if (!enabled) {
        text = @"LiveProxy 已加载 · 代理未启用";
    } else if ([effectiveMode isEqualToString:@"kingcard"]) {
        text = @"LiveProxy 已加载 · 王卡代理";
    } else if ([effectiveMode isEqualToString:@"custom"]) {
        text = @"LiveProxy 已加载 · 自定义代理";
    } else if ([effectiveMode isEqualToString:@"tailscale"]) {
        text = @"LiveProxy 已加载 · Tailscale";
    } else {
        text = @"LiveProxy 已加载 · 直连";
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *hud = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        hud.windowLevel = UIWindowLevelStatusBar + 1;
        hud.userInteractionEnabled = NO;
        hud.backgroundColor = [UIColor clearColor];
        UILabel *label = [[UILabel alloc] init];
        label.text = text;
        label.font = [UIFont boldSystemFontOfSize:13];
        label.textColor = [UIColor whiteColor];
        label.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.78];
        label.textAlignment = NSTextAlignmentCenter;
        label.numberOfLines = 0;
        CGFloat width = MIN(hud.bounds.size.width - 32, 320);
        CGFloat height = 32;
        label.frame = CGRectMake((hud.bounds.size.width - width) / 2.0,
                                 hud.bounds.size.height > 0 ? hud.bounds.size.height * 0.18 : 80,
                                 width, height);
        label.layer.cornerRadius = 8;
        label.layer.masksToBounds = YES;
        [hud addSubview:label];
        hud.hidden = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            hud.hidden = YES;
        });
    });
}

__attribute__((constructor))
static void LCTailscaleControlConstructor(void) {
    @autoreleasepool {
        // Apply persisted settings immediately. The proxychains C core is already
        // initialized by its own constructor; these calls update runtime flags.
        NSDictionary *initialSettings = [[LCProxyConfig shared] load];
        [[LCProxyConfig shared] applyToRuntime];
        LCProxyShowBanner(initialSettings);
        [[LCProxyConfig shared] startNetworkMonitor];

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification * _Nonnull note) {
            [[LCProxyConfig shared] applyToRuntime];
            // applyToRuntime already schedules a Wangka refresh when the cached
            // credentials/proxies are missing or stale. Do not force a network
            // refresh here: at launch we want to use the cache immediately and
            // avoid blocking the main thread.
        }];

        // Persist this process's cellular traffic in 10-minute buckets.
        [[LCProxyStats shared] start];
        [[LCProxyStats shared] flushNow];

        // Start the loopback web console. If another guest app already owns the
        // port, this instance stays headless but still records stats.
        BOOL web = [[LCProxyServer shared] start];
        NSLog(@"[LCProxy] control loaded, data=%@ web=%d", LCProxyDataDirectory(), web);
    }
}
