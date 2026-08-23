#import "AutoUpdater.h"
#import <stdlib.h>
#import <stdarg.h>
#import <objc/message.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <mach-o/loader.h>

static BOOL gDownloadedNew = NO;
static NSMutableString *gDiag = nil;

@implementation AutoUpdater

+ (NSString *)repo {
    NSString *repo = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"LCProxyUpdateRepo"];
    return repo.length ? repo : @"koast18/livecontainer-kingcard-proxy";
}

+ (void)diag:(NSString *)fmt, ... {
    if (!gDiag) gDiag = [NSMutableString string];
    va_list args;
    va_start(args, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    [gDiag appendFormat:@"%@\n", s];
}

+ (NSString *)diagnostics {
    return gDiag ?: @"";
}

+ (void)reset {
    gDiag = nil;
    gDownloadedNew = NO;
}

+ (BOOL)downloadedAnything {
    return gDownloadedNew;
}

+ (NSString *)lcRootDirectory {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *candidates = [NSMutableArray array];
    const char *home = getenv("LC_HOME_PATH");
    if (home && home[0]) {
        NSString *h = [NSString stringWithUTF8String:home];
        [candidates addObject:h];
        [candidates addObject:[h stringByAppendingPathComponent:@"Documents"]];
    }
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count) [candidates addObject:paths[0]];
    for (NSString *c in candidates) {
        if (!c.length) continue;
        NSString *probe = [c stringByAppendingPathComponent:@"Tweaks"];
        NSError *err = nil;
        if ([fm createDirectoryAtPath:probe withIntermediateDirectories:YES attributes:nil error:&err]) {
            [self diag:@"[路径] 可写共享根: %@", c];
            return c;
        }
        [self diag:@"[路径] 候选不可写 %@: %@", c, err.localizedDescription ?: @"?"];
    }
    return nil;
}

+ (NSData *)fetchURL:(NSString *)urlString {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return nil;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 60;
    [req setValue:@"LiveProxyTailscaleConsole/1.0" forHTTPHeaderField:@"User-Agent"];
    NSHTTPURLResponse *resp = nil;
    NSError *err = nil;
    NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&resp error:&err];
    if (err) {
        [self diag:@"[请求] %@ 错误: %@ (%ld)", urlString, err.localizedDescription ?: @"?", (long)err.code];
        return nil;
    }
    if (resp.statusCode == 200 && data) {
        [self diag:@"[请求] %@ HTTP 200 %ld bytes", urlString, (long)data.length];
        return data;
    }
    [self diag:@"[请求] %@ HTTP %ld", urlString, (long)resp.statusCode];
    return nil;
}

+ (NSString *)updateTag {
    NSString *tag = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"LCProxyUpdateTag"];
    return tag.length ? tag : nil;
}

+ (NSData *)apiRelease {
    NSString *tag = [self updateTag];
    NSString *path = tag ? [NSString stringWithFormat:@"releases/tags/%@", tag] : @"releases/latest";
    NSArray *urls = @[
        [NSString stringWithFormat:@"https://gh-proxy.com/https://api.github.com/repos/%@/%@", self.repo, path],
        [NSString stringWithFormat:@"https://api.github.com/repos/%@/%@", self.repo, path],
    ];
    for (NSString *u in urls) {
        NSData *d = [self fetchURL:u];
        if (d) return d;
    }
    return nil;
}

+ (NSString *)latestDylibAssetName {
    NSData *data = [self apiRelease];
    if (!data) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![obj isKindOfClass:[NSDictionary class]]) return nil;
    NSArray *assets = obj[@"assets"];
    NSString *best = nil;
    NSArray *bestVer = nil;
    for (NSDictionary *a in assets) {
        NSString *name = a[@"name"];
        if (![name hasPrefix:@"LCTailscaleControl-"] || ![name hasSuffix:@".dylib"]) continue;
        NSString *ver = [name substringFromIndex:@"LCTailscaleControl-".length];
        ver = [ver substringToIndex:ver.length - 6];
        NSArray *parts = [ver componentsSeparatedByString:@"."];
        BOOL numeric = YES;
        for (NSString *p in parts) {
            if (p.intValue == 0 && ![p isEqualToString:@"0"]) numeric = NO;
        }
        if (!numeric) continue;
        if (!bestVer || [self versionArray:parts isNewerThan:bestVer]) {
            best = name;
            bestVer = parts;
        }
    }
    if (best) [self diag:@"[资产] 最新 dylib: %@", best];
    else [self diag:@"[资产] 未找到 LCTailscaleControl-*.dylib 资产"];
    return best;
}

+ (BOOL)versionArray:(NSArray *)a isNewerThan:(NSArray *)b {
    NSUInteger n = MAX(a.count, b.count);
    for (NSUInteger i = 0; i < n; i++) {
        int x = i < a.count ? [a[i] intValue] : 0;
        int y = i < b.count ? [b[i] intValue] : 0;
        if (x != y) return x > y;
    }
    return NO;
}

+ (NSString *)downloadURLForAsset:(NSString *)name {
    NSData *data = [self apiRelease];
    if (!data) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![obj isKindOfClass:[NSDictionary class]]) return nil;
    for (NSDictionary *a in obj[@"assets"]) {
        if ([a[@"name"] isEqualToString:name]) {
            return a[@"browser_download_url"];
        }
    }
    return nil;
}

+ (BOOL)downloadAsset:(NSString *)name toDirectory:(NSString *)dir {
    NSString *browser = [self downloadURLForAsset:name];
    if (!browser) return NO;
    NSArray *urls = @[
        [NSString stringWithFormat:@"https://gh-proxy.com/%@", browser],
        browser,
    ];
    for (NSString *u in urls) {
        NSData *data = [self fetchURL:u];
        if (!data) continue;
        NSString *dst = [dir stringByAppendingPathComponent:name];
        NSError *err = nil;
        if ([data writeToFile:dst options:NSDataWritingAtomic error:&err]) {
            [self diag:@"[写入] %@", dst];
            return YES;
        }
        [self diag:@"[写入] 失败: %@", err.localizedDescription ?: @"?"];
    }
    return NO;
}

+ (void)cleanOldDylibsIn:(NSString *)dir keep:(NSString *)keep {
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    for (NSString *f in files) {
        if ([f hasPrefix:@"LCTailscaleControl-"] && [f hasSuffix:@".dylib"] && ![f isEqualToString:keep]) {
            [[NSFileManager defaultManager] removeItemAtPath:[dir stringByAppendingPathComponent:f] error:nil];
            [self diag:@"[清理] %@", f];
        }
    }
}

struct lc_code_signature_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

static BOOL LCProxyCodeSignatureValid(NSString *path) {
    if (!path.length) return NO;
    int fd = open(path.UTF8String, O_RDONLY);
    if (fd < 0) return NO;

    struct mach_header_64 header;
    if (read(fd, &header, sizeof(header)) != (ssize_t)sizeof(header) || header.magic != MH_MAGIC_64) {
        close(fd);
        return NO;
    }

    struct lc_code_signature_command cs = {0};
    BOOL found = NO;
    off_t off = (off_t)sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header.ncmds && i < 64; i++) {
        struct load_command lc = {0};
        if (lseek(fd, off, SEEK_SET) == -1) break;
        if (read(fd, &lc, sizeof(lc)) != (ssize_t)sizeof(lc)) break;
        if (lc.cmd == LC_CODE_SIGNATURE && lc.cmdsize >= sizeof(cs)) {
            if (lseek(fd, off, SEEK_SET) != -1 && read(fd, &cs, sizeof(cs)) == (ssize_t)sizeof(cs)) {
                found = YES;
            }
            break;
        }
        off += lc.cmdsize;
    }

    if (!found || cs.dataoff == 0 || cs.datasize == 0) {
        close(fd);
        return NO;
    }

    fsignatures_t siginfo;
    memset(&siginfo, 0, sizeof(siginfo));
    siginfo.fs_file_start = 0;
    siginfo.fs_blob_start = (void *)(long)cs.dataoff;
    siginfo.fs_blob_size = cs.datasize;
    if (fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo) == -1) {
        close(fd);
        return NO;
    }

    char messageBuffer[512];
    messageBuffer[0] = '\0';
    fchecklv_t checkInfo;
    memset(&checkInfo, 0, sizeof(checkInfo));
    checkInfo.lv_error_message_size = sizeof(messageBuffer);
    checkInfo.lv_error_message = messageBuffer;
    checkInfo.lv_file_start = 0;
    int checkResult = fcntl(fd, F_CHECK_LV, &checkInfo);
    close(fd);
    return checkResult == 0;
}

+ (NSString *)normalTweaksDirectory {
    NSString *root = [self lcRootDirectory];
    return root ? [root stringByAppendingPathComponent:@"Tweaks"] : nil;
}

+ (NSString *)sharedTweaksDirectory {
    Class lcSharedUtils = NSClassFromString(@"LCSharedUtils");
    if (!lcSharedUtils) return nil;
    SEL sel = NSSelectorFromString(@"appGroupID");
    NSString *groupID = ((NSString *(*)(id, SEL))objc_msgSend)(lcSharedUtils, sel);
    if (![groupID isKindOfClass:[NSString class]] || groupID.length == 0) return nil;
    NSURL *groupURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:groupID];
    if (!groupURL) return nil;
    return [[groupURL URLByAppendingPathComponent:@"LiveContainer/Tweaks"] path];
}

+ (NSString *)runAutoUpdateWithProgress:(KPAutoUpdateProgress)progress {
    [self reset];
    void (^stage)(NSString *, double) = ^(NSString *s, double f) {
        if (progress) progress(s, f);
    };
    stage(@"定位 LiveContainer Tweaks 目录…", -1);
    NSString *normalTweaks = [self normalTweaksDirectory];
    NSString *sharedTweaks = [self sharedTweaksDirectory];
    if (!normalTweaks) {
        NSString *msg = @"无法定位 LiveContainer Tweaks 目录（LC_HOME_PATH 不可写）。";
        [self diag:msg];
        return [self diagnostics];
    }
    [[NSFileManager defaultManager] createDirectoryAtPath:normalTweaks withIntermediateDirectories:YES attributes:nil error:nil];
    [self diag:@"[目录] 普通 Tweaks: %@", normalTweaks];
    if (sharedTweaks) {
        [[NSFileManager defaultManager] createDirectoryAtPath:sharedTweaks withIntermediateDirectories:YES attributes:nil error:nil];
        [self diag:@"[目录] 共享 App Tweaks: %@", sharedTweaks];
    }

    stage(@"检查最新版本…", -1);
    NSString *asset = [self latestDylibAssetName];
    if (!asset) {
        [self diag:@"未找到可下载的 dylib 资产（请检查 Release 是否已构建）。"];
        return [self diagnostics];
    }

    NSString *normalDst = [normalTweaks stringByAppendingPathComponent:asset];
    if (![[NSFileManager defaultManager] fileExistsAtPath:normalDst]) {
        stage([NSString stringWithFormat:@"下载 %@…", asset], -1);
        if (![self downloadAsset:asset toDirectory:normalTweaks]) {
            [self diag:@"下载失败。"];
            return [self diagnostics];
        }
        gDownloadedNew = YES;
    } else {
        [self diag:@"普通 Tweaks 已存在：%@", asset];
    }

    // 只复制用户已签名的 dylib 到共享 App 目录。
    BOOL normalSigned = LCProxyCodeSignatureValid(normalDst);
    if (normalSigned) {
        [self diag:@"[签名] %@ 已签名", asset];
        if (sharedTweaks) {
            NSString *sharedDst = [sharedTweaks stringByAppendingPathComponent:asset];
            BOOL sharedExists = [[NSFileManager defaultManager] fileExistsAtPath:sharedDst];
            BOOL sharedSigned = sharedExists && LCProxyCodeSignatureValid(sharedDst);
            if (!sharedSigned) {
                NSError *err = nil;
                if (sharedExists) [[NSFileManager defaultManager] removeItemAtPath:sharedDst error:&err];
                if ([[NSFileManager defaultManager] copyItemAtPath:normalDst toPath:sharedDst error:&err]) {
                    [self diag:@"[复制] 已签名 dylib -> 共享 App: %@", sharedDst];
                    // 复制到共享目录是给其它 guest App 用的，不影响控制台进程自身
                    // 的 dylib 注入；不要置 gDownloadedNew，否则用户签名后还要
                    // 重复打开两次才能进入控制台。
                } else {
                    [self diag:@"[复制] 到共享 App 失败: %@", err.localizedDescription ?: @"?"];
                }
            } else {
                [self diag:@"共享 App 已有已签名 dylib：%@", asset];
            }
        }
    } else {
        [self diag:@"[签名] %@ 尚未签名。请在 LiveContainer 的 Tweaks 页签名后重新打开本控制台。", asset];
    }

    // 清理旧版本和未签名副本。
    [self cleanOldDylibsIn:normalTweaks keep:asset];
    if (sharedTweaks) {
        // 共享目录只保留已签名的当前版本。
        NSString *sharedDst = [sharedTweaks stringByAppendingPathComponent:asset];
        BOOL sharedSigned = [[NSFileManager defaultManager] fileExistsAtPath:sharedDst] && LCProxyCodeSignatureValid(sharedDst);
        [self cleanOldDylibsIn:sharedTweaks keep:sharedSigned ? asset : nil];
    }

    if (!normalSigned) {
        [self diag:@"请完成 dylib 签名后重新打开本控制台。"];
    }
    return [self diagnostics];
}

@end
