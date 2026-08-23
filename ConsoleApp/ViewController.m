//
//  ViewController.m
//  LCProxyConsole
//
//  全屏 WKWebView → http://127.0.0.1:19092。
//  首次打开自动下载 LCTailscaleControl dylib 到 LiveContainer 的 Tweaks 目录；
//  下载完成后提示重启，已安装则直接进入控制台。
//

#import "ViewController.h"
#import "AutoUpdater.h"
#import <WebKit/WebKit.h>

static NSString *const KPCConsoleURL = @"http://127.0.0.1:19092/";

@interface ViewController () <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) UIView *errorView;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, assign) BOOL loadedOnce;
@property (nonatomic, copy) NSString *lastFullLog;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:config];
    self.webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.webView.navigationDelegate = self;
    self.webView.scrollView.bounces = NO;
    [self.view addSubview:self.webView];

    [self setupErrorView];
    [self startAutoUpdate];
}

- (void)setupErrorView {
    self.errorView = [[UIView alloc] initWithFrame:self.view.bounds];
    self.errorView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.errorView.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1];
    self.errorView.hidden = YES;

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    self.spinner.color = [UIColor whiteColor];
    self.spinner.center = CGPointMake(CGRectGetMidX(self.view.bounds), CGRectGetMidY(self.view.bounds) - 80);
    [self.errorView addSubview:self.spinner];
    [self.spinner startAnimating];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(20, 80, CGRectGetWidth(self.view.bounds) - 40,
                                                              CGRectGetHeight(self.view.bounds) - 160)];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logView.backgroundColor = [UIColor clearColor];
    self.logView.textColor = [UIColor colorWithWhite:0.85 alpha:1];
    self.logView.font = [UIFont systemFontOfSize:14];
    self.logView.editable = NO;
    self.logView.selectable = YES;
    [self.errorView addSubview:self.logView];

    [self.view addSubview:self.errorView];
}

- (void)showLog:(NSString *)line {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.lastFullLog = line;
        self.logView.text = line;
        [self.logView scrollRangeToVisible:NSMakeRange(self.logView.text.length, 0)];
    });
}

- (void)startAutoUpdate {
    self.errorView.hidden = NO;
    [self showLog:@"正在初始化（检查/下载 LCTailscaleControl dylib）…\n请保持 LiveContainer 在前台"];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *result = [AutoUpdater runAutoUpdateWithProgress:^(NSString *stage, double fraction) {
            [self showLog:stage];
        }];
        BOOL downloaded = [AutoUpdater downloadedAnything];
        BOOL failed = result.length > 0 && [result containsString:@"失败"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.spinner.hidden = YES;
            if (failed || downloaded) {
                NSString *msg = result ?: @"（无输出）";
                if (!failed) {
                    msg = [msg stringByAppendingString:@"\n\n请退出 App 重新打开（或重启 LiveContainer），dylib 签名生效后自动进入控制台。"];
                }
                [self showLog:msg];
            } else {
                [self showLog:@"正在连接控制台 127.0.0.1:19092 …"];
                [self loadConsole];
            }
        });
    });
}

- (void)loadConsole {
    if (self.loadedOnce) return;
    NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:KPCConsoleURL]
                                         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                     timeoutInterval:5];
    [self.webView loadRequest:req];
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    if (self.loadedOnce) return;
    self.errorView.hidden = NO;
    [self showLog:[NSString stringWithFormat:@"无法连接 127.0.0.1:19092\n%@\n2 秒后自动重试…", error.localizedDescription]];
    [self performSelector:@selector(loadConsole) withObject:nil afterDelay:2.0];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.loadedOnce = YES;
    self.errorView.hidden = YES;
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {
}

@end
