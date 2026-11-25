// AX Pro Max 激活器（启动器）
//
// 职责：
//   1. 输入卡密，向授权服务器验证（设备绑定 + 有效期）
//   2. 验证通过后保存授权，并调起目标 App
//   3. 下次打开若授权仍有效，直接显示"启动"按钮
//
// 说明：本程序不修改目标 App，任何注入/反注入/签名问题都与它无关。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

// ====== 配置 ======
static NSString *const kServerBase   = @"https://192.168.1.112";
static NSString *const kVerifyPath   = @"/api/v1/launcher/verify";
static NSString *const kTargetBundle = @"com.axp.promax";
static NSString *const kTargetName   = @"AX Pro Max";
static NSString *const kLicenseKey   = @"AXP.Launcher.License.v1";
static NSString *const kCardKey      = @"AXP.Launcher.Card.v1";

// ====== 日志（Documents/launcher.log，可用「文件」App 取出）======
static void LOG(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap;
        va_start(ap, fmt);
        NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        NSLog(@"[AXP] %@", msg);
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (!dir) return;
        NSString *path = [dir stringByAppendingPathComponent:@"launcher.log"];
        NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                          [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                         dateStyle:NSDateFormatterNoStyle
                                                         timeStyle:NSDateFormatterMediumStyle], msg];
        FILE *fp = fopen(path.UTF8String, "a");
        if (fp) { fputs(line.UTF8String, fp); fclose(fp); }
    }
}

static NSString *DeviceID(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSData *d = [[NSString stringWithFormat:@"axplauncher|%@", idfv] dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes, (CC_LONG)d.length, digest);
    NSMutableString *out = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [out appendFormat:@"%02x", digest[i]];
    return out;
}

// ====== 授权缓存 ======
static NSDictionary *CachedLicense(void) {
    id obj = [[NSUserDefaults standardUserDefaults] objectForKey:kLicenseKey];
    if (![obj isKindOfClass:[NSDictionary class]]) return nil;
    NSNumber *exp = obj[@"expires_at"];
    if ([exp isKindOfClass:[NSNumber class]] && exp.doubleValue > 0 &&
        exp.doubleValue < [[NSDate date] timeIntervalSince1970]) {
        LOG(@"缓存授权已过期");
        return nil;
    }
    NSString *dev = obj[@"device_id"];
    if ([dev isKindOfClass:[NSString class]] && dev.length && ![dev isEqualToString:DeviceID()]) {
        LOG(@"缓存授权与本机不匹配");
        return nil;
    }
    return obj;
}

// ====== 调起目标 App（多种方式依次尝试）======
static BOOL OpenTargetApp(void) {
    // 1) LSApplicationWorkspace（私有 API，侧载环境常见做法）
    Class wsClass = NSClassFromString(@"LSApplicationWorkspace");
    if (wsClass) {
        id ws = ((id (*)(id, SEL))objc_msgSend)((id)wsClass, sel_registerName("defaultWorkspace"));
        if (ws) {
            SEL sel = sel_registerName("openApplicationWithBundleID:");
            if ([ws respondsToSelector:sel]) {
                BOOL ok = ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, sel, kTargetBundle);
                LOG(@"LSApplicationWorkspace openApplicationWithBundleID -> %@", ok ? @"成功" : @"失败");
                if (ok) return YES;
            }
        }
    }
    // 2) UIApplication 私有方法
    SEL s2 = sel_registerName("launchApplicationWithIdentifier:suspended:");
    if ([[UIApplication sharedApplication] respondsToSelector:s2]) {
        ((void (*)(id, SEL, id, BOOL))objc_msgSend)([UIApplication sharedApplication], s2, kTargetBundle, NO);
        LOG(@"launchApplicationWithIdentifier 已调用");
        return YES;
    }
    LOG(@"所有调起方式都不可用");
    return NO;
}

// ====== 界面 ======
@interface AXPLauncherVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIButton *actionBtn;
@property (nonatomic, strong) UIActivityIndicatorView *spin;
@property (nonatomic, assign) BOOL hasLicense;
@end

@implementation AXPLauncherVC

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *devId = DeviceID();\n    LOG(@"界面加载，deviceId=%@", [devId substringToIndex:MIN(12, devId.length)]);
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    CGFloat W = self.view.bounds.size.width;
    CGFloat x = 24, w = W - 48;

    UILabel *icon = [[UILabel alloc] initWithFrame:CGRectMake(x, 110, w, 44)];
    icon.text = @"AX Pro Max";
    icon.font = [UIFont boldSystemFontOfSize:32];
    icon.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:icon];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(x, 160, w, 24)];
    sub.text = @"激活器 · 请输入你的卡密";
    sub.font = [UIFont systemFontOfSize:15];
    sub.textColor = [UIColor secondaryLabelColor];
    sub.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:sub];

    self.field = [[UITextField alloc] initWithFrame:CGRectMake(x, 210, w, 50)];
    self.field.placeholder = @"AXPM-XXXX-XXXX-XXXX-XXXX";
    self.field.borderStyle = UITextBorderStyleRoundedRect;
    self.field.textAlignment = NSTextAlignmentCenter;
    self.field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    self.field.autocorrectionType = UITextAutocorrectionTypeNo;
    self.field.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.field.delegate = self;
    self.field.text = [[NSUserDefaults standardUserDefaults] stringForKey:kCardKey];
    [self.view addSubview:self.field];

    self.actionBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.actionBtn.frame = CGRectMake(x, 276, w, 50);
    self.actionBtn.backgroundColor = [UIColor systemBlueColor];
    [self.actionBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.actionBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    self.actionBtn.layer.cornerRadius = 12;
    [self.actionBtn addTarget:self action:@selector(onAction) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.actionBtn];

    self.spin = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spin.frame = CGRectMake(W / 2 - 20, 340, 40, 40);
    self.spin.hidesWhenStopped = YES;
    [self.view addSubview:self.spin];

    self.status = [[UILabel alloc] initWithFrame:CGRectMake(x, 390, w, 72)];
    self.status.font = [UIFont systemFontOfSize:13];
    self.status.textColor = [UIColor secondaryLabelColor];
    self.status.textAlignment = NSTextAlignmentCenter;
    self.status.numberOfLines = 0;
    [self.view addSubview:self.status];

    UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(x, self.view.bounds.size.height - 90, w, 60)];
    tip.font = [UIFont systemFontOfSize:11];
    tip.textColor = [UIColor tertiaryLabelColor];
    tip.textAlignment = NSTextAlignmentCenter;
    tip.numberOfLines = 0;
    tip.text = @"一台设备仅限激活一台卡密\n激活后请从本页面启动使用";
    [self.view addSubview:tip];

    [self refreshState];
}

- (void)refreshState {
    NSDictionary *lic = CachedLicense();
    self.hasLicense = (lic != nil);
    if (self.hasLicense) {
        self.field.text = lic[@"card_masked"] ?: @"";
        self.field.enabled = NO;
        NSNumber *exp = lic[@"expires_at"];
        NSString *expStr = @"未知";
        if ([exp isKindOfClass:[NSNumber class]] && exp.doubleValue > 0) {
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.dateFormat = @"yyyy-MM-dd";
            expStr = [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:exp.doubleValue]];
        }
        self.status.text = [NSString stringWithFormat:@"已激活，有效期至 %@", expStr];
        self.status.textColor = [UIColor systemGreenColor];
        [self.actionBtn setTitle:[NSString stringWithFormat:@"启动 %@", kTargetName] forState:UIControlStateNormal];
    } else {
        self.field.enabled = YES;
        self.status.text = @"";
        [self.actionBtn setTitle:@"立即激活" forState:UIControlStateNormal];
    }
}

- (void)onAction {
    if (self.hasLicense) { [self launch]; return; }
    NSString *card = [[self.field.text ?: @"" uppercaseString]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (card.length < 8) {
        self.status.textColor = [UIColor systemRedColor];
        self.status.text = @"卡密格式不正确";
        return;
    }
    [self verify:card];
}

- (void)verify:(NSString *)card {
    self.status.textColor = [UIColor secondaryLabelColor];
    self.status.text = @"正在验证…";
    self.actionBtn.enabled = NO;
    [self.spin startAnimating];
    LOG(@"开始验证卡密 len=%lu", (unsigned long)card.length);

    NSDictionary *body = @{
        @"card_code": card,
        @"device_id": DeviceID(),
        @"action": @"activate",
        @"app": @"axpromax",
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSURL *url = [NSURL URLWithString:[kServerBase stringByAppendingString:kVerifyPath]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 12;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = json;

    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) me = weakSelf;
            if (!me) return;
            [me.spin stopAnimating];
            me.actionBtn.enabled = YES;
            if (err || !data) {
                LOG(@"网络错误: %@", err.localizedDescription);
                me.status.textColor = [UIColor systemRedColor];
                me.status.text = [NSString stringWithFormat:@"连接服务器失败\n%@", err.localizedDescription ?: @""];
                return;
            }
            LOG(@"响应 %lu 字节", (unsigned long)data.length);
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (![obj isKindOfClass:[NSDictionary class]]) {
                me.status.textColor = [UIColor systemRedColor];
                me.status.text = @"服务器响应格式异常";
                return;
            }
            if (![obj[@"ok"] boolValue]) {
                NSString *reason = obj[@"reason"] ?: @"";
                LOG(@"验证未通过 reason=%@", reason);
                me.status.textColor = [UIColor systemRedColor];
                NSString *msg = @"卡密无效或已过期";
                if ([reason isEqualToString:@"device_limit"]) msg = @"该卡密已绑定其他设备";
                else if ([reason isEqualToString:@"expired"]) msg = @"卡密已过期";
                else if ([reason isEqualToString:@"revoked"]) msg = @"卡密已被作废";
                me.status.text = msg;
                return;
            }
            LOG(@"验证通过，保存授权");
            [[NSUserDefaults standardUserDefaults] setObject:obj forKey:kLicenseKey];
            [[NSUserDefaults standardUserDefaults] setObject:card forKey:kCardKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
            [me refreshState];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [me launch]; });
        });
    }];
    [t resume];
}

- (void)launch {
    LOG(@"尝试启动目标 App %@", kTargetBundle);
    BOOL ok = OpenTargetApp();
    if (!ok) {
        self.status.textColor = [UIColor systemRedColor];
        self.status.text = [NSString stringWithFormat:@"请先把 %@ 安装好\n然后回到这里点启动", kTargetName];
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        self.status.textColor = [UIColor secondaryLabelColor];
        self.status.text = @"已发送启动请求\n若没有自动跳转，请检查目标 App 是否已安装";
    });
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    [self onAction];
    return YES;
}

@end

@interface AXPAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AXPAppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    LOG(@"=== 启动器启动 ===");
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[AXPLauncherVC alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AXPAppDelegate class]));
    }
}
