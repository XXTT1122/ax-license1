// gate_v4.m —— 稳定版授权门
//
// 相比上一版的关键改动：
//   * 完全不用 Auto Layout，全部用 initWithFrame / setFrame（消除约束崩溃这类问题）
//   * 每个步骤都写日志到 <容器>/Documents/axp.log
//   * 全部逻辑包 @try/@catch，异常原因也写进日志
//   * 网络请求延后到用户点按钮才发，不在启动路径上
//   * 窗口创建有 UIWindowScene / initWithFrame 双分支兜底

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#if __has_include("axp_config.h")
#import "axp_config.h"
#endif
#ifndef AXP_SERVER_URL
#define AXP_SERVER_URL @"https://your.domain.com"
#endif
#ifndef AXP_PUBLIC_KEY_B64
#define AXP_PUBLIC_KEY_B64 @""
#endif
#ifndef AXP_APP_KEY
#define AXP_APP_KEY @"ax_pro_max"
#endif
#ifndef AXP_BUNDLE_IDS
#define AXP_BUNDLE_IDS @[ @"com.axp.promax", @"com.apple.music" ]
#endif

static NSString *const kServerURL = AXP_SERVER_URL;
static NSString *const kPubKeyB64 = AXP_PUBLIC_KEY_B64;
static NSString *const kAppKey = AXP_APP_KEY;
static NSArray<NSString *> *AXPAllowedIDs(void) { return AXP_BUNDLE_IDS; }
static NSString *const kLicenseKey = @"AXP.License.v6";

// ---------- 日志 ----------
static void P(const char *fmt, ...) {
    @try {
        const char *home = getenv("HOME");
        if (!home) return;
        char path[512];
        snprintf(path, sizeof(path), "%s/Documents/axp.log", home);
        FILE *fp = fopen(path, "a");
        if (!fp) return;
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
        fprintf(fp, "\n");
        fclose(fp);
    } @catch (id e) { }
}

// ---------- 工具 ----------
static NSString *Sha256Hex(NSString *s) {
    if (!s) return nil;
    const char *c = [s UTF8String];
    unsigned char d[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(c, (unsigned int)strlen(c), d);
    NSMutableString *out = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [out appendFormat:@"%02x", d[i]];
    return out;
}

static NSString *DeviceID(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    return Sha256Hex([NSString stringWithFormat:@"axp|%@", idfv]);
}

static NSData *SPKIFromPKCS1(NSData *pkcs1) {
    static const unsigned char algo[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    NSUInteger n = pkcs1.length + 1;
    NSMutableData *mid = [NSMutableData data];
    unsigned char t = 0x03;
    [mid appendBytes:&t length:1];
    if (n < 0x80) {
        unsigned char l = (unsigned char)n; [mid appendBytes:&l length:1];
    } else if (n < 0x100) {
        unsigned char l[2] = {0x81, (unsigned char)n}; [mid appendBytes:l length:2];
    } else {
        unsigned char l[3] = {0x82, (unsigned char)(n >> 8), (unsigned char)(n & 0xFF)};
        [mid appendBytes:l length:3];
    }
    unsigned char z = 0; [mid appendBytes:&z length:1];
    [mid appendData:pkcs1];

    NSUInteger bodyLen = sizeof(algo) + mid.length;
    NSMutableData *out = [NSMutableData data];
    unsigned char s0 = 0x30;
    [out appendBytes:&s0 length:1];
    if (bodyLen < 0x80) {
        unsigned char l = (unsigned char)bodyLen; [out appendBytes:&l length:1];
    } else if (bodyLen < 0x100) {
        unsigned char l[2] = {0x81, (unsigned char)bodyLen}; [out appendBytes:l length:2];
    } else {
        unsigned char l[3] = {0x82, (unsigned char)(bodyLen >> 8), (unsigned char)(bodyLen & 0xFF)};
        [out appendBytes:l length:3];
    }
    [out appendBytes:algo length:sizeof(algo)];
    [out appendData:mid];
    return out;
}

static SecKeyRef PublicKey(void) {
    static SecKeyRef key = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            if (!kPubKeyB64 || kPubKeyB64.length < 100) { P("[E1] 公钥未配置"); return; }
            NSData *pkcs1 = [[NSData alloc] initWithBase64EncodedString:kPubKeyB64 options:0];
            if (!pkcs1) { P("[E2] 公钥 base64 解析失败"); return; }
            NSData *spki = SPKIFromPKCS1(pkcs1);
            NSDictionary *attrs = @{
                (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                (__bridge id)kSecAttrKeySizeInBits: @2048,
            };
            key = SecKeyCreateWithData((__bridge CFDataRef)spki, (__bridge CFDictionaryRef)attrs, NULL);
            P("[E3] 公钥载入 %s", key ? "成功" : "失败");
        } @catch (NSException *e) { P("[E4] 公钥异常 %s", e.reason.UTF8String); }
    });
    return key;
}

static BOOL VerifyResponse(NSDictionary *resp) {
    @try {
        if (!resp) return NO;
        NSString *raw = resp[@"payload_raw"];
        NSString *sigB64 = resp[@"signature"];
        if (!raw || !sigB64) return NO;
        SecKeyRef pub = PublicKey();
        if (!pub) return NO;
        NSData *sig = [[NSData alloc] initWithBase64EncodedString:sigB64 options:0];
        NSData *msg = [raw dataUsingEncoding:NSUTF8StringEncoding];
        if (!sig || !msg) return NO;
        BOOL ok = SecKeyVerifySignature(pub, kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
                                        (__bridge CFDataRef)msg, (__bridge CFDataRef)sig, NULL);
        return ok;
    } @catch (NSException *e) { P("[E5] 验签异常 %s", e.reason.UTF8String); return NO; }
}

static NSDictionary *PayloadOf(NSDictionary *resp) {
    if (!resp) return nil;
    id p = resp[@"payload"];
    return [p isKindOfClass:[NSDictionary class]] ? p : resp;
}

static BOOL IsUnlocked(NSDictionary *p) {
    return p && [p[@"ok"] boolValue] && [p[@"activationState"] isEqualToString:@"unlocked"];
}

static BOOL CachedValid(void) {
    @try {
        id d = [[NSUserDefaults standardUserDefaults] objectForKey:kLicenseKey];
        if (![d isKindOfClass:[NSData class]]) return NO;
        id resp = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![resp isKindOfClass:[NSDictionary class]]) return NO;
        if (!VerifyResponse(resp)) return NO;
        NSDictionary *p = PayloadOf(resp);
        if (!IsUnlocked(p)) return NO;
        NSNumber *exp = p[@"expires_at"];
        if ([exp isKindOfClass:[NSNumber class]] &&
            exp.doubleValue > 0 && exp.doubleValue < [[NSDate date] timeIntervalSince1970]) return NO;
        NSString *bound = p[@"device_id"];
        if ([bound isKindOfClass:[NSString class]] && bound.length &&
            ![bound isEqualToString:DeviceID()]) return NO;
        return YES;
    } @catch (NSException *e) { P("[E6] 缓存校验异常 %s", e.reason.UTF8String); return NO; }
}

// ---------- 界面 ----------
@interface AXPVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *hint;
@property (nonatomic, strong) UIActivityIndicatorView *spin;
@property (nonatomic, copy) void (^onDone)(BOOL);
@end

@implementation AXPVC

- (void)viewDidLoad {
    [super viewDidLoad];
    @try {
        P("[6a] viewDidLoad 进入");
        self.view.backgroundColor = [UIColor systemBackgroundColor];

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(24, 150, 342, 40)];
        title.text = @"激活 AX Pro Max";
        title.font = [UIFont boldSystemFontOfSize:26];
        title.textAlignment = NSTextAlignmentCenter;
        [self.view addSubview:title];

        UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(24, 196, 342, 24)];
        sub.text = @"请输入卡密完成激活";
        sub.font = [UIFont systemFontOfSize:14];
        sub.textColor = [UIColor secondaryLabelColor];
        sub.textAlignment = NSTextAlignmentCenter;
        [self.view addSubview:sub];

        self.field = [[UITextField alloc] initWithFrame:CGRectMake(32, 250, 326, 48)];
        self.field.placeholder = @"AXPM-XXXX-XXXX-XXXX-XXXX";
        self.field.borderStyle = UITextBorderStyleRoundedRect;
        self.field.textAlignment = NSTextAlignmentCenter;
        self.field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        self.field.autocorrectionType = UITextAutocorrectionTypeNo;
        self.field.delegate = self;
        [self.view addSubview:self.field];

        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(32, 312, 326, 48);
        [btn setTitle:@"立即激活" forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
        btn.backgroundColor = [UIColor systemBlueColor];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.layer.cornerRadius = 10;
        [btn addTarget:self action:@selector(tapActivate) forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:btn];

        self.spin = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
        self.spin.frame = CGRectMake(187, 380, 40, 40);
        self.spin.hidesWhenStopped = YES;
        [self.view addSubview:self.spin];

        self.hint = [[UILabel alloc] initWithFrame:CGRectMake(32, 428, 326, 60)];
        self.hint.font = [UIFont systemFontOfSize:13];
        self.hint.textColor = [UIColor systemRedColor];
        self.hint.textAlignment = NSTextAlignmentCenter;
        self.hint.numberOfLines = 0;
        [self.view addSubview:self.hint];

        P("[6b] 视图构建完成（frame 布局，无 Auto Layout）");
    } @catch (NSException *e) {
        P("[E7] viewDidLoad 异常 %s", e.reason.UTF8String);
    }
}

- (void)tapActivate {
    @try {
        NSString *card = [[self.field.text ?: @"" uppercaseString]
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (card.length < 8) { self.hint.text = @"卡密格式不正确"; return; }
        P("[7] 提交卡密 len=%lu", (unsigned long)card.length);
        self.hint.text = @"正在验证…";
        [self.spin startAnimating];

        NSDictionary *body = @{
            @"schema": @"KVREQ-V3",
            @"card_code": card,
            @"device_id": DeviceID() ?: @"",
            @"action": @"activate",
            @"app_version": @"1.6.1",
            @"bundle_id": [[NSBundle mainBundle] bundleIdentifier] ?: @"",
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        NSString *urlStr = [kServerURL stringByAppendingString:@"/api/v1/app/verify"];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 15;
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        [req setValue:kAppKey forHTTPHeaderField:@"X-App-Key"];
        req.HTTPBody = json;
        P("[8] 发起请求 %s", urlStr.UTF8String);

        __weak typeof(self) weakSelf = self;
        [[[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *data, NSURLResponse *r, NSError *err) {
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    __strong typeof(weakSelf) me = weakSelf;
                    if (!me) return;
                    [me.spin stopAnimating];
                    if (err || !data) {
                        P("[9] 网络失败 %s", err.localizedDescription.UTF8String ?: "nil");
                        me.hint.text = @"网络不通，请检查连接";
                        return;
                    }
                    P("[9] 收到响应 %lu 字节", (unsigned long)data.length);
                    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (![obj isKindOfClass:[NSDictionary class]]) { me.hint.text = @"响应格式错误"; return; }
                    if (!VerifyResponse(obj)) { P("[10] 验签失败"); me.hint.text = @"响应验签失败"; return; }
                    NSDictionary *p = PayloadOf(obj);
                    if (!IsUnlocked(p)) {
                        NSString *reason = p[@"reason"] ?: @"";
                        P("[10] 未通过 reason=%s", reason.UTF8String);
                        me.hint.text = @"卡密无效或已过期";
                        return;
                    }
                    P("[10] 验证通过，保存并关闭窗口");
                    NSData *save = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
                    if (save) {
                        [[NSUserDefaults standardUserDefaults] setObject:save forKey:kLicenseKey];
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    }
                    if (me.onDone) me.onDone(YES);
                } @catch (NSException *e) {
                    P("[E9] 回调异常 %s", e.reason.UTF8String);
                }
            });
        }] resume];
    } @catch (NSException *e) {
        P("[E8] 提交异常 %s", e.reason.UTF8String);
    }
}

@end

// ---------- 窗口 ----------
static UIWindow *gWin = nil;

static void ShowGate(void) {
    @try {
        if (gWin) return;
        P("[6] 准备创建激活窗口");
        UIWindow *w = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                w = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)s];
                break;
            }
        }
        if (!w) w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        if (!w) { P("[E10] 窗口创建失败"); return; }
        w.windowLevel = UIWindowLevelAlert + 100;

        AXPVC *vc = [[AXPVC alloc] init];
        __weak UIWindow *weakWin = w;
        vc.onDone = ^(BOOL ok) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                weakWin.hidden = YES;
                gWin = nil;
                P("[11] 窗口已关闭，进入 App");
            });
        };
        w.rootViewController = vc;
        w.alpha = 1;
        [w makeKeyAndVisible];
        gWin = w;
        P("[6c] 激活窗口已显示");
    } @catch (NSException *e) {
        P("[E11] ShowGate 异常 %s", e.reason.UTF8String);
    }
}

__attribute__((constructor))
static void GateEntry(void) {
    P("[1] constructor 进入");
    @try {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        P("[2] bundleIdentifier=%s whitelist=%s",
          bid.UTF8String ?: "?", [[AXPAllowedIDs() componentsJoinedByString:@","] UTF8String] ?: "?");
        if (!bid || ![AXPAllowedIDs() containsObject:bid]) {
            P("[2b] bundle id 不在白名单，退出");
            return;
        }
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) {
            P("[3] 启动通知触发");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @try {
                    BOOL ok = CachedValid();
                    P("[5] 本地缓存校验=%s", ok ? "有效" : "无效");
                    if (!ok) ShowGate();
                } @catch (NSException *e) { P("[E12] 延时块异常 %s", e.reason.UTF8String); }
            });
        }];
        P("[4] 通知已注册，constructor 结束");
    } @catch (NSException *e) {
        P("[E13] constructor 异常 %s", e.reason.UTF8String);
    }
}
