// gate.m —— AX Pro Max 卡密授权门
// 纯 ObjC + ObjC 运行时，不依赖 CydiaSubstrate / ElleKit，适合 TrollStore 侧载注入。
//
// 行为：
//   1) dylib 加载后在主线程挂一个最高层级 UIWindow，未授权前拦截全部交互；
//      （原 App 已被绕过，这里加的是"你自己的"门）
//   2) 卡密提交到你的服务端，用内置 RSA-2048 公钥对 payload_raw 做 PSS-SHA256 验签；
//   3) 验签通过后写入本地缓存，有效期内 + 设备一致则离线放行；
//   4) 可选开关：关掉原包的假服务器拦截器 AXZQURLProtocol（让 App 走真实网络）。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>

// ============================ 配置（由 patch/configure.py 生成 axp_config.h） ============================
#if __has_include("axp_config.h")
#import "axp_config.h"
#endif

#ifndef AXP_SERVER_URL
#define AXP_SERVER_URL     @"https://your.domain.com"
#endif
#ifndef AXP_PUBLIC_KEY_B64
#define AXP_PUBLIC_KEY_B64 @""
#endif
#ifndef AXP_APP_KEY
#define AXP_APP_KEY        @"ax_pro_max"
#endif
#ifndef AXP_BUNDLE_IDS
#define AXP_BUNDLE_IDS     @[ @"com.axp.promax", @"com.apple.music" ]
#endif
#ifndef AXP_DISABLE_AX_INTERCEPTOR
#define AXP_DISABLE_AX_INTERCEPTOR 0
#endif

static NSString *const kAXPServerURL       = AXP_SERVER_URL;
static NSString *const kAXPPublicKeyB64    = AXP_PUBLIC_KEY_B64;
static NSString *const kAXPAppKey          = AXP_APP_KEY;
static NSArray<NSString *> *AXPAllowedBundleIDs(void) { return AXP_BUNDLE_IDS; }
static const BOOL kAXPDisableAXInterceptor = (AXP_DISABLE_AX_INTERCEPTOR != 0);
// 时钟回拨容差（秒）：本地时间比"见过的最大时间"倒退超过该值即判定作弊
static const NSTimeInterval kAXPClockTolerance = 300;
// ---------- 自诊断：日志写入 <容器>/Documents/axp.log（可用「文件」App 取出） ----------
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
static void AXP_LOG(const char *fmt, ...) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/Documents/axp.log", home);
    FILE *fp = fopen(path, "a");
    if (!fp) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fprintf(fp, "\n");
    fclose(fp);
}
// =====================================================================================================

static NSString *const kAXPLicenseKey = @"AXP.License.v3";
static NSString *const kAXPCardKey = @"AXP.Card.v3";
static NSString *const kAXPLastSeenKey = @"AXP.LastSeen.v3";

/// 记录"见过的最大时间戳"，用于识别越狱设备把系统时间往回调来续命
static void AXPStampClock(void) {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    NSTimeInterval last = [u doubleForKey:kAXPLastSeenKey];
    if (now > last) {
        [u setDouble:now forKey:kAXPLastSeenKey];
        [u synchronize];
    }
}

static BOOL AXPClockLooksTampered(void) {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval last = [[NSUserDefaults standardUserDefaults] doubleForKey:kAXPLastSeenKey];
    if (last <= 0) return NO;
    return (now + kAXPClockTolerance) < last;
}

#pragma mark - 基础工具

static NSString *AXPSHA256HexOfData(NSData *d) {
    unsigned char out[CC_SHA256_DIGEST_LENGTH];
    const void *p = d.length ? d.bytes : (const void *)"";
    CC_SHA256(p, (CC_LONG)d.length, out);
    NSMutableString *s = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [s appendFormat:@"%02x", out[i]];
    return s;
}

static NSString *AXPDeviceID(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    NSData *d = [[NSString stringWithFormat:@"axp|%@", idfv] dataUsingEncoding:NSUTF8StringEncoding];
    return AXPSHA256HexOfData(d);
}

// PKCS#1 RSAPublicKey DER → SubjectPublicKeyInfo DER
static NSData *AXPSPKIFromPKCS1(NSData *pkcs1) {
    static const unsigned char kAlgo[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    NSUInteger n = pkcs1.length + 1;
    NSMutableData *bit = [NSMutableData data];
    unsigned char t = 0x03;
    [bit appendBytes:&t length:1];
    if (n < 0x80) {
        unsigned char l = (unsigned char)n;
        [bit appendBytes:&l length:1];
    } else if (n < 0x100) {
        unsigned char l[2] = {0x81, (unsigned char)n};
        [bit appendBytes:l length:2];
    } else {
        unsigned char l[3] = {0x82, (unsigned char)(n >> 8), (unsigned char)(n & 0xff)};
        [bit appendBytes:l length:3];
    }
    unsigned char zero = 0x00;
    [bit appendBytes:&zero length:1];
    [bit appendData:pkcs1];

    NSMutableData *body = [NSMutableData dataWithBytes:kAlgo length:sizeof(kAlgo)];
    [body appendData:bit];

    NSMutableData *out = [NSMutableData data];
    unsigned char seq = 0x30;
    NSUInteger bl = body.length;
    [out appendBytes:&seq length:1];
    if (bl < 0x80) {
        unsigned char l = (unsigned char)bl;
        [out appendBytes:&l length:1];
    } else if (bl < 0x100) {
        unsigned char b[2] = {0x81, (unsigned char)bl};
        [out appendBytes:b length:2];
    } else {
        unsigned char b[3] = {0x82, (unsigned char)(bl >> 8), (unsigned char)(bl & 0xff)};
        [out appendBytes:b length:3];
    }
    [out appendData:body];
    return out;
}

static SecKeyRef AXPPublicKey(void) {
    static SecKeyRef key = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!kAXPPublicKeyB64.length) {
            NSLog(@"[AXP] 公钥未配置：请用 patch/configure.py 生成 axp_config.h 后重新编译");
            return;
        }
        NSData *pkcs1 = [[NSData alloc] initWithBase64EncodedString:kAXPPublicKeyB64 options:0];
        if (!pkcs1) {
            NSLog(@"[AXP] 公钥 Base64 解析失败（长度 %lu）", (unsigned long)kAXPPublicKeyB64.length);
            return;
        }
        NSData *spki = AXPSPKIFromPKCS1(pkcs1);
        NSDictionary *attrs = @{
            (__bridge id)kSecAttrKeyType:      (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeyClass:     (__bridge id)kSecAttrKeyClassPublic,
            (__bridge id)kSecAttrKeySizeInBits: @2048,
        };
        CFErrorRef err = NULL;
        key = SecKeyCreateWithData((__bridge CFDataRef)spki,
                                   (__bridge CFDictionaryRef)attrs, &err);
        if (err) CFRelease(err);
    });
    return key;
}

// 验签对象 = 服务端返回的 payload_raw 原文（避免两端 JSON 序列化差异）
static BOOL AXPVerifyResponse(NSDictionary *resp) {
    if (![resp isKindOfClass:[NSDictionary class]]) return NO;
    NSString *raw = resp[@"payload_raw"];
    NSString *sigB64 = resp[@"signature"];
    if (![raw isKindOfClass:[NSString class]] || ![sigB64 isKindOfClass:[NSString class]]) return NO;
    SecKeyRef pub = AXPPublicKey();
    if (!pub) return NO;
    NSData *sig = [[NSData alloc] initWithBase64EncodedString:sigB64 options:0];
    NSData *msg = [raw dataUsingEncoding:NSUTF8StringEncoding];
    if (!sig || !msg) return NO;
    CFErrorRef err = NULL;
    BOOL ok = SecKeyVerifySignature(pub, kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
                                    (__bridge CFDataRef)msg, (__bridge CFDataRef)sig, &err);
    if (err) CFRelease(err);
    return ok;
}

static BOOL AXPUnlocked(NSDictionary *payload) {
    return [payload[@"ok"] boolValue] &&
           [payload[@"activationState"] isEqualToString:@"unlocked"];
}

#pragma mark - 本地授权缓存

static NSDictionary *AXPLoadLicense(void) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:kAXPLicenseKey];
    if (![v isKindOfClass:[NSData class]]) return nil;
    id o = [NSJSONSerialization JSONObjectWithData:v options:0 error:nil];
    return [o isKindOfClass:[NSDictionary class]] ? o : nil;
}

static void AXPSaveLicense(NSDictionary *resp) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
    if (!d) return;
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setObject:d forKey:kAXPLicenseKey];
    [u synchronize];
}

static BOOL AXPLicenseStillValid(void) {
    AXPStampClock();
    if (AXPClockLooksTampered()) {
        NSLog(@"[AXP] 检测到系统时间回拨");
        return NO;
    }
    NSDictionary *resp = AXPLoadLicense();
    if (!resp || !AXPVerifyResponse(resp)) return NO;
    NSDictionary *p = resp[@"payload"];
    if (![p isKindOfClass:[NSDictionary class]] || !AXPUnlocked(p)) return NO;
    NSTimeInterval exp = [p[@"expires_at"] doubleValue];
    if (exp > 0 && exp < [[NSDate date] timeIntervalSince1970]) return NO;
    NSString *bound = p[@"device_id"];
    if ([bound isKindOfClass:[NSString class]] && bound.length &&
        ![bound isEqualToString:AXPDeviceID()])
        return NO;
    return YES;
}

#pragma mark - 客户端

@interface AXPLicenseClient : NSObject
+ (void)verifyCard:(NSString *)card completion:(void (^)(BOOL ok, NSString *msg))done;
+ (void)refreshWithCompletion:(void (^)(BOOL ok))done;
@end

@implementation AXPLicenseClient

+ (NSURL *)endpoint:(NSString *)path {
    return [NSURL URLWithString:[kAXPServerURL stringByAppendingString:path]];
}

+ (void)post:(NSString *)path body:(NSDictionary *)body
  completion:(void (^)(NSDictionary *obj, NSError *err))done {
    NSURL *url = [self endpoint:path];
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 15;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"KVREQ-V3" forHTTPHeaderField:@"X-Protocol-Version"];
    [req setValue:@"1.6.1" forHTTPHeaderField:@"X-Version"];
    [req setValue:kAXPAppKey forHTTPHeaderField:@"X-App-Key"];
    [req setValue:AXPSHA256HexOfData(json) forHTTPHeaderField:@"X-Body-SHA256"];
    req.HTTPBody = json;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *r, NSError *e) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (e || !data) { done(nil, e); return; }
            id o = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            done([o isKindOfClass:[NSDictionary class]] ? o : nil, nil);
        });
    }] resume];
}

+ (NSDictionary *)requestBodyWithCard:(NSString *)card action:(NSString *)action {
    return @{
        @"schema": @"KVREQ-V3",
        @"card_code": card ?: @"",
        @"device_id": AXPDeviceID(),
        @"nonce": [[NSUUID UUID] UUIDString],
        @"issued_at": @([[NSDate date] timeIntervalSince1970]),
        @"app_version": [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"",
        @"bundle_id": [[NSBundle mainBundle] bundleIdentifier] ?: @"",
        @"action": action,
    };
}

+ (NSString *)localizedReason:(NSString *)reason {
    static NSDictionary *map;
    static dispatch_once_t o;
    dispatch_once(&o, ^{
        map = @{
            @"card_not_found": @"卡密不存在",
            @"expired": @"卡密已过期",
            @"revoked": @"卡密已被封禁",
            @"device_limit": @"该卡密已绑定其他设备",
            @"bad_request": @"请求参数错误",
        };
    });
    if (!reason.length) return @"激活失败";
    return map[reason] ?: reason;
}

+ (void)verifyCard:(NSString *)card completion:(void (^)(BOOL, NSString *))done {
    NSString *clean = [[card uppercaseString]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    [self post:@"/api/v1/app/verify"
          body:[self requestBodyWithCard:clean action:@"activate"]
    completion:^(NSDictionary *obj, NSError *err) {
        if (err || !obj) {
            if (AXPLicenseStillValid()) { done(YES, @"离线授权有效"); return; }
            done(NO, @"网络异常，请稍后重试");
            return;
        }
        if (!AXPVerifyResponse(obj)) { done(NO, @"服务器响应验签失败"); return; }
        NSDictionary *p = obj[@"payload"];
        if (AXPUnlocked(p)) {
            AXPSaveLicense(obj);
            [[NSUserDefaults standardUserDefaults] setObject:clean forKey:kAXPCardKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
            done(YES, @"");
            return;
        }
        done(NO, [self localizedReason:p[@"reason"]]);
    }];
}

+ (void)refreshWithCompletion:(void (^)(BOOL))done {
    NSString *card = [[NSUserDefaults standardUserDefaults] stringForKey:kAXPCardKey] ?: @"";
    if (!card.length) { done(AXPLicenseStillValid()); return; }
    [self post:@"/api/v1/app/heartbeat"
          body:[self requestBodyWithCard:card action:@"heartbeat"]
    completion:^(NSDictionary *obj, NSError *err) {
        if (err || !obj) { done(AXPLicenseStillValid()); return; }
        if (AXPVerifyResponse(obj)) {
            NSDictionary *p = obj[@"payload"];
            if (AXPUnlocked(p)) { AXPSaveLicense(obj); done(YES); return; }
        }
        done(NO);
    }];
}

@end

#pragma mark - 授权界面

@interface AXPGateController : UIViewController
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *hint;
@property (nonatomic, strong) UIButton *button;
@property (nonatomic, strong) UIActivityIndicatorView *spin;
@property (nonatomic, copy) void (^onUnlocked)(void);
@end

@implementation AXPGateController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *title = [UILabel new];
    title.text = @"激活 AX Pro Max";
    title.font = [UIFont systemFontOfSize:26 weight:UIFontWeightBold];
    title.textAlignment = NSTextAlignmentCenter;

    UILabel *sub = [UILabel new];
    sub.text = @"请输入你的卡密完成激活";
    sub.font = [UIFont systemFontOfSize:14];
    sub.textColor = [UIColor secondaryLabelColor];
    sub.textAlignment = NSTextAlignmentCenter;

    UITextField *f = [UITextField new];
    f.placeholder = @"AXPM-XXXX-XXXX-XXXX-XXXX";
    f.borderStyle = UITextBorderStyleRoundedRect;
    f.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    f.autocorrectionType = UITextAutocorrectionTypeNo;
    f.textAlignment = NSTextAlignmentCenter;
    f.font = [UIFont monospacedSystemFontOfSize:16 weight:UIFontWeightMedium];
    f.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.field = f;

    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:@"立即激活" forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
    b.backgroundColor = [UIColor systemBlueColor];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.layer.cornerRadius = 10;
    [b addTarget:self action:@selector(activateTapped) forControlEvents:UIControlEventTouchUpInside];
    self.button = b;

    UILabel *hint = [UILabel new];
    hint.font = [UIFont systemFontOfSize:13];
    hint.textColor = [UIColor systemRedColor];
    hint.textAlignment = NSTextAlignmentCenter;
    hint.numberOfLines = 0;
    self.hint = hint;

    UIActivityIndicatorView *sp = [[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    sp.hidesWhenStopped = YES;
    self.spin = sp;

    for (UIView *v in @[title, sub, f, b, sp, hint]) {
        v.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:v];
    }

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [title.topAnchor constraintEqualToAnchor:g.topAnchor constant:110],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [sub.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [f.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:36],
        [f.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:32],
        [f.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-32],
        [f.heightAnchor constraintEqualToConstant:48],
        [b.topAnchor constraintEqualToAnchor:f.bottomAnchor constant:16],
        [b.leadingAnchor constraintEqualToAnchor:f.leadingAnchor],
        [b.trailingAnchor constraintEqualToAnchor:f.trailingAnchor],
        [b.heightAnchor constraintEqualToConstant:48],
        [sp.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [sp.topAnchor constraintEqualToAnchor:b.bottomAnchor constant:18],
        [hint.topAnchor constraintEqualToAnchor:sp.bottomAnchor constant:8],
        [hint.leadingAnchor constraintEqualToAnchor:f.leadingAnchor],
        [hint.trailingAnchor constraintEqualToAnchor:f.trailingAnchor],
    ]];
}

- (void)activateTapped {
    NSString *raw = self.field.text ?: @"";
    if (raw.length < 8) { self.hint.text = @"卡密格式不正确"; return; }
    self.hint.text = @"";
    self.button.enabled = NO;
    [self.spin startAnimating];
    __weak typeof(self) weakSelf = self;
    [AXPLicenseClient verifyCard:raw completion:^(BOOL ok, NSString *msg) {
        __strong typeof(weakSelf) s = weakSelf;
        [s.spin stopAnimating];
        s.button.enabled = YES;
        if (ok) {
            s.hint.text = @"";
            if (s.onUnlocked) s.onUnlocked();
        } else {
            s.hint.text = msg;
        }
    }];
}

@end

#pragma mark - 授权门管理

@interface AXPGate : NSObject
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AXPGate

+ (instancetype)shared {
    static AXPGate *g;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [AXPGate new]; });
    return g;
}

- (void)presentIfNeeded {
    AXP_LOG("[5] 检查本地缓存授权");
    if (AXPLicenseStillValid()) {
        AXP_LOG("[5a] 缓存有效，静默续期");
        // 已授权：后台静默续期，不影响使用
        [AXPLicenseClient refreshWithCompletion:^(BOOL ok) {
            if (!ok) dispatch_async(dispatch_get_main_queue(), ^{ [self present]; });
        }];
        return;
    }
    [self present];
}

- (void)present {
    if (self.window) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        AXP_LOG("[6] 开始构建激活窗口");
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
        }
        UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                            : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        w.windowLevel = UIWindowLevelAlert + 100;
        AXPGateController *vc = [AXPGateController new];
        __weak typeof(self) weakSelf = self;
        vc.onUnlocked = ^{
            __strong typeof(weakSelf) s = weakSelf;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.25 animations:^{ s.window.alpha = 0; }
                                 completion:^(BOOL finished) {
                    s.window.hidden = YES;
                    s.window = nil;
                }];
            });
        };
        w.rootViewController = vc;
        w.alpha = 1;
        [w makeKeyAndVisible];
        self.window = w;
        AXP_LOG("[7] 激活窗口已显示");
    });
}

@end

#pragma mark - 可选：关掉原包的假服务器拦截器

static BOOL AXP_canInitWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    return NO;   // 一律不拦截 -> 请求走真实网络
}

static void AXPKillFakeServerIfNeeded(void) {
    if (!kAXPDisableAXInterceptor) return;
    Class cls = objc_getClass("AXZQURLProtocol");
    if (!cls) return;
    Method m = class_getClassMethod(cls, @selector(canInitWithRequest:));
    if (m) method_setImplementation(m, (IMP)AXP_canInitWithRequest);
}

#pragma mark - 入口

__attribute__((constructor))
static void AXPGateInit(void) {
    AXP_LOG("[1] constructor 进入");
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        AXP_LOG("[2] bundleIdentifier=%s whitelist=%s", [bid ?: @"" UTF8String] ?: "?", [[AXPAllowedBundleIDs() componentsJoinedByString:@","] UTF8String] ?: "?");
        if (![AXPAllowedBundleIDs() containsObject:bid]) {
            AXP_LOG("[2b] bundle id 不在白名单，退出");
            return;
        }
        AXPKillFakeServerIfNeeded();

        AXPStampClock();
        void (^kick)(NSNotification *) = ^(NSNotification *note) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                AXP_LOG("[3] 启动通知触发，开始判断");
                [[AXPGate shared] presentIfNeeded];
                AXP_LOG("[4] presentIfNeeded 返回");
            });
        };
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        // WillFinish 先挂一次（越早越好），DidFinish 再兜一次（防错过）
        [nc addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil queue:[NSOperationQueue mainQueue] usingBlock:kick];
    }
}
