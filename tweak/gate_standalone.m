// gate_standalone.m —— arm64e 兼容版授权门（无 ObjC 回调 / 无 block / 无 IMP）
//
// 为什么这么写：
//   本机用 Zig 只能编出 arm64 机器码，而目标进程是 arm64e。arm64 代码在 arm64e
//   运行时里做 ObjC 回调（IMP、block invoke）有 ptrauth 风险，所以这里只用
//   **纯 C 回调**：CFRunLoopTimer 的 callout、pthread 的线程函数。
//   界面轮询文本、自动提交；网络用同步 NSData，不注册任何 handler。
//
// 编译（见 patch/build_dylib.ps1）：
//   zig cc -target aarch64-macos -dynamiclib ... ;然后改 cpusubtype 为 0x80000002

typedef unsigned long size_t;
typedef signed char BOOL8;
typedef unsigned long NSUInteger;
typedef long NSInteger;
typedef double CGFloat;
typedef struct { CGFloat x, y; } CGPoint;
typedef struct { CGFloat width, height; } CGSize;
typedef struct { CGPoint origin; CGSize size; } CGRect;

typedef const void *CFTypeRef;
typedef const struct __CFData *CFDataRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef const struct __CFString *CFStringRef;
typedef struct __CFError *CFErrorRef;
typedef const struct __CFRunLoop *CFRunLoopRef;
typedef struct __CFRunLoopTimer *CFRunLoopTimerRef;
typedef struct __SecKey *SecKeyRef;
typedef double CFAbsoluteTime;
typedef double CFTimeInterval;
typedef void *SEL;
typedef void *pthread_t;

extern size_t strlen(const char *s);
extern int strcmp(const char *a, const char *b);
extern void *memcpy(void *d, const void *s, size_t n);
extern int snprintf(char *b, size_t n, const char *f, ...);
extern int pthread_create(pthread_t *th, const void *attr, void *(*fn)(void *), void *arg);
extern int pthread_detach(pthread_t th);

#ifndef NULL
#define NULL ((void *)0)
#endif
#define NIL ((id)0)

extern void *objc_getClass(const char *name);
extern SEL sel_registerName(const char *name);
extern id objc_msgSend(id self, SEL op, ...);

extern CFTimeInterval CFAbsoluteTimeGetCurrent(void);
extern CFRunLoopRef CFRunLoopGetMain(void);
extern void CFRunLoopAddTimer(CFRunLoopRef rl, CFRunLoopTimerRef t, CFStringRef mode);
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void *allocator, CFAbsoluteTime fireDate,
                                              CFTimeInterval interval, unsigned long flags,
                                              long order,
                                              void (*callout)(CFRunLoopTimerRef, void *),
                                              void *context);
extern const CFStringRef kCFRunLoopDefaultMode;
extern void CFRelease(CFTypeRef cf);

extern SecKeyRef SecKeyCreateWithData(CFDataRef data, CFDictionaryRef attrs, CFErrorRef *error);
extern BOOL8 SecKeyVerifySignature(SecKeyRef key, CFStringRef alg, CFDataRef data,
                                   CFDataRef sig, CFErrorRef *error);
extern const CFStringRef kSecAttrKeyType;
extern const CFStringRef kSecAttrKeyClass;
extern const CFStringRef kSecAttrKeySizeInBits;
extern const CFStringRef kSecAttrKeyTypeRSA;
extern const CFStringRef kSecAttrKeyClassPublic;
extern const CFStringRef kSecKeyAlgorithmRSASignatureMessagePSSSHA256;

extern unsigned char *CC_SHA256(const void *data, unsigned int len, unsigned char *md);
#define SHA256_LEN 32

// ---------- 消息发送（固定元数） ----------
#define CLS(name) ((id)objc_getClass(name))
#define O0(T, o, s)            ((T (*)(id, SEL))objc_msgSend)((id)(o), sel_registerName(s))
#define O1(T, o, s, a)         ((T (*)(id, SEL, id))objc_msgSend)((id)(o), sel_registerName(s), (id)(a))
#define O2(T, o, s, a, b)      ((T (*)(id, SEL, id, id))objc_msgSend)((id)(o), sel_registerName(s), (id)(a), (id)(b))
#define P1(T, o, s, a)         ((T (*)(id, SEL, const void *))objc_msgSend)((id)(o), sel_registerName(s), (const void *)(a))
#define N1(T, o, s, a)         ((T (*)(id, SEL, unsigned long))objc_msgSend)((id)(o), sel_registerName(s), (unsigned long)(a))
#define I1(T, o, s, a)         ((T (*)(id, SEL, long))objc_msgSend)((id)(o), sel_registerName(s), (long)(a))
#define D1(T, o, s, a)         ((T (*)(id, SEL, double))objc_msgSend)((id)(o), sel_registerName(s), (double)(a))
#define R1(T, o, s, a)         ((T (*)(id, SEL, CGRect))objc_msgSend)((id)(o), sel_registerName(s), (CGRect)(a))
#define SN2(T, o, s, a, b)     ((T (*)(id, SEL, id, unsigned long))objc_msgSend)((id)(o), sel_registerName(s), (id)(a), (unsigned long)(b))
#define N2P(T, o, s, a, b, c)  ((T (*)(id, SEL, id, unsigned long, const void *))objc_msgSend)((id)(o), sel_registerName(s), (id)(a), (unsigned long)(b), (const void *)(c))
#define PPN(T, o, s, a, b, c)  ((T (*)(id, SEL, const void *, const void *, unsigned long))objc_msgSend)((id)(o), sel_registerName(s), (const void *)(a), (const void *)(b), (unsigned long)(c))
#define PN(T, o, s, a, b)      ((T (*)(id, SEL, const void *, unsigned long))objc_msgSend)((id)(o), sel_registerName(s), (const void *)(a), (unsigned long)(b))

#define CSTR(c)  str_impl((const char *)(c))
#define UTF8(s)  ((s) ? ((const char *(*)(id, SEL))objc_msgSend)((id)(s), sel_registerName("UTF8String")) : NULL)

static id str_impl(const char *c) {
    if (!c) return NIL;
    return P1(id, CLS("NSString"), "stringWithUTF8String:", c);
}

static BOOL8 str_eq(id a, const char *b) {
    if (!a || !b) return 0;
    const char *x = UTF8(a);
    return x && strcmp(x, b) == 0;
}

// ---------- 配置 ----------
#if __has_include("axp_config.h")
#include "axp_config.h"
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
#ifndef AXP_BUNDLE_IDS_C
#define AXP_BUNDLE_IDS_C "com.axp.promax"
#endif

static id kServerURL = AXP_SERVER_URL;
static id kPubKeyB64 = AXP_PUBLIC_KEY_B64;
static id kAppKeyName = AXP_APP_KEY;
static const char *kBundleCSV = AXP_BUNDLE_IDS_C;
static id kLicenseKey = @"AXP.License.v5";

// ---------- 工具 ----------
static void hex32(const unsigned char *d, char *out) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < SHA256_LEN; i++) {
        out[i * 2] = h[d[i] >> 4];
        out[i * 2 + 1] = h[d[i] & 0xF];
    }
    out[SHA256_LEN * 2] = 0;
}

static id sha256hexStr(const char *c) {
    if (!c) return NIL;
    unsigned char d[SHA256_LEN];
    CC_SHA256(c, (unsigned int)strlen(c), d);
    char out[SHA256_LEN * 2 + 1];
    hex32(d, out);
    return str_impl(out);
}

static char gDeviceID[80] = {0};
static const char *deviceIDC(void) {
    if (gDeviceID[0]) return gDeviceID;
    id dev = O0(id, CLS("UIDevice"), "currentDevice");
    id idfv = dev ? O0(id, dev, "identifierForVendor") : NIL;
    id uuid = idfv ? O0(id, idfv, "UUIDString") : NIL;
    const char *u = uuid ? UTF8(uuid) : "unknown-device";
    if (!u) u = "unknown-device";
    char raw[128];
    snprintf(raw, sizeof(raw), "axp|%s", u);
    unsigned char d[SHA256_LEN];
    CC_SHA256(raw, (unsigned int)strlen(raw), d);
    hex32(d, gDeviceID);
    return gDeviceID;
}

static BOOL8 bundleAllowed(void) {
    id bid = O0(id, O0(id, CLS("NSBundle"), "mainBundle"), "bundleIdentifier");
    if (!bid || !kBundleCSV) return 0;
    const char *b = UTF8(bid);
    if (!b) return 0;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", kBundleCSV);
    char *cur = tmp;
    while (cur && *cur) {
        char *comma = NULL;
        for (char *q = cur; *q; q++) if (*q == ',') { comma = q; break; }
        if (comma) *comma = 0;
        if (strcmp(cur, b) == 0) return 1;
        cur = comma ? comma + 1 : NULL;
    }
    return 0;
}

static id spkiFromPkcs1(id pkcs1) {
    if (!pkcs1) return NIL;
    const unsigned char *in = O0(const unsigned char *, pkcs1, "bytes");
    NSUInteger n = O0(NSUInteger, pkcs1, "length");
    if (!in || n == 0 || n > 512) return NIL;
    static const unsigned char algo[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    unsigned char mid[1200];
    NSUInteger p = 0;
    NSUInteger bitlen = n + 1;
    mid[p++] = 0x03;
    if (bitlen < 0x80) { mid[p++] = (unsigned char)bitlen; }
    else if (bitlen < 0x100) { mid[p++] = 0x81; mid[p++] = (unsigned char)bitlen; }
    else { mid[p++] = 0x82; mid[p++] = (unsigned char)(bitlen >> 8); mid[p++] = (unsigned char)(bitlen & 0xFF); }
    mid[p++] = 0x00;
    memcpy(mid + p, in, n);
    p += n;
    NSUInteger bodyLen = sizeof(algo) + p;
    unsigned char out[1300];
    NSUInteger q = 0;
    out[q++] = 0x30;
    if (bodyLen < 0x80) { out[q++] = (unsigned char)bodyLen; }
    else if (bodyLen < 0x100) { out[q++] = 0x81; out[q++] = (unsigned char)bodyLen; }
    else { out[q++] = 0x82; out[q++] = (unsigned char)(bodyLen >> 8); out[q++] = (unsigned char)(bodyLen & 0xFF); }
    memcpy(out + q, algo, sizeof(algo));
    q += sizeof(algo);
    memcpy(out + q, mid, p);
    q += p;
    return PN(id, CLS("NSData"), "dataWithBytes:length:", out, (unsigned long)q);
}

static SecKeyRef publicKey(void) {
    static SecKeyRef key = NULL;
    if (key) return key;
    if (!kPubKeyB64 || O0(NSUInteger, kPubKeyB64, "length") < 100) return NULL;
    id pkcs1 = SN2(id, CLS("NSData"), "initWithBase64EncodedString:options:", kPubKeyB64, 0ul);
    if (!pkcs1) return NULL;
    id spki = spkiFromPkcs1(pkcs1);
    if (!spki) return NULL;
    id n2048 = I1(id, CLS("NSNumber"), "numberWithInt:", 2048);
    id keys[3]; id vals[3];
    keys[0] = (id)kSecAttrKeyType;  vals[0] = (id)kSecAttrKeyTypeRSA;
    keys[1] = (id)kSecAttrKeyClass; vals[1] = (id)kSecAttrKeyClassPublic;
    keys[2] = (id)kSecAttrKeySizeInBits; vals[2] = n2048;
    id attrs = PPN(id, CLS("NSDictionary"), "dictionaryWithObjects:forKeys:count:", vals, keys, 3ul);
    if (!attrs) return NULL;
    key = SecKeyCreateWithData((CFDataRef)spki, (CFDictionaryRef)attrs, NULL);
    return key;
}

static BOOL8 verifyResponse(id resp) {
    if (!resp) return 0;
    id raw = O1(id, resp, "objectForKeyedSubscript:", CSTR("payload_raw"));
    id sigB64 = O1(id, resp, "objectForKeyedSubscript:", CSTR("signature"));
    if (!raw || !sigB64) return 0;
    SecKeyRef pub = publicKey();
    if (!pub) return 0;
    id sig = SN2(id, CLS("NSData"), "initWithBase64EncodedString:options:", sigB64, 0ul);
    id msg = N1(id, raw, "dataUsingEncoding:", 4ul);
    if (!sig || !msg) return 0;
    return SecKeyVerifySignature(pub, kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
                                 (CFDataRef)msg, (CFDataRef)sig, NULL);
}

static BOOL8 isUnlocked(id payload) {
    if (!payload) return 0;
    id ok = O1(id, payload, "objectForKeyedSubscript:", CSTR("ok"));
    id st = O1(id, payload, "objectForKeyedSubscript:", CSTR("activationState"));
    if (!ok || !st) return 0;
    if (!O0(BOOL8, ok, "boolValue")) return 0;
    return str_eq(st, "unlocked");
}

static BOOL8 cachedValid(void) {
    id u = O0(id, CLS("NSUserDefaults"), "standardUserDefaults");
    id d = u ? O1(id, u, "objectForKey:", kLicenseKey) : NIL;
    if (!d) return 0;
    id resp = N2P(id, CLS("NSJSONSerialization"), "JSONObjectWithData:options:error:", d, 0ul, NULL);
    if (!resp || !verifyResponse(resp)) return 0;
    id p = O1(id, resp, "objectForKeyedSubscript:", CSTR("payload"));
    if (!isUnlocked(p)) return 0;
    id exp = O1(id, p, "objectForKeyedSubscript:", CSTR("expires_at"));
    if (exp) {
        double e = O0(double, exp, "doubleValue");
        double now = O0(double, O0(id, CLS("NSDate"), "date"), "timeIntervalSince1970");
        if (e > 0 && e < now) return 0;
    }
    id bound = O1(id, p, "objectForKeyedSubscript:", CSTR("device_id"));
    const char *mine = deviceIDC();
    if (bound && mine) {
        const char *bs = UTF8(bound);
        if (bs && strcmp(bs, mine) != 0) return 0;
    }
    return 1;
}

static void saveLicense(id resp) {
    id d = N2P(id, CLS("NSJSONSerialization"), "dataWithJSONObject:options:error:", resp, 0ul, NULL);
    if (!d) return;
    id u = O0(id, CLS("NSUserDefaults"), "standardUserDefaults");
    if (!u) return;
    O2(void, u, "setObject:forKey:", d, kLicenseKey);
    O0(BOOL8, u, "synchronize");
}

// ---------- 状态机 ----------
static id gWindow = NIL, gField = NIL, gHint = NIL, gSpinner = NIL, gButton = NIL;
static volatile int gState = 0;            // 0=等输入 1=请求中 2=成功 3=失败
static char gCard[64] = {0};
static char gMsg[160] = {0};

static void *fetch_thread(void *arg) {
    (void)arg;
    char url[512];
    snprintf(url, sizeof(url), "%s/api/v1/app/verify?card_code=%s&device_id=%s",
             UTF8(kServerURL) ? UTF8(kServerURL) : "", gCard, deviceIDC());
    id u = O1(id, CLS("NSURL"), "URLWithString:", str_impl(url));
    id data = u ? O1(id, CLS("NSData"), "dataWithContentsOfURL:", u) : NIL;
    if (!data) {
        snprintf(gMsg, sizeof(gMsg), "网络不通");
        gState = 3;
        return NULL;
    }
    id resp = N2P(id, CLS("NSJSONSerialization"), "JSONObjectWithData:options:error:", data, 0ul, NULL);
    if (!resp || !verifyResponse(resp)) {
        snprintf(gMsg, sizeof(gMsg), "响应验签失败");
        gState = 3;
        return NULL;
    }
    id p = O1(id, resp, "objectForKeyedSubscript:", CSTR("payload"));
    if (!isUnlocked(p)) {
        id r = O1(id, p, "objectForKeyedSubscript:", CSTR("reason"));
        const char *rs = r ? UTF8(r) : "";
        if (rs && strcmp(rs, "expired") == 0) snprintf(gMsg, sizeof(gMsg), "卡密已过期");
        else if (rs && strcmp(rs, "device_limit") == 0) snprintf(gMsg, sizeof(gMsg), "已绑定其他设备");
        else if (rs && strcmp(rs, "revoked") == 0) snprintf(gMsg, sizeof(gMsg), "卡密已被封禁");
        else snprintf(gMsg, sizeof(gMsg), "卡密无效");
        gState = 3;
        return NULL;
    }
    saveLicense(resp);
    gState = 2;
    return NULL;
}

static id newLabel(const char *text, double size, BOOL8 bold) {
    id l = O0(id, CLS("UILabel"), "new");
    if (!l) return NIL;
    if (text) O1(void, l, "setText:", CSTR(text));
    id font = bold ? D1(id, CLS("UIFont"), "boldSystemFontOfSize:", size)
                   : D1(id, CLS("UIFont"), "systemFontOfSize:", size);
    if (font) O1(void, l, "setFont:", font);
    I1(void, l, "setTextAlignment:", 1);
    I1(void, l, "setNumberOfLines:", 0);
    return l;
}

static void buildGate(void) {
    if (gWindow) return;
    if (!CLS("UIWindow") || !CLS("UIViewController")) return;

    id window = NIL;
    id app = O0(id, CLS("UIApplication"), "sharedApplication");
    id scenes = app ? O0(id, app, "connectedScenes") : NIL;
    id scene = NIL;
    if (scenes) {
        id it = O0(id, scenes, "objectEnumerator");
        id s = it ? O0(id, it, "nextObject") : NIL;
        while (s) {
            if (O1(BOOL8, s, "isKindOfClass:", CLS("UIWindowScene"))) { scene = s; break; }
            s = O0(id, it, "nextObject");
        }
    }
    if (scene) window = O1(id, O0(id, CLS("UIWindow"), "alloc"), "initWithWindowScene:", scene);
    if (!window) {
        CGRect r = { {0, 0}, {390, 844} };
        window = R1(id, O0(id, CLS("UIWindow"), "alloc"), "initWithFrame:", r);
    }
    if (!window) return;

    D1(void, window, "setWindowLevel:", 2100.0);
    id vc = O0(id, CLS("UIViewController"), "new");
    id root = vc ? O0(id, vc, "view") : NIL;
    if (!root) return;
    id bg = O0(id, CLS("UIColor"), "systemBackgroundColor");
    if (bg) O1(void, root, "setBackgroundColor:", bg);

    id title = newLabel("\u6fc0\u6d3b AX Pro Max", 26, 1);
    id sub = newLabel("\u8f93\u5165\u5361\u5bc6\uff0c\u81ea\u52a8\u9a8c\u8bc1", 14, 0);
    id field = O0(id, CLS("UITextField"), "new");
    if (field) {
        O1(void, field, "setPlaceholder:", CSTR("AXPM-XXXX-XXXX-XXXX-XXXX"));
        I1(void, field, "setBorderStyle:", 3);
        I1(void, field, "setTextAlignment:", 1);
    }
    id spinner = I1(id, O0(id, CLS("UIActivityIndicatorView"), "alloc"),
                    "initWithActivityIndicatorStyle:", 100);
    if (spinner) O1(void, spinner, "setHidesWhenStopped:", (id)1);
    id hint = newLabel(NULL, 13, 0);
    id red = O0(id, CLS("UIColor"), "systemRedColor");
    if (hint && red) O1(void, hint, "setTextColor:", red);

    CGRect ft = { {24, 150}, {342, 40} };
    CGRect fs = { {24, 196}, {342, 24} };
    CGRect ff = { {32, 250}, {326, 48} };
    CGRect fp = { {175, 316}, {40, 40} };
    CGRect fh = { {32, 364}, {326, 60} };
    if (title) { R1(void, title, "setFrame:", ft); O1(void, root, "addSubview:", title); }
    if (sub)   { R1(void, sub, "setFrame:", fs);   O1(void, root, "addSubview:", sub); }
    if (field) { R1(void, field, "setFrame:", ff); O1(void, root, "addSubview:", field); }
    if (spinner) { R1(void, spinner, "setFrame:", fp); O1(void, root, "addSubview:", spinner); }
    if (hint)  { R1(void, hint, "setFrame:", fh);  O1(void, root, "addSubview:", hint); }

    gWindow = window; gField = field; gHint = hint; gSpinner = spinner; gButton = NIL;
    O1(void, window, "setRootViewController:", vc);
    O0(void, window, "makeKeyAndVisible");
}

static void tick(CFRunLoopTimerRef timer, void *info) {
    (void)timer; (void)info;
    if (!gWindow) {
        if (!cachedValid()) buildGate();
        return;
    }

    if (gState == 2) {
        O1(void, gWindow, "setHidden:", (id)1);
        gWindow = NIL; gField = NIL; gHint = NIL; gSpinner = NIL;
        gState = 0;
        gMsg[0] = 0;
        return;
    }
    if (gState == 3) {
        if (gSpinner) O0(void, gSpinner, "stopAnimating");
        if (gHint) O1(void, gHint, "setText:", CSTR(gMsg[0] ? gMsg : "激活失败"));
        gState = 0;
        return;
    }
    if (gState == 1) return;   // 请求中

    // 轮询输入框：长度够了且与上次不同 -> 提交
    id text = O0(id, gField, "text");
    if (!text) return;
    const char *t = UTF8(text);
    if (!t || strlen(t) < 16) return;
    if (strcmp(t, gCard) == 0) return;
    snprintf(gCard, sizeof(gCard), "%s", t);
    gState = 1;
    if (gSpinner) O0(void, gSpinner, "startAnimating");
    if (gHint) O1(void, gHint, "setText:", CSTR("\u6b63\u5728\u9a8c\u8bc1\u2026"));
    pthread_t th;
    if (pthread_create(&th, NULL, fetch_thread, NULL) == 0) pthread_detach(th);
    else gState = 3;
}

// ---------- 入口 ----------
__attribute__((constructor))
static void gate_entry(void) {
    @try {
        if (!bundleAllowed()) return;
        CFRunLoopTimerRef t = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + 0.8,
                                                   1.0, 0, 0, tick, NULL);
        if (t) {
            CFRunLoopAddTimer(CFRunLoopGetMain(), t, kCFRunLoopDefaultMode);
        } else {
            buildGate();
        }
    } @catch (id e) { }
}
