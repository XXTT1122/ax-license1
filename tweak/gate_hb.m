// gate_hb.m —— 心跳探针：每 0.1 秒写一行日志，不做任何 UI
// 目的：测出"注入 dylib 后 App 能存活多久"，判断是不是被系统杀掉
//   只看到几行心跳就断 -> 进程被外部杀死（AMFI/签名/看门狗）
//   一直写到 150 行（15 秒）-> App 活着，问题不在加载层

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static int gTick = 0;

static void P(const char *fmt, ...) {
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
}

static void Tick(CFRunLoopTimerRef t, void *info) {
    (void)t; (void)info;
    gTick++;
    P("[HB %d] 进程存活 %.1f 秒", gTick, gTick * 0.1);
    if (gTick >= 150) {
        P("[HB done] 存活了 15 秒，加载层没问题");
    }
}

__attribute__((constructor))
static void hb_entry(void) {
    @autoreleasepool {
        P("===== 心跳探针开始 =====");
        P("[HB 0] dylib 已加载");
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        P("[HB 0] bundleIdentifier=%s", bid ? [bid UTF8String] : "(nil)");

        CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL,
            CFAbsoluteTimeGetCurrent() + 0.1, 0.1, 0, 0, Tick, NULL);
        if (timer) {
            CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopDefaultMode);
            P("[HB 0] 定时器已挂到主 runloop");
        } else {
            P("[HB 0] 定时器创建失败");
        }

        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) {
            P("[HB] 收到 didFinishLaunching");
        }];
    }
}
