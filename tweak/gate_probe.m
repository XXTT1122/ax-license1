// gate_probe.m —— 只写日志、不做任何 UI 的探针 dylib
// 用途：判断"App 闪退"是因为 dylib 的存在/签名，还是因为闸门的界面代码。
//   - 装上探针后 App 能正常进  -> 问题在闸门代码
//   - 装上探针后仍然闪退        -> 问题在注入/签名层，需要换方案

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

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

__attribute__((constructor))
static void probe_entry(void) {
    @autoreleasepool {
        P("[probe] dylib 已加载并执行构造函数");
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        P("[probe] bundleIdentifier=%s", bid ? [bid UTF8String] : "(nil)");
        P("[probe] 探针结束，不创建任何界面，交还给 App");
    }
}
