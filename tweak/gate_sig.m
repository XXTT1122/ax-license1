// gate_sig.m —— 信号探针
//
// 目的：区分「进程内崩溃」和「被系统 SIGKILL」
//   * 后台 pthread 每 0.1 秒写心跳（不依赖主 runloop，主线程卡住也能继续写）
//   * 捕获 SIGSEGV / SIGBUS / SIGABRT / SIGILL / SIGTRAP，崩溃前把信号号写进日志
//   * 注册 atexit，正常退出也能看出来
//
// 读法：
//   日志出现 [SIG xx]        -> 进程内崩溃（可定位、可修）
//   日志只有心跳、突然中断    -> 被 SIGKILL（外部杀，通常是签名/AMFI/看门狗）
//   日志出现 [exit]          -> 正常退出（App 自己调了 exit）

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

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

static void on_signal(int sig) {
    const char *name = "?";
    switch (sig) {
        case SIGSEGV: name = "SIGSEGV(段错误)"; break;
        case SIGBUS:  name = "SIGBUS(总线错误)"; break;
        case SIGABRT: name = "SIGABRT(abort)"; break;
        case SIGILL:  name = "SIGILL(非法指令)"; break;
        case SIGTRAP: name = "SIGTRAP"; break;
        case SIGFPE:  name = "SIGFPE"; break;
    }
    P("[SIG] 捕获信号 %d %s —— 这是进程内崩溃", sig, name);
    _exit(128 + sig);
}

static void on_exit(void) {
    P("[exit] 进程正常退出（atexit 触发）");
}

static void *bg_thread(void *arg) {
    (void)arg;
    for (int i = 1; i <= 200; i++) {
        usleep(100000);
        P("[BG %d] 后台心跳 %.1f 秒", i, i * 0.1);
    }
    return NULL;
}

__attribute__((constructor))
static void sig_entry(void) {
    @autoreleasepool {
        P("===== 信号探针开始 =====");
        P("[SIG0] dylib 已加载");

        signal(SIGSEGV, on_signal);
        signal(SIGBUS, on_signal);
        signal(SIGABRT, on_signal);
        signal(SIGILL, on_signal);
        signal(SIGTRAP, on_signal);
        signal(SIGFPE, on_signal);
        atexit(on_exit);
        P("[SIG0] 信号处理器 + atexit 已注册");

        pthread_t th;
        if (pthread_create(&th, NULL, bg_thread, NULL) == 0) {
            pthread_detach(th);
            P("[SIG0] 后台心跳线程已启动");
        } else {
            P("[SIG0] 线程创建失败");
        }

        [[NSNotificationCenter defaultCenter]
            addObserverForName:@"UIApplicationDidFinishLaunchingNotification"
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) {
            P("[SIG0] 收到 didFinishLaunching");
        }];
        P("[SIG0] 构造函数结束");
    }
}
