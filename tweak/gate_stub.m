// gate_stub.m —— 空壳 dylib：只有一个什么都不做的构造函数
// 用途：判断"启动崩溃"是 dylib 加载问题，还是门代码本身的问题。
//   装了带空壳 dylib 的包能正常启动 -> 加载没问题，崩溃在我写的门代码里
//   装了还是崩              -> dyld/签名/架构层面拒载

__attribute__((constructor))
static void gate_stub_entry(void) {
    // 故意保留一点副作用，防止被优化掉
    volatile int marker = 0x41585031; // "AXP1"
    (void)marker;
}
