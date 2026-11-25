// gate_empty.m —— 完全空壳 dylib：没有构造函数、没有 ObjC 类、不留任何痕迹
// 目的：验证"只要 App 里多一个镜像就会自杀"这个判断
//   装上后 App 能正常用  -> 是构造函数里的行为触发的
//   装上后仍然闪退      -> 任何注入镜像都会被检测，dylib 方案彻底不可行

int axp_probe_marker(void) {
    return 20261125;
}
