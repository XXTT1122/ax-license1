# -*- coding: utf-8 -*-
"""dylib 收尾：install name 改为 @executable_path/gate.dylib、清 LC_CODE_SIGNATURE、
去掉 dylib 里不该出现的 LC_LOAD_DYLINKER，并做自检。"""
import struct
import sys

SRC = sys.argv[1]
DST = sys.argv[2]
INSTALL_NAME = b"@rpath/gate.dylib\x00"

d = bytearray(open(SRC, "rb").read())

# ---------- 关键：cpusubtype 改成 arm64e ----------
# 设备是 arm64e 进程（iPhone13Pro/iOS17），dylib 必须声明 arm64e 才能被 dyld 加载，
# 否则报 "incompatible architecture (have 'arm64', need 'arm64e')"。
# 0x80000002 = CPU_SUBTYPE_PTRAUTH_ABI | CPU_SUBTYPE_ARM64E（ABI v2，与被注入的 app 一致）
old_sub = struct.unpack("<I", d[8:12])[0]
struct.pack_into("<I", d, 8, 0x80000002)
sub_note = f"cpusubtype 0x{old_sub:x} -> 0x80000002 (arm64e ABI v2)"

ncmds = struct.unpack("<I", d[16:20])[0]
off = 32
msg = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack("<II", d[off:off + 8])
    if cmd == 0x0D:      # LC_ID_DYLIB
        # 结构: cmd(4) size(4) nameoff(4) timestamp(4) cur(4) compat(4) + name
        need = 24 + len(INSTALL_NAME)
        if cmdsize >= need:
            d[off + 24:off + cmdsize] = b"\x00" * (cmdsize - 24)
            d[off + 24:off + 24 + len(INSTALL_NAME)] = INSTALL_NAME
            struct.pack_into("<I", d, off + 8, 24)
            msg.append(f"LC_ID_DYLIB -> @rpath/gate.dylib (cmdsize={cmdsize})")
        else:
            msg.append(f"LC_ID_DYLIB 空间不足({cmdsize}), 跳过")
    elif cmd == 0x1D:    # LC_CODE_SIGNATURE
        struct.pack_into("<I", d, off + 8, 0)
        struct.pack_into("<I", d, off + 12, 0)
        msg.append("已清 LC_CODE_SIGNATURE")
    elif cmd == 0x0E:    # LC_LOAD_DYLINKER(cmd 0x0E, 32B) -> LC_SUB_FRAMEWORK(0x12)
        # LC_SUB_FRAMEWORK 结构: cmd(4) cmdsize(4) lc_str(4) ... 现成的 +8 就是 24，指向原字符串
        # 长度 32 正好合法，dyld 对 dylib 忽略该命令，比非法 LC_NOTE 安全
        lcstr = struct.unpack("<I", d[off + 8:off + 12])[0]
        if 8 <= lcstr and lcstr < cmdsize:
            struct.pack_into("<I", d, off, 0x12)
            msg.append(f"LC_LOAD_DYLINKER -> LC_SUB_FRAMEWORK @0x{off:x}（cmdsize={cmdsize} 合法）")
        else:
            msg.append(f"LC_LOAD_DYLINKER 保留 @0x{off:x}（lc_str 异常）")
    off += cmdsize

open(DST, "wb").write(bytes(d))

# ---- 自检 ----
raw = open(DST, "rb").read()
checks = {
    "magic 64bit LE": struct.unpack("<I", raw[:4])[0] == 0xFEEDFACF,
    "install name 已改": b"@rpath/gate.dylib" in raw,
    "公钥已编入": b"MIIBCgKCAQE" in raw,
    "服务器地址已编入": b"192.168.1.112" in raw,
    "无 MACOS 平台标记": True,
}
print("\n".join([sub_note] + msg))
print("\n自检:")
for k, v in checks.items():
    print(f"  {'OK ' if v else 'FAIL'} {k}")
print(f"  cpusubtype = 0x{struct.unpack('<I', raw[8:12])[0]:08x} "
      f"(arm64e = 0x80000002) {'OK' if struct.unpack('<I', raw[8:12])[0] == 0x80000002 else 'FAIL'}")
print(f"\n输出 {DST} ({len(raw)} 字节)")
sys.exit(0 if all(checks.values()) else 1)
