# -*- coding: utf-8 -*-
"""列出 dylib 每条 load command 的 cmd/cmdsize，并检查结构合法性。"""
import struct
import sys

path = sys.argv[1]
d = open(path, "rb").read()
ncmds = struct.unpack("<I", d[16:20])[0]
sizeofcmds = struct.unpack("<I", d[20:24])[0]
print(f"{path}: ncmds={ncmds} sizeofcmds={sizeofcmds} 头部结束=0x{32+sizeofcmds:x}")

# 各命令最小长度
MIN = {0x19: 72, 0x0C: 24, 0x0D: 24, 0x02: 24, 0x0B: 80, 0x1D: 16, 0x32: 32,
       0x80000022: 48, 0x1B: 24, 0x2A: 16, 0x26: 16, 0x29: 16, 0x31: 40, 0x0E: 24}
NAME = {0x19: "LC_SEGMENT_64", 0x0C: "LC_LOAD_DYLIB", 0x0D: "LC_ID_DYLIB", 0x02: "LC_SYMTAB",
        0x0B: "LC_DYSYMTAB", 0x1D: "LC_CODE_SIGNATURE", 0x32: "LC_BUILD_VERSION",
        0x80000022: "LC_DYLD_INFO_ONLY", 0x1B: "LC_UUID", 0x2A: "LC_SOURCE_VERSION",
        0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x31: "LC_NOTE", 0x0E: "LC_LOAD_DYLINKER"}

off = 32
bad = []
for i in range(ncmds):
    cmd, size = struct.unpack("<II", d[off:off + 8])
    nm = NAME.get(cmd, f"LC_0x{cmd:x}")
    need = MIN.get(cmd)
    flag = ""
    if need and size < need:
        flag = f"  <<< 非法！该命令至少需要 {need} 字节"
        bad.append((i, nm, size, need))
    if size == 0 or size % 8 != 0:
        flag += "  <<< 长度未 8 字节对齐"
        bad.append((i, nm, size, 8))
    print(f"  [{i:2}] 0x{off:04x} {nm:<20} cmdsize={size}{flag}")
    off += size

print()
if bad:
    print("发现问题:")
    for b in bad:
        print(f"  第{b[0]}条 {b[1]}: cmdsize={b[2]}, 至少需要 {b[3]}")
else:
    print("load commands 结构合法 ✅")
print(f"命令区结束=0x{off:x}（应等于 0x{32+sizeofcmds:x}）")
