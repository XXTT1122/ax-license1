# -*- coding: utf-8 -*-
"""交付前把两个二进制都体检一遍：签名槽是否落在文件末尾、load commands 是否合法。"""
import struct
import sys
import zipfile

IPA = sys.argv[1]
z = zipfile.ZipFile(IPA)
app = [n for n in z.namelist() if n.startswith("Payload/") and n.count("/") == 2][0].split("/")[1]
exe = [n for n in z.namelist() if n.endswith("/Tips")][0] if any(
    n.endswith("/Tips") for n in z.namelist()) else None
import plistlib
pl = plistlib.loads(z.read(f"Payload/{app}/Info.plist"))
exe = f"Payload/{app}/{pl['CFBundleExecutable']}"

print(f"IPA: {IPA}")
print(f"bundle_id = {pl['CFBundleIdentifier']}")
print(f"ATS = {pl.get('NSAppTransportSecurity')}")

targets = [(exe, z.read(exe))]
for n in z.namelist():
    if n.endswith("gate.dylib"):
        targets.append((n, z.read(n)))

all_ok = True
for (name, d) in targets:
    ncmds = struct.unpack("<I", d[16:20])[0]
    sizeofcmds = struct.unpack("<I", d[20:24])[0]
    off = 32
    lcok = True
    sig = None
    load_dylib = []
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        if size == 0 or size % 8:
            lcok = False
        if cmd == 0x1D:
            sig = struct.unpack("<II", d[off + 8:off + 16])
        if cmd == 0x0C:
            so = struct.unpack("<I", d[off + 8:off + 12])[0]
            load_dylib.append(d[off + so:off + size].split(b"\x00")[0].decode())
        off += size
    print(f"\n--- {name} ---")
    print(f"  大小={len(d)} ncmds={ncmds} sizeofcmds={sizeofcmds} "
          f"命令区结束=0x{off:x} {'✅' if off == 32 + sizeofcmds else '❌'}")
    print(f"  load commands 合法: {'✅' if lcok else '❌'}")
    if sig:
        do, ds = sig
        end_ok = (do + ds == len(d)) and ds > 0
        print(f"  LC_CODE_SIGNATURE dataoff={do} datasize={ds} "
              f"→ 末尾对齐: {'✅' if end_ok else '❌（工具剥离签名时会报不一致）'}")
        all_ok = all_ok and end_ok
    else:
        print("  无 LC_CODE_SIGNATURE ❌")
        all_ok = False
    for l in load_dylib:
        if "gate" in l or "Frameworks" in l:
            print(f"  LC_LOAD_DYLIB: {l}")
    all_ok = all_ok and lcok

print(f"\n总判定: {'可以交给签名工具 ✅' if all_ok else '仍有问题 ❌'}")
sys.exit(0 if all_ok else 1)
