# -*- coding: utf-8 -*-
"""列出 dylib 每个段的 fileoff/filesize，标出超出文件长度的段。"""
import struct
import sys
import zipfile

src = sys.argv[1]
if src.endswith(".ipa"):
    z = zipfile.ZipFile(src)
    d = z.read([n for n in z.namelist() if n.endswith("gate.dylib")][0])
else:
    d = open(src, "rb").read()

n = struct.unpack("<I", d[16:20])[0]
off = 32
need = 0
print(f"文件大小 = {len(d)} (0x{len(d):x})")
for i in range(n):
    cmd, size = struct.unpack("<II", d[off:off + 8])
    if cmd == 0x19:
        seg = d[off + 8:off + 24].split(b"\x00")[0].decode()
        vmaddr, vmsize, fo, fs = struct.unpack("<QQQQ", d[off + 24:off + 56])
        end = fo + fs
        flag = ""
        if end > len(d):
            flag = f"  <<< 超出文件 {end - len(d)} 字节"
            need = max(need, end)
        elif fs == 0:
            flag = "  (无文件内容)"
        print(f"  {seg:<14} fileoff=0x{fo:<7x} filesize=0x{fs:<7x} end=0x{end:<7x}{flag}")
    off += size

print(f"\n需要补齐到: {need} (0x{need:x})" if need else "\n所有段都在文件范围内 ✅")
