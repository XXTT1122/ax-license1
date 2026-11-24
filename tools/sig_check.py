# -*- coding: utf-8 -*-
"""检查 dylib 里 LC_CODE_SIGNATURE 的真实字段，以及文件大小关系。"""
import struct
import sys
import zipfile

src = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\方言\Downloads\AX新加卡密\out\A3-frameworks.ipa"
if src.endswith(".ipa"):
    z = zipfile.ZipFile(src)
    name = [n for n in z.namelist() if n.endswith("gate.dylib")][0]
    d = z.read(name)
    print(f"来源: {src} :: {name}")
else:
    d = open(src, "rb").read()
    print(f"来源: {src}")

print(f"文件大小 = {len(d)} 字节")
ncmds = struct.unpack("<I", d[16:20])[0]
sizeofcmds = struct.unpack("<I", d[20:24])[0]
off = 32
for i in range(ncmds):
    cmd, size = struct.unpack("<II", d[off:off + 8])
    if cmd == 0x1D:
        dataoff, datasize = struct.unpack("<II", d[off + 8:off + 16])
        print(f"\nLC_CODE_SIGNATURE @0x{off:x}")
        print(f"  dataoff  = {dataoff} (0x{dataoff:x})")
        print(f"  datasize = {datasize} (0x{datasize:x})")
        print(f"  文件大小 = {len(d)}")
        if datasize == 0:
            print("  -> datasize=0，空签名槽")
        print(f"  越界? dataoff+datasize = {dataoff + datasize} > {len(d)} ? "
              f"{'是 ❌' if dataoff + datasize > len(d) else '否'}")
    if cmd == 0x19:
        seg = d[off + 8:off + 24].split(b"\x00")[0].decode()
        fo = struct.unpack("<Q", d[off + 32:off + 40])[0]
        fs = struct.unpack("<Q", d[off + 40:off + 48])[0]
        if seg == "__LINKEDIT":
            print(f"\n__LINKEDIT fileoff=0x{fo:x} filesize=0x{fs:x} (结束=0x{fo+fs:x})")
    off += size

# 尾部 32 字节看看是不是残留签名魔数
tail = d[-32:]
print(f"\n末尾 32 字节: {tail.hex()}")
print(f"含 CodeDirectory 魔数(0xfade0c02)? {b'\x02\x0c\xde\xfa' in d[-4096:]}")
