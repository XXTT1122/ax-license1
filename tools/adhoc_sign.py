# -*- coding: utf-8 -*-
"""给 Mach-O 补一个合法的 ad-hoc 代码签名（CodeDirectory + SuperBlob）。

为什么需要：全能签这类工具会先"剥离旧签名再重签"，它要求 LC_CODE_SIGNATURE 的
dataoff+datasize 恰好等于文件末尾。若签名槽是 0/0，它直接报
"strip: dataoff=... 与文件大小 ... 不一致" 并中止。

产出结构：
  [原文件][SuperBlob(CodeDirectory)]
  LC_CODE_SIGNATURE.dataoff  = 原文件长度
  LC_CODE_SIGNATURE.datasize = SuperBlob 长度
  __LINKEDIT 同步扩展到覆盖签名（按页对齐）
"""
import hashlib
import struct
import sys

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_SUPERBLOB = 0xFADE0CC0
CSSLOT_CODEDIRECTORY = 0
PAGE = 4096


def find_lc(d, want):
    n = struct.unpack("<I", d[16:20])[0]
    off = 32
    for _ in range(n):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        if cmd == want:
            return off, size
        off += size
    return None, None


def build_superblob(code_limit, ident=b"gate.dylib", page=PAGE):
    """生成 CodeDirectory + SuperBlob。"""
    ident_off = 52
    hash_off = ident_off + len(ident) + 1
    n_slots = (code_limit + page - 1) // page
    cd_len = hash_off + n_slots * 32

    # version 0x20200 = 支持 scatterOffset / teamOffset 的常见版本
    cd = bytearray(cd_len)
    struct.pack_into(">IIIIIIIII", cd, 0,
                     CSMAGIC_CODEDIRECTORY, cd_len, 0x20200, 0x2,  # flags=adhoc
                     hash_off, ident_off, 0, n_slots, code_limit)
    cd[36] = 32   # hashSize
    cd[37] = 2    # hashType = SHA256
    cd[38] = 0    # platform
    cd[39] = 12   # pageSize = 4KB (log2)
    struct.pack_into(">III", cd, 40, 0, 0, 0)  # spare2, scatterOffset, teamOffset
    cd[ident_off:ident_off + len(ident)] = ident
    return cd, hash_off, n_slots


def sign(path, out=None, ident=b"gate.dylib"):
    d = bytearray(open(path, "rb").read())

    lc_off, lc_size = find_lc(d, 0x1D)
    if lc_off is None:
        raise SystemExit("没有 LC_CODE_SIGNATURE，无法补签名")
    if lc_size < 16:
        raise SystemExit(f"LC_CODE_SIGNATURE 长度异常: {lc_size}")

    # 先把签名槽指向 EOF（当作 codeLimit）
    struct.pack_into("<II", d, lc_off + 8, len(d), 0)

    code_limit = len(d)
    cd, hash_off, n_slots = build_superblob(code_limit, ident)
    for i in range(n_slots):
        chunk = bytes(d[i * PAGE:min((i + 1) * PAGE, code_limit)])
        h = hashlib.sha256(chunk).digest()
        cd[hash_off + i * 32:hash_off + i * 32 + 32] = h

    blob = bytearray()
    blob += struct.pack(">III", CSMAGIC_SUPERBLOB, 12 + 8 + len(cd), 1)
    blob += struct.pack(">II", CSSLOT_CODEDIRECTORY, 20)
    blob += cd

    # 写入 LC 指针
    struct.pack_into("<II", d, lc_off + 8, code_limit, len(blob))

    # __LINKEDIT 扩展覆盖签名（页对齐）
    seg_off, _ = find_lc(d, 0x19)  # 只是定位，下面遍历所有段找 __LINKEDIT
    n = struct.unpack("<I", d[16:20])[0]
    off = 32
    for _ in range(n):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        if cmd == 0x19:
            seg = d[off + 8:off + 24].split(b"\x00")[0].decode()
            if seg == "__LINKEDIT":
                vmaddr, vmsize, fo, fs = struct.unpack("<QQQQ", d[off + 24:off + 56])
                new_end = code_limit + len(blob)
                new_fs = new_end - fo
                new_vs = (new_fs + PAGE - 1) // PAGE * PAGE
                struct.pack_into("<Q", d, off + 32, new_vs)   # vmsize
                struct.pack_into("<Q", d, off + 40, new_fs)   # filesize
                print(f"__LINKEDIT: filesize {fs} -> {new_fs}, vmsize {vmsize} -> {new_vs}")
        off += size

    d += blob
    out = out or path
    open(out, "wb").write(bytes(d))
    print(f"ad-hoc 签名完成: codeLimit={code_limit} 槽数={n_slots} "
          f"blob={len(blob)} 总大小={len(d)}")
    return out


def verify(path):
    d = open(path, "rb").read()
    lc_off, _ = find_lc(d, 0x1D)
    dataoff, datasize = struct.unpack("<II", d[lc_off + 8:lc_off + 16])
    ok = (dataoff + datasize == len(d)) and datasize > 0
    print(f"校验: dataoff={dataoff} datasize={datasize} 文件={len(d)} "
          f"dataoff+datasize={dataoff + datasize} -> {'一致 ✅' if ok else '不一致 ❌'}")
    return ok


if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src
    sign(src, dst)
    sys.exit(0 if verify(dst) else 1)
