# -*- coding: utf-8 -*-
"""把 macOS dylib 改成 iOS dylib：LC_BUILD_VERSION.platform 1->2，minos 提到 15.0。

同时打印所有 load command 便于核对。
"""
import struct
import sys

PLATFORM = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "macCatalyst",
            7: "iOSSimulator", 8: "tvOSSimulator", 9: "watchOSSimulator", 10: "driverKit",
            11: "visionOS", 12: "visionOSSimulator"}
LC_NAMES = {0x0C: "LC_LOAD_DYLIB", 0x0D: "LC_ID_DYLIB", 0x02: "LC_SYMTAB", 0x0B: "LC_DYSYMTAB",
            0x19: "LC_SEGMENT_64", 0x1D: "LC_CODE_SIGNATURE", 0x32: "LC_BUILD_VERSION",
            0x80000022: "LC_DYLD_INFO_ONLY", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
            0x80000033: "LC_DYLD_EXPORTS_TRIE", 0x1B: "LC_UUID", 0x80000028: "LC_MAIN",
            0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION"}


def ver(v):
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def main(path, out):
    d = bytearray(open(path, "rb").read())
    magic = struct.unpack("<I", d[:4])[0]
    assert magic == 0xFEEDFACF, hex(magic)
    ncmds = struct.unpack("<I", d[16:20])[0]
    off = 32
    print(f"{path}: ncmds={ncmds} size={len(d)}")
    patched = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", d[off:off + 8])
        name = LC_NAMES.get(cmd, f"LC_0x{cmd:x}")
        extra = ""
        if cmd == 0x32:
            platform, minos, sdk, ntools = struct.unpack("<IIII", d[off + 8:off + 24])
            extra = f"platform={PLATFORM.get(platform, platform)} minos={ver(minos)} sdk={ver(sdk)}"
            if platform != 2:
                struct.pack_into("<I", d, off + 8, 2)          # iOS
                struct.pack_into("<I", d, off + 12, 0x000F0000)  # minos 15.0
                struct.pack_into("<I", d, off + 16, 0x000F0000)  # sdk 15.0
                patched += 1
                extra += "  -> 已改为 iOS/15.0"
        elif cmd in (0x0C, 0x0D):
            stroff = struct.unpack("<I", d[off + 8:off + 12])[0]
            s = d[off + stroff:off + cmdsize].split(b"\x00")[0].decode()
            extra = s
        elif cmd == 0x19:
            seg = d[off + 8:off + 24].split(b"\x00")[0].decode()
            vmaddr, vmsize, fo, fs = struct.unpack("<QQQQ", d[off + 24:off + 56])
            extra = f"{seg} vm=0x{vmaddr:x} size=0x{vmsize:x} off=0x{fo:x}"
        elif cmd == 0x1B:
            extra = d[off + 8:off + 24].hex()
        print(f"  {name:<24} {extra}")
        off += cmdsize
    open(out, "wb").write(bytes(d))
    print(f"patched={patched} -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
