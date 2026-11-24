# -*- coding: utf-8 -*-
"""Mach-O 手术刀：读写头、追加 LC_LOAD_DYLIB、等长替换常量。

仅处理 64-bit little-endian 单一 slice（与目标 App 一致）。
"""
from __future__ import annotations

import struct

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0x0C
LC_DYLD_CHAINED_FIXUPS = 0x80000034


class MachOFile:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        magic = struct.unpack("<I", self.data[:4])[0]
        if magic != 0xFEEDFACF:
            raise ValueError(f"不是 64 位小端 Mach-O: 0x{magic:08x}")
        self.ncmds = struct.unpack("<I", self.data[16:20])[0]
        self.sizeofcmds = struct.unpack("<I", self.data[20:24])[0]
        self.header_size = 32
        self.segs = []
        self._parse()

    def _parse(self):
        off = self.header_size
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack("<II", self.data[off:off + 8])
            if cmd == LC_SEGMENT_64:
                name = bytes(self.data[off + 8:off + 24]).rstrip(b"\x00").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", self.data[off + 24:off + 56])
                self.segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize,
                                      fileoff=fileoff, filesize=filesize, cmd_off=off))
            off += cmdsize

    # ---------- 查询 ----------
    @property
    def cmds_end(self) -> int:
        return self.header_size + self.sizeofcmds

    def first_section_offset(self) -> int:
        """load commands 之后的第一个节起点（通常是 __TEXT.__text 的 0x4000）。"""
        cands = []
        off = self.header_size
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack("<II", self.data[off:off + 8])
            if cmd == LC_SEGMENT_64:
                nsects = struct.unpack("<I", self.data[off + 64:off + 68])[0]
                for i in range(nsects):
                    s = off + 72 + i * 80
                    so = struct.unpack("<I", self.data[s + 48:s + 52])[0]
                    if so > 0:
                        cands.append(so)
            off += cmdsize
        if not cands:
            cands = [s["fileoff"] for s in self.segs if s["fileoff"] > 0]
        return min(cands) if cands else self.cmds_end

    def slack(self) -> int:
        return self.first_section_offset() - self.cmds_end

    def v2o(self, va: int):
        for s in self.segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    # ---------- 修改 ----------
    def add_load_dylib(self, path: str) -> int:
        """在已有的 load commands 尾部追加一条 LC_LOAD_DYLIB，返回写入偏移。"""
        need = 24 + len(path.encode()) + 1
        cmdsize = (need + 7) & ~7
        if self.slack() < cmdsize:
            raise RuntimeError(f"头部空洞不足：需要 {cmdsize}，可用 {self.slack()}")
        off = self.cmds_end
        buf = bytearray(cmdsize)
        struct.pack_into("<II", buf, 0, LC_LOAD_DYLIB, cmdsize)
        struct.pack_into("<I", buf, 8, 24)          # name offset
        struct.pack_into("<I", buf, 12, 2)          # timestamp
        struct.pack_into("<I", buf, 16, 0x10000)    # current_version 1.0.0
        struct.pack_into("<I", buf, 20, 0x10000)    # compatibility_version
        name = path.encode()
        buf[24:24 + len(name)] = name
        self.data[off:off + cmdsize] = buf
        self.ncmds += 1
        self.sizeofcmds += cmdsize
        struct.pack_into("<I", self.data, 16, self.ncmds)
        struct.pack_into("<I", self.data, 20, self.sizeofcmds)
        return off

    def replace_equal(self, old: bytes, new: bytes) -> int:
        """等长替换（长度必须一致），返回文件偏移。"""
        if len(old) != len(new):
            raise ValueError(f"长度不一致: old={len(old)} new={len(new)}")
        i = self.data.find(old)
        if i < 0:
            raise ValueError("未找到目标字节序列")
        if self.data.find(old, i + 1) >= 0:
            raise ValueError("目标字节序列不唯一，请用 --offset 指定")
        self.data[i:i + len(new)] = new
        return i

    def write_fixed_width(self, offset: int, text: str, width: int):
        """写入固定宽度字符串（NUL 结尾 + 零填充），长度不得超过 width-1。"""
        b = text.encode()
        if len(b) > width - 1:
            raise ValueError(f"字符串过长: {text!r} 最多 {width-1} 字节")
        self.data[offset:offset + width] = b + b"\x00" * (width - len(b))

    def tobytes(self) -> bytes:
        return bytes(self.data)
