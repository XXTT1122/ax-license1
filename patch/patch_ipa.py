# -*- coding: utf-8 -*-
"""常量级补丁：换公钥、换域名/服务器、关掉原包假服务器拦截器。

用途（路线 B）：不编译任何代码，把 App 的卡密校验"改用你自己的服务器 + 你自己的公钥"，
从而让 App 原有的卡密输入框变成真正由你控制的卡密校验。

用法：
    python patch_ipa.py --ipa in.ipa --out out.ipa \
        --pubkey-from ../server/keys/public_b64.txt \
        --host your.domain.com --ip 1.2.3.4 \
        --kill-interceptor

每一步都会先校验目标字节，匹配不上就跳过并告警，绝不盲改。
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machop import MachOFile  # noqa: E402

# 本构建（AX_Pro_Max 1.6.1，build 0ec0b5c2…）已验证的定位点
INTERCEPTOR_OFF = 0x1096A78               # +[AXZQURLProtocol canInitWithRequest:]
INTERCEPTOR_PROLOGUE = bytes.fromhex("208e38d4")   # 原函数前 4 字节
KILL_CODE = bytes.fromhex("00008052" "c0035fd6")   # mov w0,#0 ; ret

HOST_ANCHOR = b"api.axpro.local"
PUBKEY_ANCHOR = b"MIIBCgKCAQEA"
IPS = [b"156.238.241.71", b"38.34.15.91"]
SCHEME_ANCHOR = b"https"   # 独立短串，用于把固定 https 改成 http 做本地测试


def find_exe(root):
    payload = os.path.join(root, "Payload")
    apps = [d for d in os.listdir(payload) if d.endswith(".app")]
    if len(apps) != 1:
        raise SystemExit(f"Payload 下 .app 数量异常: {apps}")
    app = apps[0]
    import plistlib
    with open(os.path.join(payload, app, "Info.plist"), "rb") as f:
        pl = plistlib.load(f)
    return app, os.path.join(payload, app, pl["CFBundleExecutable"])


def cstr_span(data: bytes, start: int) -> int:
    end = data.find(b"\x00", start)
    if end < 0:
        raise SystemExit("字符串未终止")
    return end - start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pubkey-from", help="含 Base64(DER) 公钥的文本文件")
    ap.add_argument("--host", help="替换 api.axpro.local 的域名")
    ap.add_argument("--ip", help="替换内置 IP 的服务器地址")
    ap.add_argument("--kill-interceptor", action="store_true",
                    help="把 +[AXZQURLProtocol canInitWithRequest:] 改成 return NO")
    ap.add_argument("--scheme", choices=["http", "https"],
                    help="改写硬编码的 https 前缀（本地 http 测试用）")
    ap.add_argument("--ats", action="store_true",
                    help="改写 Info.plist 放开 ATS（配合 --scheme http）")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="axppatch_")
    with zipfile.ZipFile(a.ipa) as zf:
        zf.extractall(work)
    app, exe = find_exe(work)
    raw = open(exe, "rb").read()
    m = MachOFile(raw)
    d = m.data
    report = []

    # ---------- 1. 公钥 ----------
    if a.pubkey_from:
        new_b64 = open(a.pubkey_from, encoding="utf-8").read().strip()
        i = d.find(PUBKEY_ANCHOR)
        if i < 0:
            report.append("X 未找到内置公钥，跳过")
        else:
            n = cstr_span(d, i)
            old = bytes(d[i:i + n])
            new = new_b64.encode()
            if len(old) != len(new):
                report.append(
                    f"X 公钥长度不一致 old={len(old)} new={len(new)}"
                    f"（必须都是 2048-bit RSAPublicKey DER）")
            else:
                d[i:i + n] = new
                report.append(f"OK 公钥已替换 @ file 0x{i:x}（{n} 字节等长替换）")

    # ---------- 2. 域名 / IP ----------
    if a.host:
        i = d.find(HOST_ANCHOR)
        if i < 0:
            report.append("X 未找到 api.axpro.local")
        else:
            n = cstr_span(d, i)
            if len(a.host) > n:
                report.append(f"X 域名过长：{a.host} 最多 {n} 字节（原串 {n}）")
            else:
                d[i:i + len(a.host)] = a.host.encode()
                for k in range(len(a.host), n):
                    d[i + k] = 0
                report.append(f"OK 域名 -> {a.host} @ 0x{i:x}（原 {n} 字节，尾部补 NUL）")

    if a.ip:
        for ip in IPS:
            j = d.find(ip)
            if j < 0:
                continue
            if len(a.ip) > len(ip):
                report.append(f"X IP 过长：{a.ip} 最多 {len(ip)} 字节")
                continue
            d[j:j + len(a.ip)] = a.ip.encode()
            for k in range(len(a.ip), len(ip)):
                d[j + k] = 0
            report.append(f"OK {ip.decode()} -> {a.ip} @ 0x{j:x}")

    # ---------- 3. 改写 https 前缀（本地测试用 http） ----------
    if a.scheme and a.scheme != "https":
        # 只改"独立"的 https 短串（后面紧跟 NUL），避免误伤 https 出现在长串里的情况
        hits = []
        start = 0
        while True:
            j = d.find(SCHEME_ANCHOR, start)
            if j < 0:
                break
            if d[j + 5:j + 6] == b"\x00":
                hits.append(j)
            start = j + 1
        if not hits:
            report.append("X 未找到独立的 https 字面量")
        else:
            for j in hits:
                d[j:j + 5] = b"http\x00"
            report.append(f"OK https -> http @ {', '.join(hex(h) for h in hits)}（需配合 --ats）")

    # ---------- 4. 关掉假服务器拦截 ----------
    if a.kill_interceptor:
        if bytes(d[INTERCEPTOR_OFF:INTERCEPTOR_OFF + 4]) == INTERCEPTOR_PROLOGUE:
            d[INTERCEPTOR_OFF:INTERCEPTOR_OFF + len(KILL_CODE)] = KILL_CODE
            report.append(
                f"OK AXZQURLProtocol.canInitWithRequest => return NO @ 0x{INTERCEPTOR_OFF:x}")
        else:
            cur = bytes(d[INTERCEPTOR_OFF:INTERCEPTOR_OFF + 4]).hex()
            found = d.find(INTERCEPTOR_PROLOGUE)
            report.append(
                f"X 拦截器补丁点不匹配（当前 {cur}，期望 {INTERCEPTOR_PROLOGUE.hex()}）；"
                f"特征字节出现在：{hex(found) if found >= 0 else '未找到'}")

    print("\n".join(report))

    # ---------- 5. 放开 ATS ----------
    if a.ats:
        import plistlib
        pp = os.path.join(os.path.dirname(exe), "Info.plist")
        with open(pp, "rb") as f:
            pl = plistlib.load(f)
        ats = dict(pl.get("NSAppTransportSecurity") or {})
        ats["NSAllowsArbitraryLoads"] = True
        pl["NSAppTransportSecurity"] = ats
        with open(pp, "wb") as f:
            plistlib.dump(pl, f, sort_keys=False)
        print("OK Info.plist 已放开 ATS（NSAllowsArbitraryLoads=true）")

    if a.dry_run:
        print("\n[dry-run] 未写出文件")
        shutil.rmtree(work, ignore_errors=True)
        return
    if not any(r.startswith("OK") for r in report):
        print("\n没有任何补丁生效，已中止")
        shutil.rmtree(work, ignore_errors=True)
        raise SystemExit(1)

    open(exe, "wb").write(bytes(d))

    # 清空 LC_CODE_SIGNATURE，避免旧签名干扰重签工具
    m2 = MachOFile(open(exe, "rb").read())
    dd = m2.data
    o = m2.header_size
    for _ in range(m2.ncmds):
        cmd, cmdsize = struct.unpack("<II", dd[o:o + 8])
        if cmd == 0x1D:
            struct.pack_into("<I", dd, o + 8, 0)
            struct.pack_into("<I", dd, o + 12, 0)
            print(f"OK 已清空 LC_CODE_SIGNATURE @ 0x{o:x}（需重签）")
            break
        o += cmdsize
    open(exe, "wb").write(bytes(dd))

    if os.path.exists(a.out):
        os.remove(a.out)
    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(work):
            for fn in files:
                full = os.path.join(root, fn)
                zf.write(full, os.path.relpath(full, work).replace(os.sep, "/"))
    print(f"\n输出: {a.out} ({os.path.getsize(a.out)} 字节)")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
