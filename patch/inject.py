# -*- coding: utf-8 -*-
"""把 gate.dylib 注入 IPA：追加 LC_LOAD_DYLIB + 放入 app 目录 + 重新打包。

用法：
    python inject.py --ipa in.ipa --dylib gate.dylib --out out.ipa [--name gate.dylib]

注意：注入后原代码签名失效，必须重新签名（CI 里用 ldid -S，或 TrollStore 安装时由其处理）。
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


def find_app(entries):
    apps = []
    for n in entries:
        parts = n.split("/")
        if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app"):
            if parts[1] not in apps:
                apps.append(parts[1])
    return apps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--dylib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", default="gate.dylib", help="注入后的 dylib 文件名")
    ap.add_argument("--keep-signature", action="store_true", help="保留原 LC_CODE_SIGNATURE")
    ap.add_argument("--ats-allow-http", action="store_true",
                    help="改写 Info.plist 放开 ATS（允许 http:// 测试，无需域名/证书）")
    ap.add_argument("--bundle-id", help="改写 CFBundleIdentifier（证书签名时必需，比如 com.axp.promax）")
    ap.add_argument("--frameworks", action="store_true",
                    help="把 dylib 放进 .app/Frameworks/（签名工具通常只重签这里）")
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="axpinj_")
    with zipfile.ZipFile(a.ipa) as zf:
        names = zf.namelist()
        zf.extractall(work)

    apps = find_app(names)
    if len(apps) != 1:
        raise SystemExit(f"Payload 下的 .app 数量异常: {apps}")
    app_name = apps[0]
    app_dir = os.path.join(work, "Payload", app_name)

    # 主可执行文件
    import plistlib
    plist_path = os.path.join(app_dir, "Info.plist")
    with open(plist_path, "rb") as f:
        pl = plistlib.load(f)

    # 可选：放开 ATS，允许 http（没有域名/证书时用来先跑通）
    plist_dirty = False
    if a.ats_allow_http:
        ats = pl.get("NSAppTransportSecurity") or {}
        ats = dict(ats)
        ats["NSAllowsArbitraryLoads"] = True
        pl["NSAppTransportSecurity"] = ats
        plist_dirty = True
        print("已放开 ATS（NSAllowsArbitraryLoads=true）——仅建议测试期使用")

    if a.bundle_id:
        old_bid = pl.get("CFBundleIdentifier")
        pl["CFBundleIdentifier"] = a.bundle_id
        plist_dirty = True
        print(f"Bundle ID: {old_bid} -> {a.bundle_id}（原 ID 是苹果自己的，证书签不了）")

    if plist_dirty:
        with open(plist_path, "wb") as f:
            plistlib.dump(pl, f, sort_keys=False)

    exe = pl["CFBundleExecutable"]
    exe_path = os.path.join(app_dir, exe)
    print(f"app={app_name} exe={exe}")
    print(f"bundle_id={pl.get('CFBundleIdentifier')} version={pl.get('CFBundleShortVersionString')}")

    raw = open(exe_path, "rb").read()
    m = MachOFile(raw)
    print(f"原 ncmds={m.ncmds} sizeofcmds={m.sizeofcmds} 头部空洞={m.slack()} 字节")

    # 目标路径：--frameworks 时放 .app/Frameworks/（签名工具的标准扫描位置）
    if a.frameworks:
        install_name = f"@executable_path/Frameworks/{a.name}"
    else:
        install_name = f"@executable_path/{a.name}"
    off = m.add_load_dylib(install_name)
    print(f"已追加 LC_LOAD_DYLIB '{install_name}' @ file 0x{off:x}")

    if not a.keep_signature:
        # 把 LC_CODE_SIGNATURE 的 dataoff/datasize 归零，避免残留签名干扰重签
        i = 0
        d = m.data
        o = m.header_size
        for _ in range(m.ncmds):
            cmd, cmdsize = struct.unpack("<II", d[o:o + 8])
            if cmd == 0x1D:   # LC_CODE_SIGNATURE: cmd(0) cmdsize(4) dataoff(8) datasize(12)
                struct.pack_into("<I", d, o + 8, 0)    # dataoff
                struct.pack_into("<I", d, o + 12, 0)   # datasize
                print(f"已清空 LC_CODE_SIGNATURE @ 0x{o:x}（需重新签名）")
                break
            o += cmdsize

    open(exe_path, "wb").write(m.tobytes())

    # 复制 dylib
    if a.frameworks:
        fw_dir = os.path.join(app_dir, "Frameworks")
        os.makedirs(fw_dir, exist_ok=True)
        dst = os.path.join(fw_dir, a.name)
        rel = f"Payload/{app_name}/Frameworks/{a.name}"
    else:
        dst = os.path.join(app_dir, a.name)
        rel = f"Payload/{app_name}/{a.name}"
    shutil.copyfile(a.dylib, dst)
    print(f"dylib -> {rel} ({os.path.getsize(dst)} 字节)")

    # 校验：重新解析输出二进制
    m2 = MachOFile(open(exe_path, "rb").read())
    ok = any(x for x in [True]) and m2.ncmds == m.ncmds
    print(f"校验：新 ncmds={m2.ncmds} sizeofcmds={m2.sizeofcmds} -> {'OK' if ok else '失败'}")
    if not ok:
        raise SystemExit("注入校验失败")

    # 重新打包
    if os.path.exists(a.out):
        os.remove(a.out)
    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(work):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, work).replace(os.sep, "/")
                zf.write(full, rel)
    print(f"输出: {a.out} ({os.path.getsize(a.out)} 字节)")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
