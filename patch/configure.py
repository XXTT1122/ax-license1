# -*- coding: utf-8 -*-
"""把服务器地址 / 公钥 / App Key 固化进 tweak/axp_config.h。

用法：
    python patch/configure.py --server https://lic.yourdomain.com \
        --pubkey-from server/keys/public_b64.txt

    # 可选
    --bundle-ids com.apple.music,com.ax.promax
    --app-key ax_pro_max
    --disable-ax-interceptor        # 顺手关掉原包假服务器
    --print                         # 只打印将生成的配置，不写文件
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "tweak", "axp_config.h")
DEFAULT_PUB = os.path.join(ROOT, "server", "keys", "public_b64.txt")


def die(msg: str):
    print(f"[x] {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="服务端根地址，如 https://lic.example.com")
    ap.add_argument("--pubkey-from", default=DEFAULT_PUB)
    ap.add_argument("--pubkey", help="直接给 Base64 公钥（优先于 --pubkey-from）")
    ap.add_argument("--app-key", default="ax_pro_max")
    ap.add_argument("--bundle-ids", default="com.axp.promax,com.apple.music")
    ap.add_argument("--disable-ax-interceptor", action="store_true")
    ap.add_argument("--print", dest="only_print", action="store_true")
    a = ap.parse_args()

    url = a.server.rstrip("/")
    if not re.match(r"^https?://[^\s/]+$", url):
        die(f"服务端地址不合法: {url}（不要带路径和结尾斜杠）")
    if url.startswith("http://") and "127.0.0.1" not in url and "192.168." not in url:
        print("[!] 警告：使用 HTTP 明文，App 的 ATS 可能拦截；生产请用 HTTPS")

    pub = (a.pubkey or (open(a.pubkey_from, encoding="utf-8").read().strip()
                        if os.path.exists(a.pubkey_from) else ""))
    if not pub:
        die(f"找不到公钥，请先跑 server/crypto.py 生成（期望文件：{a.pubkey_from}）")
    pub = "".join(pub.split())
    try:
        der = base64.b64decode(pub, validate=True)
    except Exception:
        die("公钥不是合法 Base64")
    if len(der) != 270:
        die(f"公钥 DER 长度 {len(der)}，期望 270（2048-bit RSAPublicKey）。"
            f"若你用 4096-bit 请改成 2048-bit，否则无法与注入侧约定一致")
    if len(pub) != 360:
        die(f"公钥 Base64 长度 {len(pub)}，期望 360")

    bids = [x.strip() for x in (a.bundle_ids or "").split(",") if x.strip()]
    # 永远把改名后的 Bundle ID 加进白名单，避免漏配导致闸门拒绝自己
    for must in ("com.axp.promax",):
        if must not in bids:
            bids.insert(0, must)
    if not bids:
        die("bundle id 列表为空")
    bid_literal = "@[ " + ", ".join(f'@"{b}"' for b in bids) + " ]"
    bid_csv = ",".join(bids)

    text = f"""// axp_config.h —— 由 patch/configure.py 自动生成，请勿手改
// 生成时间: {__import__("time").strftime("%Y-%m-%d %H:%M:%S")}
// 服务端  : {url}
// 公钥长度: {len(pub)} 字符（DER {len(der)} 字节）

#ifndef AXP_CONFIG_H
#define AXP_CONFIG_H

#define AXP_SERVER_URL      @"{url}"
#define AXP_PUBLIC_KEY_B64  @"{pub}"
#define AXP_APP_KEY         @"{a.app_key}"
#define AXP_BUNDLE_IDS      {bid_literal}
#define AXP_BUNDLE_IDS_C    "{bid_csv}"
#define AXP_DISABLE_AX_INTERCEPTOR {1 if a.disable_ax_interceptor else 0}

#endif
"""
    if a.only_print:
        print(text)
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"[ok] 已生成 {OUT}")
    print(f"     服务端  : {url}")
    print(f"     公钥    : {pub[:24]}…{pub[-8:]}（{len(pub)} 字符）")
    print(f"     Bundle  : {', '.join(bids)}")
    print(f"     关假服务器: {'是' if a.disable_ax_interceptor else '否'}")
    print("\n下一步：编译 dylib（CI 或本机 Theos）后注入 IPA。")


if __name__ == "__main__":
    main()
