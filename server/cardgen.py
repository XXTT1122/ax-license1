# -*- coding: utf-8 -*-
"""卡密生成 / 查询 / 吊销 / 导出（CLI）。

用法：
    python cardgen.py issue  -n 20 -d 30 -m 1 -p pro -o cards.csv
    python cardgen.py list
    python cardgen.py info  AXPM-XXXX-XXXX-XXXX-XXXX
    python cardgen.py revoke AXPM-XXXX-XXXX-XXXX-XXXX
    python cardgen.py unbind AXPM-XXXX-XXXX-XXXX-XXXX --device <id|all>
    python cardgen.py export -o cards.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import store  # noqa: E402


def ts(v):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(v))


def cmd_issue(a):
    conn = store.connect()
    codes = store.issue(conn, days=a.days, plan=a.plan, max_devices=a.devices,
                        note=a.note, count=a.n)
    for c in codes:
        print(c)
    if a.out:
        new = not os.path.exists(a.out)
        with open(a.out, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["card", "plan", "days", "max_devices", "note", "issued_at"])
            for c in codes:
                w.writerow([c, a.plan, a.days, a.devices, a.note,
                            time.strftime("%Y-%m-%d %H:%M")])
        print(f"\n已追加 {len(codes)} 条到 {a.out}")
    print(f"\n合计生成 {len(codes)} 个卡密（有效期 {a.days} 天，最多 {a.devices} 台设备）")


def cmd_list(a):
    conn = store.connect()
    rows = conn.execute(
        "SELECT full_code,plan,expires_at,revoked,"
        "(SELECT COUNT(*) FROM activations x WHERE x.code=cards.code) "
        "FROM cards ORDER BY created_at DESC LIMIT ?", (a.limit,)).fetchall()
    print(f"{'卡密':<26}{'套餐':<8}{'到期':<18}{'设备':<6}{'状态'}")
    for (code, plan, exp, rev, nd) in rows:
        state = "已吊销" if rev else ("已过期" if exp < time.time() else "有效")
        print(f"{code:<26}{plan:<8}{ts(exp):<18}{nd:<6}{state}")


def cmd_info(a):
    conn = store.connect()
    row = store.lookup(conn, a.card)
    if not row:
        print("卡密不存在")
        return
    print(f"卡密    : {store.fmt_body(row['code'])}")
    print(f"套餐    : {row['plan']}  有效期 {row['days']} 天  设备上限 {row['max_devices']}")
    print(f"创建    : {ts(row['created_at'])}")
    print(f"到期    : {ts(row['expires_at'])}  (剩余 {max(0, (row['expires_at'] - int(time.time())) // 86400)} 天)")
    print(f"状态    : {'已吊销' if row['revoked'] else '有效'}")
    print("绑定设备：")
    for r in conn.execute("SELECT device_id,first_seen,last_seen,last_ip FROM activations "
                          "WHERE code=? ORDER BY last_seen DESC", (row["code"],)):
        print(f"  {r[0][:24]:<26} 首次 {ts(r[1])}  最近 {ts(r[2])}  {r[3] or ''}")


def cmd_revoke(a):
    conn = store.connect()
    conn.execute("UPDATE cards SET revoked=? WHERE code=?", (0 if a.undo else 1, store.normalize(a.card)))
    print(("已恢复" if a.undo else "已吊销"), a.card)


def cmd_unbind(a):
    conn = store.connect()
    body = store.normalize(a.card)
    if a.device == "all":
        conn.execute("DELETE FROM activations WHERE code=?", (body,))
        print("已清空该卡所有绑定设备")
    else:
        conn.execute("DELETE FROM activations WHERE code=? AND device_id=?", (body, a.device))
        print("已解绑", a.device)


def cmd_export(a):
    conn = store.connect()
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["card", "plan", "days", "max_devices", "created_at", "expires_at",
                    "revoked", "devices"])
        for r in conn.execute(
                "SELECT full_code,plan,days,max_devices,created_at,expires_at,revoked,"
                "(SELECT COUNT(*) FROM activations x WHERE x.code=cards.code) FROM cards"):
            w.writerow([r[0], r[1], r[2], r[3], ts(r[4]), ts(r[5]), r[6], r[7]])
    print("已导出到", a.out)


def main():
    ap = argparse.ArgumentParser(description="AX 卡密管理")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("issue", help="批量生成")
    p.add_argument("-n", type=int, default=10)
    p.add_argument("-d", "--days", type=int, default=30)
    p.add_argument("-m", "--devices", type=int, default=1)
    p.add_argument("-p", "--plan", default="pro", choices=["basic", "pro", "max"])
    p.add_argument("--note", default="")
    p.add_argument("-o", "--out", help="追加写入 CSV")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("list", help="列出卡密")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("info", help="查看单个")
    p.add_argument("card")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("revoke", help="吊销")
    p.add_argument("card")
    p.add_argument("--undo", action="store_true")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("unbind", help="解绑设备")
    p.add_argument("card")
    p.add_argument("--device", default="all")
    p.set_defaults(func=cmd_unbind)

    p = sub.add_parser("export", help="导出 CSV")
    p.add_argument("-o", "--out", default="cards_export.csv")
    p.set_defaults(func=cmd_export)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
