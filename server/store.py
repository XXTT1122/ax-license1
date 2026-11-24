# -*- coding: utf-8 -*-
"""卡密存储：SQLite。卡号规则 / 绑机 / 有效期 / 吊销 / 审计。"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("AXP_DB", os.path.join(HERE, "axp.sqlite3"))

# 服务端是多线程的，SQLite 连接需跨线程复用 -> 关闭线程检查 + 全局串行锁
LOCK = threading.Lock()

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32（去掉 I L O U，避免混淆）


def new_card(prefix: str = "AXPM", groups: int = 4, size: int = 4) -> str:
    """生成 AXPM-XXXX-XXXX-XXXX-XXXX 形式的卡号（16 个随机字符 = 80 bit 熵）。"""
    body = "".join(secrets.choice(ALPHABET) for _ in range(groups * size))
    return prefix + "-" + "-".join(body[i:i + size] for i in range(0, len(body), size))


def normalize(code: str) -> str:
    """输入规范化：去空格/横线，转大写，I/L→1，O→0，U→V。"""
    s = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    s = s.replace("I", "1").replace("L", "1").replace("O", "0").replace("U", "V")
    if s.startswith("AXPM"):
        s = s[4:]
    return s


def fmt_body(body: str, prefix: str = "AXPM") -> str:
    return prefix + "-" + "-".join(body[i:i + 4] for i in range(0, len(body), 4))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cards (
        code        TEXT PRIMARY KEY,   -- 规范化后的卡体（不含前缀与横线）
        full_code   TEXT NOT NULL,      -- 展示用完整卡号
        plan        TEXT NOT NULL DEFAULT 'pro',
        days        INTEGER NOT NULL DEFAULT 30,
        max_devices INTEGER NOT NULL DEFAULT 1,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        revoked     INTEGER NOT NULL DEFAULT 0,
        note        TEXT
    );
    CREATE TABLE IF NOT EXISTS activations (
        code       TEXT NOT NULL,
        device_id  TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        last_ip    TEXT,
        PRIMARY KEY (code, device_id)
    );
    CREATE TABLE IF NOT EXISTS audit (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        INTEGER NOT NULL,
        code      TEXT,
        device_id TEXT,
        action    TEXT,
        ip        TEXT,
        ua        TEXT,
        ok        INTEGER,
        reason    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
    """)
    return conn


def issue(conn, days: int = 30, plan: str = "pro", max_devices: int = 1,
          note: str = "", count: int = 1) -> list[str]:
    now = int(time.time())
    out = []
    for _ in range(count):
        while True:
            body = normalize(new_card())
            if len(body) != 16:
                continue
            full = fmt_body(body)
            try:
                conn.execute(
                    "INSERT INTO cards(code,full_code,plan,days,max_devices,created_at,expires_at,note)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (body, full, plan, days, max_devices, now, now + days * 86400, note))
                out.append(full)
                break
            except sqlite3.IntegrityError:
                continue
    return out


def lookup(conn, code: str):
    row = conn.execute("SELECT code,plan,days,max_devices,created_at,expires_at,revoked "
                       "FROM cards WHERE code=?", (normalize(code),)).fetchone()
    if not row:
        return None
    keys = ("code", "plan", "days", "max_devices", "created_at", "expires_at", "revoked")
    return dict(zip(keys, row))


def bind_device(conn, code: str, device_id: str, ip: str) -> tuple[bool, str, int]:
    """返回 (是否允许, 原因, 设备数)。"""
    body = normalize(code)
    row = conn.execute("SELECT max_devices FROM cards WHERE code=?", (body,)).fetchone()
    if not row:
        return False, "card_not_found", 0
    max_dev = row[0]
    now = int(time.time())
    cur = conn.execute("SELECT COUNT(*) FROM activations WHERE code=?", (body,)).fetchone()[0]
    exists = conn.execute("SELECT 1 FROM activations WHERE code=? AND device_id=?",
                          (body, device_id)).fetchone()
    if exists:
        conn.execute("UPDATE activations SET last_seen=?, last_ip=? WHERE code=? AND device_id=?",
                     (now, ip, body, device_id))
        return True, "rebind_ok", cur
    if cur >= max_dev:
        return False, "device_limit", cur
    conn.execute("INSERT INTO activations(code,device_id,first_seen,last_seen,last_ip)"
                 " VALUES(?,?,?,?,?)", (body, device_id, now, now, ip))
    return True, "bound", cur + 1


def audit(conn, code, device_id, action, ip, ua, ok, reason):
    conn.execute("INSERT INTO audit(ts,code,device_id,action,ip,ua,ok,reason)"
                 " VALUES(?,?,?,?,?,?,?,?)",
                 (int(time.time()), normalize(code or ""), device_id, action, ip, ua,
                  1 if ok else 0, reason))
