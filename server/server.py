# -*- coding: utf-8 -*-
"""卡密验证服务端（零第三方依赖，仅标准库 + cryptography）。

启动：
    python server.py --host 0.0.0.0 --port 8443 [--tls-cert crt.pem --tls-key key.pem]

对外接口（与目标 App 观察到的协议字段对齐）：
    GET  /health
    GET  /api/v1/client/probe?app_key=&nonce=          -> AXNET-V1
    POST /api/v1/app/verify                            -> KVRESP-V1（校验卡密 + 绑机）
    POST /api/v1/app/activate                          -> KVRESP-V1（同上，别名）
    POST /api/v1/app/heartbeat                         -> KVRESP-V1（续期检查）
    POST /api/v1/app/card/query                        -> 查询剩余有效期（不绑机）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import crypto  # noqa: E402
import store   # noqa: E402

APP_KEY = os.environ.get("AXP_APP_KEY", "")
CONN = None
SERVER_START = int(time.time())
VERBOSE = os.environ.get("AXP_VERBOSE", "") not in ("", "0")


def build_body(resp: dict, fmt: str) -> tuple[bytes, str]:
    """按客户端方言输出响应体。

    AX 模块的原生格式（字面量 `AXNET-V1\\n%@\\n%@`）：
        AXNET-V1
        <payload 原文>
        <signature>
    任何以 AXNET-V1 开头的三行文本都能被它按行解析。
    """
    if fmt == "json" or "payload_raw" not in resp or "signature" not in resp:
        return (json.dumps(resp, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                "application/json; charset=utf-8")
    body = "AXNET-V1\n%s\n%s" % (resp["payload_raw"], resp["signature"])
    return body.encode("utf-8"), "text/plain; charset=utf-8"


def build_resp(ok: bool, state: str, extra: dict, reason: str = "") -> dict:
    now = int(time.time())
    payload = {
        "schema": "KVRESP-V1",
        "ok": bool(ok),
        "activationState": state,
        "status": state,
        "reason": reason,
        "msg": reason,
        "message": reason,
        "code": 0 if ok else 1001,
        "vip": bool(ok),
        "issued_at": now,
        "server_time": now,
    }
    payload.update(extra)
    # payload_raw 是签名原文：客户端直接对该字符串验签，避免两端 JSON 序列化差异
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig = crypto.sign_bytes(raw.encode("utf-8"))
    resp = {
        "schema": "KVRESP-V1",
        "ok": bool(ok),
        "activationState": state,
        "code": 0 if ok else 1001,
        "msg": reason,
        "message": reason,
        "vip": bool(ok),
        "payload": payload,
        "payload_raw": raw,
        "signature": sig,
    }
    # 常见别名，尽量喂饱不同客户端的字段期待
    resp["data"] = dict(payload)
    resp["result"] = dict(payload)
    return resp


def handle_verify(body: dict, ip: str, ua: str) -> tuple[int, dict]:
    code = body.get("card_code") or body.get("card") or body.get("code") or \
        body.get("key") or body.get("license") or ""
    device = (body.get("device_id") or body.get("device") or body.get("udid") or "").strip().lower()
    if not device:
        # 客户端没带设备号：用 IP+UA 派生一个，保证流程能继续而不是 400
        device = "auto-" + hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:24]
    action = body.get("action") or "verify"
    if not code:
        store.audit(CONN, "", device, action, ip, ua, False, "no_card_in_body")
        return 200, build_resp(False, "locked", {"device_id": device}, "card_not_found")

    row = store.lookup(CONN, code)
    if not row:
        store.audit(CONN, code, device, action, ip, ua, False, "card_not_found")
        return 200, build_resp(False, "locked", {}, "card_not_found")
    if row["revoked"]:
        store.audit(CONN, code, device, action, ip, ua, False, "revoked")
        return 200, build_resp(False, "locked", {}, "revoked")
    if row["expires_at"] <= int(time.time()):
        store.audit(CONN, code, device, action, ip, ua, False, "expired")
        return 200, build_resp(False, "expired", {"expires_at": row["expires_at"]}, "expired")

    allowed, reason, ndev = store.bind_device(CONN, code, device, ip)
    if not allowed:
        store.audit(CONN, code, device, action, ip, ua, False, reason)
        return 200, build_resp(False, "locked", {"devices": ndev}, reason)

    left = row["expires_at"] - int(time.time())
    extra = {
        "card_masked": row["code"][:4] + "****" + row["code"][-4:],
        "plan": row["plan"],
        "expires_at": row["expires_at"],
        "days_left": max(0, left // 86400),
        "features": ["all"] if row["plan"] in ("pro", "max") else ["basic"],
        "device_id": device,
        "devices_used": ndev,
        "devices_max": row["max_devices"],
    }
    store.audit(CONN, code, device, action, ip, ua, True, reason)
    return 200, build_resp(True, "unlocked", extra)


def handle_query(body: dict) -> tuple[int, dict]:
    code = body.get("card_code") or ""
    row = store.lookup(CONN, code)
    if not row:
        return 200, build_resp(False, "locked", {}, "card_not_found")
    left = row["expires_at"] - int(time.time())
    return 200, build_resp(not row["revoked"] and left > 0,
                           "unlocked" if left > 0 and not row["revoked"] else "expired",
                           {"card_masked": row["code"][:4] + "****" + row["code"][-4:],
                            "plan": row["plan"], "expires_at": row["expires_at"],
                            "days_left": max(0, left // 86400)},
                           "revoked" if row["revoked"] else ("expired" if left <= 0 else ""))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AXP/1.0"

    def setup(self):
        super().setup()
        if VERBOSE:
            sys.stderr.write(f"[conn] {self.client_address[0]}:{self.client_address[1]}\n")
            sys.stderr.flush()

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
        sys.stderr.flush()

    def _raw_peek(self, n=2048) -> bytes:
        """把原始请求体读出来并打印，用于未知客户端的协议逆向。"""
        try:
            body = self.rfile.read(n)
        except Exception:
            return b""
        if VERBOSE and body:
            sys.stderr.write(f"[body] {body[:512]!r}\n")
            sys.stderr.flush()
        return body

    # ---------- 工具 ----------
    def _fmt(self) -> str:
        """显式 ?fmt=json 或 Accept: application/json 时返回 JSON，否则用 AXNET 三行方言。"""
        if "fmt=json" in self.path:
            return "json"
        if "fmt=axnet" in self.path:
            return "axnet"
        return "axnet"

    def _send(self, code: int, obj: dict):
        raw, ctype = build_body(obj, self._fmt())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 1 << 20:
            return {}
        raw = self.rfile.read(n)
        # 与目标 App 一致的完整性头
        sha = hashlib.sha256(raw).hexdigest()
        hdr = (self.headers.get("X-Body-SHA256") or "").lower()
        if hdr and hdr != sha:
            raise ValueError("body sha mismatch")
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _check_app_key(self) -> bool:
        if not APP_KEY:
            return True
        return (self.headers.get("X-App-Key") or "") == APP_KEY

    def _ip(self) -> str:
        return (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or \
            self.client_address[0]

    # ---------- 路由 ----------
    def do_GET(self):
        path = self.path.split("?")[0]
        if VERBOSE:
            sys.stderr.write(f"[GET] {self.path}\n")
            sys.stderr.flush()
        if path == "/health":
            return self._send(200, {"ok": True, "uptime": int(time.time()) - SERVER_START,
                                    "schema": "AXNET-V1"})
        # 客户端用同步 GET（避免 block 回调），参数放 query
        if path.startswith("/api/v1/app/") or path == "/api/v1/app":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            body = {k: (v[0] if v else "") for k, v in q.items()}
            with store.LOCK:
                if path == "/api/v1/app/card/query":
                    code, obj = handle_query(body)
                else:
                    code, obj = handle_verify(body, self._ip(), self.headers.get("User-Agent", ""))
            return self._send(code, obj)
        if path == "/api/v1/client/probe":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            nonce = (q.get("nonce") or [""])[0]
            payload = {"schema": "AXNET-V1", "scope": "ax.transport.probe",
                       "ok": True, "nonce": nonce, "app_key": (q.get("app_key") or [""])[0],
                       "issued_at": int(time.time()), "ready": True}
            return self._send(200, {"schema": "AXNET-V1", "ok": True, "payload": payload,
                                    "signature": crypto.sign(payload)})
        return self._send(404, {"ok": False, "reason": "not_found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if VERBOSE:
            sys.stderr.write(f"[POST] {path}  hdrs={dict(self.headers)}\n")
            sys.stderr.flush()
        try:
            body = self._body()
        except ValueError as exc:
            return self._send(400, {"ok": False, "reason": str(exc)})
        if not self._check_app_key():
            return self._send(403, {"ok": False, "reason": "app_key"})
        with store.LOCK:
            # 兼容未知 action 名：/api/v1/app/* 一律按校验处理（card/query 除外）
            if path == "/api/v1/app/card/query":
                code, obj = handle_query(body)
                return self._send(code, obj)
            if path.startswith("/api/v1/app/") or path in ("/api/v1/app", "/"):
                code, obj = handle_verify(body, self._ip(), self.headers.get("User-Agent", ""))
                return self._send(code, obj)
        return self._send(404, {"ok": False, "reason": "not_found"})


def main():
    global CONN
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="打印每条连接、请求头与请求体（逆向未知客户端时用）")
    args = ap.parse_args()

    global VERBOSE
    if args.verbose:
        VERBOSE = True

    crypto.ensure_keys()
    CONN = store.connect()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    scheme = "https" if args.tls_cert else "http"
    print(f"卡密服务已启动: {scheme}://{args.host}:{args.port}")
    print(f"公钥指纹(Base64): {open(crypto.PUB_B64, encoding='utf-8').read()[:40]}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n停止")


if __name__ == "__main__":
    main()
