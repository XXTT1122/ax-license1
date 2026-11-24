# -*- coding: utf-8 -*-
"""RSA-2048 密钥管理 + 卡密签名/验签。

设计要点
--------
* 服务端私钥签名，客户端内置公钥验签（RSA-PSS-SHA256，与目标 App 一致）。
* 公钥导出为 RSAPublicKey DER 的 Base64 —— 与目标 App 内置的常量格式完全相同，
  长度固定 360 字符，可等长替换（不需要改任何代码偏移）。
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(HERE, "keys")
PRIV_PEM = os.path.join(KEY_DIR, "private.pem")
PUB_PEM = os.path.join(KEY_DIR, "public.pem")
PUB_B64 = os.path.join(KEY_DIR, "public_b64.txt")


def ensure_keys() -> rsa.RSAPrivateKey:
    """首次运行生成 2048-bit 密钥对。"""
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(PRIV_PEM):
        with open(PRIV_PEM, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIV_PEM, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    pub = key.public_key()
    with open(PUB_PEM, "wb") as f:
        f.write(pub.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    der = pub.public_bytes(encoding=serialization.Encoding.DER,
                           format=serialization.PublicFormat.PKCS1)
    b64 = base64.b64encode(der).decode()
    with open(PUB_B64, "w", encoding="utf-8") as f:
        f.write(b64)
    return key


def _pub_der_b64(pub) -> str:
    return base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1)).decode()


def canonical(payload: dict) -> bytes:
    """规范化待签名内容：键排序 + 紧凑分隔符，保证两端一致。"""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_bytes(msg: bytes) -> str:
    key = ensure_keys()
    sig = key.sign(msg,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=hashes.SHA256().digest_size),
                   hashes.SHA256())
    return base64.b64encode(sig).decode()


def sign(payload: dict) -> str:
    return sign_bytes(canonical(payload))


def verify(payload: dict, sig_b64: str, pub_b64: str | None = None) -> bool:
    return verify_bytes(canonical(payload), sig_b64, pub_b64)


def verify_bytes(msg: bytes, sig_b64: str, pub_b64: str | None = None) -> bool:
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    b64 = pub_b64 or open(PUB_B64, encoding="utf-8").read().strip()
    der = base64.b64decode(b64)
    pub = load_der_public_key(_wrap_pkcs1_to_spki(der))
    try:
        pub.verify(base64.b64decode(sig_b64), msg,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=hashes.SHA256().digest_size),
                   hashes.SHA256())
        return True
    except Exception:
        return False


def _wrap_pkcs1_to_spki(pkcs1_der: bytes) -> bytes:
    """把 RSAPublicKey(PKCS#1) 包成 SubjectPublicKeyInfo，便于 load_der_public_key。"""
    algo = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption + NULL
    bitstr = b"\x03" + _der_len(len(pkcs1_der) + 1) + b"\x00" + pkcs1_der
    body = algo + bitstr
    return b"\x30" + _der_len(len(body)) + body


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


if __name__ == "__main__":
    k = ensure_keys()
    der_b64 = _pub_der_b64(k.public_key())
    print("私钥:", PRIV_PEM)
    print("公钥(PEM):", PUB_PEM)
    print(f"公钥(Base64 DER, {len(der_b64)} 字符):")
    print(der_b64)
    demo = {"schema": "KVRESP-V1", "card": "DEMO", "device": "x"}
    sig = sign(demo)
    print("自检验签:", verify(demo, sig))
