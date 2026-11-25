# -*- coding: utf-8 -*-
"""生成自签 CA + 服务器证书（SAN 含 IP），供 iOS 安装信任后使用 HTTPS 连接。

产物（默认 server/tls/）:
  ca.key / ca.crt          根证书
  server.key / server.crt  服务器证书（SAN: IP:<地址>）
  另导出 ca.der 供 iOS 安装
"""
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOST_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.112"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls")
os.makedirs(OUT, exist_ok=True)

now = datetime.datetime.now(datetime.timezone.utc)

# ---- CA ----
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "AXP Local CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AXP"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

# ---- server cert ----
srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST_IP)])
san = x509.SubjectAlternativeName([
    x509.IPAddress(ipaddress.ip_address(HOST_IP)),
    x509.DNSName(HOST_IP),
])
srv_cert = (
    x509.CertificateBuilder()
    .subject_name(srv_name)
    .issuer_name(ca_name)
    .public_key(srv_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(san, critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)


def w(path, data, mode="wb"):
    with open(os.path.join(OUT, path), mode) as f:
        f.write(data)


w("ca.key", ca_key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption()))
w("ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
w("ca.der", ca_cert.public_bytes(serialization.Encoding.DER))
w("server.key", srv_key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
w("server.crt", srv_cert.public_bytes(serialization.Encoding.PEM))
# 服务器链：服务器证书 + CA
w("chain.crt", srv_cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))

print("已生成到", OUT)
print("  ca.crt / ca.der  -> 装到 iPhone 并开启完全信任")
print("  server.crt/key   -> 给服务端 --tls-cert/--tls-key")
print("  SAN IP:", HOST_IP)
