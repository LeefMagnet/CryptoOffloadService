#!/usr/bin/env python3
"""
CryptoOffload Python SDK 完整接入示例。

前置条件：
  1. make proto
  2. pip install -e sdk/python grpcio protobuf cryptography
  3. 启动服务: cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
  4. python examples/python/demo.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cryptooffload import Client, PoolConfig
from cryptooffload.client import (
    HashAlgorithm,
    KeyFormat,
    KeyKind,
    KeyLifetime,
    SignAlgorithm,
)


def generate_key_material() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(x509.utcnow())
        .not_valid_after(x509.utcnow().replace(year=x509.utcnow().year + 1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return priv_pem, cert_pem


def main() -> None:
    addr = os.environ.get("CRYPTO_OFFLOAD_ADDR", "127.0.0.1:50051")
    client = Client.connect(PoolConfig(address=addr, min_idle=2, max_open=8))

    priv_pem, cert_pem = generate_key_material()
    payload = b"hello crypto-offload"

    # 1. ImportKey — 服务端一次性解析 PEM，返回 key_id
    imported = client.import_key(
        kind=KeyKind.KEY_KIND_PRIVATE,
        lifetime=KeyLifetime.KEY_LIFETIME_PERMANENT,
        format=KeyFormat.KEY_FORMAT_PEM,
        key_data=priv_pem,
        label="demo-signing-key",
        certificate_data=cert_pem,
        certificate_format=KeyFormat.KEY_FORMAT_PEM,
    )
    key_id = imported.metadata.key_id
    print(f"[ImportKey] key_id={key_id} algorithm={imported.metadata.algorithm}")

    # 2. Sign — 仅传 key_id
    sig = client.sign(
        key_id=key_id,
        data=payload,
        hash_algorithm=HashAlgorithm.HASH_SHA256,
        sign_algorithm=SignAlgorithm.SIGN_RSA_PKCS1_V15,
    )
    print(f"[Sign] signature_len={len(sig.signature)}")

    # 3. 公钥 Verify
    pub_pem = priv_pem  # 服务端从私钥 PEM 提取公钥仅适用于部分格式；此处单独导入公钥
    pub_key = serialization.load_pem_private_key(priv_pem, password=None).public_key()
    pub_pem = pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_imported = client.import_key(
        kind=KeyKind.KEY_KIND_PUBLIC,
        lifetime=KeyLifetime.KEY_LIFETIME_PERMANENT,
        format=KeyFormat.KEY_FORMAT_PEM,
        key_data=pub_pem,
    )
    verified = client.verify(
        key_id=pub_imported.metadata.key_id,
        data=payload,
        signature=sig.signature,
        hash_algorithm=HashAlgorithm.HASH_SHA256,
        sign_algorithm=SignAlgorithm.SIGN_RSA_PKCS1_V15,
    )
    print(f"[Verify] valid={verified.valid}")

    # 4. CMS Build / Verify
    cms = client.build_cms(content=payload, sign_key_id=key_id, detached=False)
    print(f"[BuildCMS] cms_len={len(cms.cms_der)}")
    cms_ok = client.verify_cms(
        cms_der=cms.cms_der,
        verify_key_id=pub_imported.metadata.key_id,
    )
    print(f"[VerifyCMS] valid={cms_ok.valid}")

    # 5. 临时密钥
    tmp = client.import_key(
        kind=KeyKind.KEY_KIND_PRIVATE,
        lifetime=KeyLifetime.KEY_LIFETIME_TEMPORARY,
        format=KeyFormat.KEY_FORMAT_PEM,
        key_data=priv_pem,
    )
    tmp_id = tmp.metadata.key_id
    client.sign(key_id=tmp_id, data=payload, hash_algorithm=HashAlgorithm.HASH_SHA256)
    try:
        client.get_key_info(tmp_id)
    except Exception as exc:
        print(f"[TemporaryKey] consumed: {exc}")

    keys = client.list_keys()
    print(f"[ListKeys] count={len(keys.keys)}")

    client.close()


if __name__ == "__main__":
    main()
