#!/usr/bin/env python3
"""CryptoOffload gRPC 压测脚本（需先 make proto）。"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import grpc

try:
    from cryptooffload.gen.cryptooffload.v1 import (
        common_pb2,
        key_service_pb2,
        key_service_pb2_grpc,
        sign_service_pb2,
        sign_service_pb2_grpc,
    )
except ImportError:
    sys.stderr.write("Run `make proto` and PYTHONPATH=sdk/python first\n")
    sys.exit(1)


def generate_rsa_pem() -> bytes:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def import_key(stub, pem: bytes, kind, lifetime=common_pb2.KEY_LIFETIME_PERMANENT) -> str:
    resp = stub.ImportKey(
        key_service_pb2.ImportKeyRequest(
            kind=kind,
            lifetime=lifetime,
            format=common_pb2.KEY_FORMAT_PEM,
            key_data=pem,
            label="bench",
        )
    )
    return resp.metadata.key_id


def bench_sign(addr: str, clients: int, total: int, warmup: float) -> None:
    channel = grpc.insecure_channel(addr)
    key_stub = key_service_pb2_grpc.KeyServiceStub(channel)
    sign_stub = sign_service_pb2_grpc.SignServiceStub(channel)

    priv_pem = generate_rsa_pem()
    priv_id = import_key(key_stub, priv_pem, common_pb2.KEY_KIND_PRIVATE)
    pub_pem = (
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["*"])
        .load_pem_private_key(priv_pem, password=None)
        .public_key()
        .public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
        )
    )
    pub_id = import_key(key_stub, pub_pem, common_pb2.KEY_KIND_PUBLIC)
    payload = b"\xab" * 256
    sig = sign_stub.Sign(
        sign_service_pb2.SignRequest(
            key_id=priv_id,
            data=payload,
            hash_algorithm=common_pb2.HASH_SHA256,
            sign_algorithm=common_pb2.SIGN_RSA_PKCS1_V15,
        )
    ).signature

    deadline = time.monotonic() + warmup
    while time.monotonic() < deadline:
        sign_stub.Sign(
            sign_service_pb2.SignRequest(
                key_id=priv_id,
                data=payload,
                hash_algorithm=common_pb2.HASH_SHA256,
            )
        )

    latencies: list[float] = []

    def worker(n: int) -> list[float]:
        local = []
        ch = grpc.insecure_channel(addr)
        stub = sign_service_pb2_grpc.SignServiceStub(ch)
        for _ in range(n):
            t0 = time.perf_counter()
            stub.Sign(
                sign_service_pb2.SignRequest(
                    key_id=priv_id,
                    data=payload,
                    hash_algorithm=common_pb2.HASH_SHA256,
                )
            )
            local.append((time.perf_counter() - t0) * 1e6)
        return local

    per = total // clients
    rem = total % clients
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=clients) as ex:
        futs = [ex.submit(worker, per + (1 if i == 0 else 0)) for i in range(clients)]
        for f in as_completed(futs):
            latencies.extend(f.result())
    elapsed = time.perf_counter() - t0

    latencies.sort()
    n = len(latencies)
    print(f"mode: sign")
    print(f"total_requests: {total}")
    print(f"clients: {clients}")
    print(f"elapsed_ms: {elapsed * 1000:.2f}")
    print(f"qps: {total / elapsed:.2f}")
    print(
        f"latency_us: p50={latencies[n * 50 // 100]:.0f} "
        f"p95={latencies[n * 95 // 100]:.0f} p99={latencies[n * 99 // 100]:.0f}"
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--address", default="127.0.0.1:50051")
    p.add_argument("--mode", default="sign", choices=["sign"])
    p.add_argument("--clients", type=int, default=4, help="建议 = 服务端 CPU / max-inflight（1:1）")
    p.add_argument("--total", type=int, default=5000)
    p.add_argument("--warmup", type=float, default=2.0)
    args = p.parse_args()
    if args.mode == "sign":
        bench_sign(args.address, args.clients, args.total, args.warmup)


if __name__ == "__main__":
    main()
