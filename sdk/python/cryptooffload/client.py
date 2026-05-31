"""CryptoOffload 高层 Python SDK。"""

from __future__ import annotations

from typing import Optional

from cryptooffload.pool import Conn, Pool, PoolConfig

# 生成代码路径：运行 `make proto` 后可用
try:
    from cryptooffload.gen.cryptooffload.v1 import (
        cms_service_pb2,
        cms_service_pb2_grpc,
        common_pb2,
        key_service_pb2,
        key_service_pb2_grpc,
        scep_service_pb2,
        scep_service_pb2_grpc,
        scep_ext_service_pb2,
        scep_ext_service_pb2_grpc,
        sign_service_pb2,
        sign_service_pb2_grpc,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "protobuf stubs missing; run `make proto` in project root first"
    ) from exc


class Client:
    def __init__(self, pool: Pool) -> None:
        self._pool = pool

    @classmethod
    def connect(cls, config: Optional[PoolConfig] = None) -> "Client":
        cfg = config or PoolConfig()
        pool = Pool(cfg)
        pool.warmup()
        return cls(pool)

    def close(self) -> None:
        self._pool.close()

    def _call(self, fn):
        conn = self._pool.acquire()
        try:
            return fn(conn)
        finally:
            conn.release()

    def import_key(self, **kwargs):
        req = key_service_pb2.ImportKeyRequest(**kwargs)
        def run(conn: Conn):
            stub = key_service_pb2_grpc.KeyServiceStub(conn.channel)
            return stub.ImportKey(req)
        return self._call(run)

    def delete_key(self, key_id: str):
        req = key_service_pb2.DeleteKeyRequest(key_id=key_id)
        def run(conn: Conn):
            stub = key_service_pb2_grpc.KeyServiceStub(conn.channel)
            return stub.DeleteKey(req)
        return self._call(run)

    def get_key_info(self, key_id: str):
        req = key_service_pb2.GetKeyInfoRequest(key_id=key_id)
        def run(conn: Conn):
            stub = key_service_pb2_grpc.KeyServiceStub(conn.channel)
            return stub.GetKeyInfo(req)
        return self._call(run)

    def list_keys(self):
        def run(conn: Conn):
            stub = key_service_pb2_grpc.KeyServiceStub(conn.channel)
            return stub.ListKeys(key_service_pb2.ListKeysRequest())
        return self._call(run)

    def sign(self, **kwargs):
        req = sign_service_pb2.SignRequest(**kwargs)
        def run(conn: Conn):
            stub = sign_service_pb2_grpc.SignServiceStub(conn.channel)
            return stub.Sign(req)
        return self._call(run)

    def verify(self, **kwargs):
        req = sign_service_pb2.VerifyRequest(**kwargs)
        def run(conn: Conn):
            stub = sign_service_pb2_grpc.SignServiceStub(conn.channel)
            return stub.Verify(req)
        return self._call(run)

    def parse_cms(self, **kwargs):
        req = cms_service_pb2.ParseCmsRequest(**kwargs)
        def run(conn: Conn):
            stub = cms_service_pb2_grpc.CmsServiceStub(conn.channel)
            return stub.Parse(req)
        return self._call(run)

    def build_cms(self, **kwargs):
        req = cms_service_pb2.BuildCmsRequest(**kwargs)
        def run(conn: Conn):
            stub = cms_service_pb2_grpc.CmsServiceStub(conn.channel)
            return stub.Build(req)
        return self._call(run)

    def verify_cms(self, **kwargs):
        req = cms_service_pb2.VerifyCmsRequest(**kwargs)
        def run(conn: Conn):
            stub = cms_service_pb2_grpc.CmsServiceStub(conn.channel)
            return stub.Verify(req)
        return self._call(run)

    def parse_scep_request(self, **kwargs):
        req = scep_service_pb2.ParseScepRequestRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_service_pb2_grpc.ScepServiceStub(conn.channel)
            return stub.ParseRequest(req)
        return self._call(run)

    def build_scep_success_cert_rep(self, **kwargs):
        req = scep_service_pb2.BuildScepSuccessCertRepRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_service_pb2_grpc.ScepServiceStub(conn.channel)
            return stub.BuildSuccessCertRep(req)
        return self._call(run)

    def build_scep_failure_cert_rep(self, **kwargs):
        req = scep_service_pb2.BuildScepFailureCertRepRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_service_pb2_grpc.ScepServiceStub(conn.channel)
            return stub.BuildFailureCertRep(req)
        return self._call(run)

    def build_scep_pending_cert_rep(self, **kwargs):
        req = scep_service_pb2.BuildScepPendingCertRepRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_service_pb2_grpc.ScepServiceStub(conn.channel)
            return stub.BuildPendingCertRep(req)
        return self._call(run)

    def parse_scep_signed_attributes(self, **kwargs):
        req = scep_ext_service_pb2.ParseScepSignedAttributesRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_ext_service_pb2_grpc.ScepExtServiceStub(conn.channel)
            return stub.ParseSignedAttributes(req)
        return self._call(run)

    def parse_get_cert_pkio(self, **kwargs):
        req = scep_ext_service_pb2.ParseGetCertPkioRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_ext_service_pb2_grpc.ScepExtServiceStub(conn.channel)
            return stub.ParseGetCertPkio(req)
        return self._call(run)

    def encode_cert_alias_content(self, **kwargs):
        req = scep_ext_service_pb2.EncodeCertAliasContentRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_ext_service_pb2_grpc.ScepExtServiceStub(conn.channel)
            return stub.EncodeCertAliasContent(req)
        return self._call(run)

    def encode_scep_http_query(self, **kwargs):
        req = scep_ext_service_pb2.EncodeScepHttpQueryRequest(**kwargs)
        def run(conn: Conn):
            stub = scep_ext_service_pb2_grpc.ScepExtServiceStub(conn.channel)
            return stub.EncodeScepHttpQuery(req)
        return self._call(run)


# 便捷枚举导出
KeyKind = common_pb2.KeyKind
KeyLifetime = common_pb2.KeyLifetime
KeyFormat = common_pb2.KeyFormat
HashAlgorithm = common_pb2.HashAlgorithm
SignAlgorithm = common_pb2.SignAlgorithm
