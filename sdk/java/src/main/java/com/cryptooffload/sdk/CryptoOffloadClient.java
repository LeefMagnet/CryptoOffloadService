package com.cryptooffload.sdk;

import cryptooffload.v1.BuildCmsRequest;
import cryptooffload.v1.BuildCmsResponse;
import cryptooffload.v1.BuildCmpProtectedPkiMessageRequest;
import cryptooffload.v1.BuildCmpProtectedPkiMessageResponse;
import cryptooffload.v1.BuildScepCertRepResponse;
import cryptooffload.v1.BuildScepFailureCertRepRequest;
import cryptooffload.v1.BuildScepGmSuccessCertRepRequest;
import cryptooffload.v1.BuildScepPendingCertRepRequest;
import cryptooffload.v1.BuildScepSuccessCertRepRequest;
import cryptooffload.v1.CmsServiceGrpc;
import cryptooffload.v1.CmpServiceGrpc;
import cryptooffload.v1.DecodeCertAliasContentRequest;
import cryptooffload.v1.DecodeCertAliasContentResponse;
import cryptooffload.v1.EncodeCertAliasContentRequest;
import cryptooffload.v1.EncodeCertAliasContentResponse;
import cryptooffload.v1.ImportKeyRequest;
import cryptooffload.v1.ImportKeyResponse;
import cryptooffload.v1.KeyServiceGrpc;
import cryptooffload.v1.ParseCmsRequest;
import cryptooffload.v1.ParseCmsResponse;
import cryptooffload.v1.ParseAndVerifyCmpPkiMessageRequest;
import cryptooffload.v1.ParseAndVerifyCmpPkiMessageResponse;
import cryptooffload.v1.ParseCmpPkiMessageRequest;
import cryptooffload.v1.ParseCmpPkiMessageResponse;
import cryptooffload.v1.ParseEnrollPkioRequest;
import cryptooffload.v1.ParseEnrollPkioResponse;
import cryptooffload.v1.ParseGetCertPkioRequest;
import cryptooffload.v1.ParseGetCertPkioResponse;
import cryptooffload.v1.ParseScepRequestRequest;
import cryptooffload.v1.ParseScepRequestResponse;
import cryptooffload.v1.ParseScepSignedAttributesRequest;
import cryptooffload.v1.ParseScepSignedAttributesResponse;
import cryptooffload.v1.ScepExtServiceGrpc;
import cryptooffload.v1.ScepServiceGrpc;
import cryptooffload.v1.SignRequest;
import cryptooffload.v1.SignResponse;
import cryptooffload.v1.SignServiceGrpc;
import cryptooffload.v1.VerifyCmsRequest;
import cryptooffload.v1.VerifyCmsResponse;
import cryptooffload.v1.VerifyCmpPkiMessageProtectionRequest;
import cryptooffload.v1.VerifyCmpPkiMessageProtectionResponse;
import cryptooffload.v1.VerifyRequest;
import cryptooffload.v1.VerifyResponse;

/**
 * CryptoOffload Java SDK 高层客户端。
 *
 * <p>使用前请运行 {@code cd sdk/java && mvn compile} 生成 gRPC stub。
 *
 * <p><b>并发</b>：本类线程安全，可在多个虚拟线程/平台线程间共享；连接池 {@code maxOpen}
 * 应 ≥ 并发 RPC 数。
 *
 * <p>适合虚拟线程并发的 RPC：Sign、Verify、buildCms、parseEnrollPkio、parseGetCertPkio、
 * buildScep*CertRep 等（各请求独立时）。
 *
 * <p>建议串行：importKey（低频）、同一临时 key_id 的多次 sign（TEMPORARY 钥仅用一次）。
 * 单条 SCEP 事务内 Parse → RA → Build 有顺序；多条事务之间可并行。
 *
 * <p>完整示例与虚拟线程演示见 {@code examples/java/Demo.java}。
 */
public final class CryptoOffloadClient implements AutoCloseable {
    private final GrpcConnectionPool pool;

    public CryptoOffloadClient(GrpcConnectionPool.PoolConfig config) {
        this.pool = new GrpcConnectionPool(config);
    }

    /** 供高级场景直接使用连接池。 */
    public GrpcConnectionPool pool() {
        return pool;
    }

    public ImportKeyResponse importKey(ImportKeyRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return KeyServiceGrpc.newBlockingStub(conn.channel()).importKey(request);
        }
    }

    public SignResponse sign(SignRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return SignServiceGrpc.newBlockingStub(conn.channel()).sign(request);
        }
    }

    public VerifyResponse verify(VerifyRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return SignServiceGrpc.newBlockingStub(conn.channel()).verify(request);
        }
    }

    public BuildCmsResponse buildCms(BuildCmsRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmsServiceGrpc.newBlockingStub(conn.channel()).build(request);
        }
    }

    public ParseCmsResponse parseCms(ParseCmsRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmsServiceGrpc.newBlockingStub(conn.channel()).parse(request);
        }
    }

    public VerifyCmsResponse verifyCms(VerifyCmsRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmsServiceGrpc.newBlockingStub(conn.channel()).verify(request);
        }
    }

    public ParseCmpPkiMessageResponse parseCmpPkiMessage(ParseCmpPkiMessageRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmpServiceGrpc.newBlockingStub(conn.channel()).parsePkiMessage(request);
        }
    }

    public VerifyCmpPkiMessageProtectionResponse verifyCmpPkiMessageProtection(
            VerifyCmpPkiMessageProtectionRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmpServiceGrpc.newBlockingStub(conn.channel()).verifyPkiMessageProtection(request);
        }
    }

    /** 推荐路径：单次 RPC 完成 CMP parse + verify，减少交互次数。 */
    public ParseAndVerifyCmpPkiMessageResponse parseAndVerifyCmpPkiMessage(
            ParseAndVerifyCmpPkiMessageRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmpServiceGrpc.newBlockingStub(conn.channel()).parseAndVerifyPkiMessage(request);
        }
    }

    /** 当前服务端可能返回 UNIMPLEMENTED（建议业务侧 fallback 到 Java BC）。 */
    public BuildCmpProtectedPkiMessageResponse buildCmpProtectedPkiMessage(
            BuildCmpProtectedPkiMessageRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return CmpServiceGrpc.newBlockingStub(conn.channel()).buildProtectedPkiMessage(request);
        }
    }

    public ParseScepRequestResponse parseScepRequest(ParseScepRequestRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepServiceGrpc.newBlockingStub(conn.channel()).parseRequest(request);
        }
    }

    public BuildScepCertRepResponse buildScepSuccessCertRep(BuildScepSuccessCertRepRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepServiceGrpc.newBlockingStub(conn.channel()).buildSuccessCertRep(request);
        }
    }

    /** 国密 SUCCESS CertRep；{@code envelope_cipher} 见 {@code ScepEnvelopeCipher}（§API 6.2）。 */
    public BuildScepCertRepResponse buildScepGmSuccessCertRep(BuildScepGmSuccessCertRepRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepServiceGrpc.newBlockingStub(conn.channel()).buildGmSuccessCertRep(request);
        }
    }

    public BuildScepCertRepResponse buildScepFailureCertRep(BuildScepFailureCertRepRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepServiceGrpc.newBlockingStub(conn.channel()).buildFailureCertRep(request);
        }
    }

    public BuildScepCertRepResponse buildScepPendingCertRep(BuildScepPendingCertRepRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepServiceGrpc.newBlockingStub(conn.channel()).buildPendingCertRep(request);
        }
    }

    public ParseScepSignedAttributesResponse parseScepSignedAttributes(
            ParseScepSignedAttributesRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepExtServiceGrpc.newBlockingStub(conn.channel()).parseSignedAttributes(request);
        }
    }

    public ParseGetCertPkioResponse parseGetCertPkio(ParseGetCertPkioRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepExtServiceGrpc.newBlockingStub(conn.channel()).parseGetCertPkio(request);
        }
    }

    public ParseEnrollPkioResponse parseEnrollPkio(ParseEnrollPkioRequest request)
            throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepExtServiceGrpc.newBlockingStub(conn.channel()).parseEnrollPkio(request);
        }
    }

    public EncodeCertAliasContentResponse encodeCertAliasContent(
            EncodeCertAliasContentRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepExtServiceGrpc.newBlockingStub(conn.channel()).encodeCertAliasContent(request);
        }
    }

    public DecodeCertAliasContentResponse decodeCertAliasContent(
            DecodeCertAliasContentRequest request) throws InterruptedException {
        try (GrpcConnectionPool.PooledConn conn = pool.acquire()) {
            return ScepExtServiceGrpc.newBlockingStub(conn.channel()).decodeCertAliasContent(request);
        }
    }

    @Override
    public void close() {
        pool.close();
    }
}
