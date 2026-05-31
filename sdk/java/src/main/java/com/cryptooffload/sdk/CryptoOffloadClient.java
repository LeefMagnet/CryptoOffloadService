package com.cryptooffload.sdk;

import cryptooffload.v1.CmsServiceGrpc;
import cryptooffload.v1.CmsServiceOuterClass.BuildCmsRequest;
import cryptooffload.v1.CmsServiceOuterClass.BuildCmsResponse;
import cryptooffload.v1.CmsServiceOuterClass.ParseCmsRequest;
import cryptooffload.v1.CmsServiceOuterClass.ParseCmsResponse;
import cryptooffload.v1.CmsServiceOuterClass.VerifyCmsRequest;
import cryptooffload.v1.CmsServiceOuterClass.VerifyCmsResponse;
import cryptooffload.v1.KeyServiceGrpc;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyRequest;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyResponse;
import cryptooffload.v1.ScepExtServiceGrpc;
import cryptooffload.v1.ScepServiceGrpc;
import cryptooffload.v1.ScepExtServiceOuterClass.DecodeCertAliasContentRequest;
import cryptooffload.v1.ScepExtServiceOuterClass.DecodeCertAliasContentResponse;
import cryptooffload.v1.ScepExtServiceOuterClass.EncodeCertAliasContentRequest;
import cryptooffload.v1.ScepExtServiceOuterClass.EncodeCertAliasContentResponse;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseEnrollPkioRequest;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseEnrollPkioResponse;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseGetCertPkioRequest;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseGetCertPkioResponse;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseScepSignedAttributesRequest;
import cryptooffload.v1.ScepExtServiceOuterClass.ParseScepSignedAttributesResponse;
import cryptooffload.v1.ScepServiceOuterClass.BuildScepCertRepResponse;
import cryptooffload.v1.ScepServiceOuterClass.BuildScepFailureCertRepRequest;
import cryptooffload.v1.ScepServiceOuterClass.BuildScepPendingCertRepRequest;
import cryptooffload.v1.ScepServiceOuterClass.BuildScepGmSuccessCertRepRequest;
import cryptooffload.v1.ScepServiceOuterClass.BuildScepSuccessCertRepRequest;
import cryptooffload.v1.ScepServiceOuterClass.ParseScepRequestRequest;
import cryptooffload.v1.ScepServiceOuterClass.ParseScepRequestResponse;
import cryptooffload.v1.SignServiceGrpc;
import cryptooffload.v1.SignServiceOuterClass.SignRequest;
import cryptooffload.v1.SignServiceOuterClass.SignResponse;
import cryptooffload.v1.SignServiceOuterClass.VerifyRequest;
import cryptooffload.v1.SignServiceOuterClass.VerifyResponse;

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
