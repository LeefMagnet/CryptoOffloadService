package com.cryptooffload.sdk;

import cryptooffload.v1.CmsServiceGrpc;
import cryptooffload.v1.CmsServiceOuterClass.BuildCmsRequest;
import cryptooffload.v1.CmsServiceOuterClass.BuildCmsResponse;
import cryptooffload.v1.KeyServiceGrpc;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyRequest;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyResponse;
import cryptooffload.v1.SignServiceGrpc;
import cryptooffload.v1.SignServiceOuterClass.SignRequest;
import cryptooffload.v1.SignServiceOuterClass.SignResponse;
import cryptooffload.v1.SignServiceOuterClass.VerifyRequest;
import cryptooffload.v1.SignServiceOuterClass.VerifyResponse;

/**
 * CryptoOffload Java SDK 高层客户端。
 *
 * <p>使用前请运行 {@code cd sdk/java && mvn compile} 生成 gRPC stub。
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

    @Override
    public void close() {
        pool.close();
    }
}
