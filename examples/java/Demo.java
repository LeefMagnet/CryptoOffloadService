package com.cryptooffload.examples;

import com.cryptooffload.sdk.CryptoOffloadClient;
import com.cryptooffload.sdk.GrpcConnectionPool;
import cryptooffload.v1.Common.KeyFormat;
import cryptooffload.v1.Common.KeyKind;
import cryptooffload.v1.Common.KeyLifetime;
import cryptooffload.v1.Common.HashAlgorithm;
import cryptooffload.v1.Common.SignAlgorithm;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyRequest;
import cryptooffload.v1.SignServiceOuterClass.SignRequest;
import cryptooffload.v1.SignServiceOuterClass.SignResponse;

/**
 * CryptoOffload Java SDK 接入示例。
 *
 * <pre>
 *   cd sdk/java && mvn compile   # 生成 gRPC stub
 *   mvn -f examples/java/pom.xml exec:java
 * </pre>
 *
 * 环境变量 {@code CRYPTO_OFFLOAD_ADDR} 默认 127.0.0.1:50051
 */
public final class Demo {
    public static void main(String[] args) throws Exception {
        String addr = System.getenv().getOrDefault("CRYPTO_OFFLOAD_ADDR", "127.0.0.1:50051");
        var config = new GrpcConnectionPool.PoolConfig(
                addr, 2, 8,
                java.time.Duration.ofMinutes(30),
                java.time.Duration.ofMinutes(5),
                java.time.Duration.ofSeconds(10));

        try (var client = new CryptoOffloadClient(config)) {
            // 1. ImportKey — PEM 仅在导入时传输一次
            byte[] privPem = DemoKeys.privateKeyPem();
            var imported = client.importKey(ImportKeyRequest.newBuilder()
                    .setKind(KeyKind.KEY_KIND_PRIVATE)
                    .setLifetime(KeyLifetime.KEY_LIFETIME_PERMANENT)
                    .setFormat(KeyFormat.KEY_FORMAT_PEM)
                    .setKeyData(com.google.protobuf.ByteString.copyFrom(privPem))
                    .setLabel("demo-java")
                    .build());
            String keyId = imported.getMetadata().getKeyId();
            System.out.printf("[ImportKey] key_id=%s%n", keyId);

            // 2. Sign — 热路径只传 key_id
            SignResponse sig = client.sign(SignRequest.newBuilder()
                    .setKeyId(keyId)
                    .setData(com.google.protobuf.ByteString.copyFrom("hello".getBytes()))
                    .setHashAlgorithm(HashAlgorithm.HASH_SHA256)
                    .setSignAlgorithm(SignAlgorithm.SIGN_RSA_PKCS1_V15)
                    .build());
            System.out.printf("[Sign] signature_len=%d%n", sig.getSignature().size());
        }
    }
}
