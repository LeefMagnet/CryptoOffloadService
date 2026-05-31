package com.cryptooffload.examples;

import com.cryptooffload.sdk.CryptoOffloadClient;
import com.cryptooffload.sdk.GrpcConnectionPool;
import cryptooffload.v1.Common.HashAlgorithm;
import cryptooffload.v1.Common.KeyFormat;
import cryptooffload.v1.Common.KeyKind;
import cryptooffload.v1.Common.KeyLifetime;
import cryptooffload.v1.Common.SignAlgorithm;
import cryptooffload.v1.KeyServiceOuterClass.ImportKeyRequest;
import cryptooffload.v1.SignServiceOuterClass.SignRequest;
import cryptooffload.v1.SignServiceOuterClass.SignResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * CryptoOffload Java SDK 接入示例。
 *
 * <pre>
 *   cd sdk/java && mvn compile   # 生成 gRPC stub
 *   mvn -f examples/java/pom.xml exec:java
 * </pre>
 *
 * <h2>并发与虚拟线程（Java 21+）</h2>
 * <ul>
 *   <li>{@link CryptoOffloadClient} 线程安全：多虚拟线程/平台线程可共享同一实例。</li>
 *   <li>连接池 {@code maxOpen} 应 ≥ 预期并发 RPC 数，避免 acquire 超时。</li>
 *   <li>阻塞 gRPC 调用适合放在虚拟线程中，避免占用少量平台线程（如 Tomcat worker）。</li>
 * </ul>
 *
 * <p><b>建议用虚拟线程并发的场景</b>（本示例 {@link #demoConcurrentSigns} 演示）：
 * <ul>
 *   <li>批量 Sign / Verify、CMS Build / Verify</li>
 *   <li>多终端 SCEP 入站：{@code ParseEnrollPkio}、{@code ParseGetCertPkio}（各请求独立）</li>
 *   <li>多终端 CertRep：{@code buildScepSuccessCertRep} / Failure / Pending</li>
 * </ul>
 *
 * <p><b>建议串行、不宜盲目并发的场景</b>：
 * <ul>
 *   <li>{@code ImportKey}：启动/轮换时一次性导入，频率低</li>
 *   <li>{@code KEY_LIFETIME_TEMPORARY} 临时钥：同一 key_id 只能 Sign 一次</li>
 *   <li>单条 SCEP 事务内 Parse → RA 决策 → Build 有顺序依赖，但<b>多条事务</b>之间可并行</li>
 *   <li>GetCACert 响应：Go SCEP 本地缓存即可，不经 Offload</li>
 * </ul>
 *
 * 环境变量 {@code CRYPTO_OFFLOAD_ADDR} 默认 127.0.0.1:50051
 */
public final class Demo {
    public static void main(String[] args) throws Exception {
        String addr = System.getenv().getOrDefault("CRYPTO_OFFLOAD_ADDR", "127.0.0.1:50051");
        // maxOpen 建议 ≥ 并发虚拟线程数；SCEP 网关可按 CPU/offload 核数调整
        var config = new GrpcConnectionPool.PoolConfig(
                addr, 2, 8,
                java.time.Duration.ofMinutes(30),
                java.time.Duration.ofMinutes(5),
                java.time.Duration.ofSeconds(10));

        try (var client = new CryptoOffloadClient(config)) {
            // --- 1. ImportKey：低频、串行即可；PEM 仅在导入时传输一次 ---
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

            // --- 2. Sign：热路径只传 key_id；高 QPS 时用虚拟线程并发（见 demoConcurrentSigns）---
            SignResponse sig = client.sign(SignRequest.newBuilder()
                    .setKeyId(keyId)
                    .setData(com.google.protobuf.ByteString.copyFrom("hello".getBytes()))
                    .setHashAlgorithm(HashAlgorithm.HASH_SHA256)
                    .setSignAlgorithm(SignAlgorithm.SIGN_RSA_PKCS1_V15)
                    .build());
            System.out.printf("[Sign] signature_len=%d%n", sig.getSignature().size());

            // --- 3. 并发 Sign 演示：模拟多请求同时 offload（需 Java 21+）---
            demoConcurrentSigns(client, keyId);
        }
    }

    /**
     * 用虚拟线程并发发起多条 Sign RPC。
     *
     * <p>在 SCEP 网关中，可对「多条独立的 Enroll/GetCert 事务」采用相同模式：
     * 每条 HTTP 请求在虚拟线程里调用 {@code parseEnrollPkio}，RA 完成后在同一线程或
     * 另一虚拟线程调用 {@code buildScepSuccessCertRep}；不同事务之间无共享可变状态。
     */
    private static void demoConcurrentSigns(CryptoOffloadClient client, String keyId) throws Exception {
        int parallelism = 8;
        byte[] payload = "concurrent-payload".getBytes();

        // Executors.newVirtualThreadPerTaskExecutor()：每条任务一个虚拟线程，阻塞 gRPC 不占用平台线程
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<SignResponse>> futures = new ArrayList<>(parallelism);
            for (int i = 0; i < parallelism; i++) {
                futures.add(executor.submit(() -> client.sign(SignRequest.newBuilder()
                        .setKeyId(keyId)
                        .setData(com.google.protobuf.ByteString.copyFrom(payload))
                        .setHashAlgorithm(HashAlgorithm.HASH_SHA256)
                        .setSignAlgorithm(SignAlgorithm.SIGN_RSA_PKCS1_V15)
                        .build())));
            }
            for (Future<SignResponse> f : futures) {
                SignResponse r = f.get();
                System.out.printf("[ConcurrentSign] signature_len=%d%n", r.getSignature().size());
            }
        }
        System.out.printf("[ConcurrentSign] completed %d parallel Sign RPCs%n", parallelism);
    }
}
