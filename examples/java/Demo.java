package com.cryptooffload.examples;

import com.cryptooffload.sdk.CryptoOffloadClient;
import com.cryptooffload.sdk.GrpcConnectionPool;
import cryptooffload.v1.HashAlgorithm;
import cryptooffload.v1.ImportKeyRequest;
import cryptooffload.v1.KeyFormat;
import cryptooffload.v1.KeyKind;
import cryptooffload.v1.KeyLifetime;
import cryptooffload.v1.ParseAndVerifyCmpPkiMessageRequest;
import cryptooffload.v1.SignAlgorithm;
import cryptooffload.v1.SignRequest;
import cryptooffload.v1.SignResponse;
import cryptooffload.v1.ScepEnvelopeCipher;

import java.util.ArrayList;
import java.util.Base64;
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

            // --- 4. CMP ParseAndVerify（按环境变量启用）---
            demoCmpParseAndVerify(client, keyId);

            // --- 5. SCEP 正向用例（来自 Rust 单测语义，按环境变量启用）---
            demoScepPositiveCases(client, keyId);
        }
    }

    /**
     * CMP 单次 RPC Parse + Verify 演示。
     *
     * <p>环境变量：
     * <ul>
     *   <li>CMP_PKI_MESSAGE_DER_B64（必填，开启演示）</li>
     *   <li>CMP_VERIFY_KEY_ID（可选，默认 fallback 到 fallbackVerifyKeyId）</li>
     * </ul>
     */
    private static void demoCmpParseAndVerify(CryptoOffloadClient client, String fallbackVerifyKeyId)
            throws Exception {
        String msgB64 = System.getenv("CMP_PKI_MESSAGE_DER_B64");
        if (msgB64 == null || msgB64.isBlank()) {
            System.out.println("[CMP] skip: set CMP_PKI_MESSAGE_DER_B64 to run ParseAndVerify example");
            return;
        }
        byte[] pkiMessageDer = Base64.getDecoder().decode(msgB64);
        String verifyKeyId = System.getenv("CMP_VERIFY_KEY_ID");
        if (verifyKeyId == null || verifyKeyId.isBlank()) {
            verifyKeyId = fallbackVerifyKeyId;
            System.out.printf("[CMP] warning: CMP_VERIFY_KEY_ID not set, fallback to key_id=%s%n", verifyKeyId);
        }
        var resp = client.parseAndVerifyCmpPkiMessage(ParseAndVerifyCmpPkiMessageRequest.newBuilder()
                .setPkiMessageDer(com.google.protobuf.ByteString.copyFrom(pkiMessageDer))
                .setVerifyKeyId(verifyKeyId)
                .build());
        System.out.printf("[CMP ParseAndVerify] valid=%s body_type=%d tx_len=%d recip_nonce_len=%d%n",
                resp.getValid(), resp.getBodyType(), resp.getTransactionId().size(), resp.getRecipientNonce().size());
    }

    /**
     * 用虚拟线程并发发起多条 Sign RPC。
     *
 * <p>在 SCEP 网关中，可对「多条独立的 Enroll/GetCert 事务」采用相同模式：
 * 每条 HTTP 请求在虚拟线程里调用 {@code parseEnrollPkio}，RA 完成后在同一线程或
 * 另一虚拟线程调用 {@code buildScepSuccessCertRep}；不同事务之间无共享可变状态。
 * CertRep 的 {@code envelope_cipher} 应与 Enroll PKIO Envelop 算法一致（见
 * {@code ScepEnvelopeCipher}：0=UNSPECIFIED(服务端默认AES-128-CBC)，1=AES-128-CBC，2=AES-256-CBC，5=3DES-CBC，6=DES-CBC(禁用)）。
 * 国密路径使用 {@code buildScepGmSuccessCertRep}，同样设置 {@code envelope_cipher}。
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

    /**
     * 对齐 server/tests/scep_tests.rs 的正向场景：
     * 1) ParseEnrollPkio（支持 challenge_password）
     * 2) BuildScepSuccessCertRep（challenge_password 非空时走 PasswordRecipientInfo）
     *
     * <p>通过环境变量注入样本，避免在仓库中硬编码业务证书：
     * <ul>
     *   <li>SCEP_ENROLL_PKIO_B64（必填，开启演示）</li>
     *   <li>SCEP_CA_KEY_ID（可选，推荐显式指定；必须是该 PKIO 对应 CA 私钥）</li>
     *   <li>SCEP_CHALLENGE_PASSWORD（可选，PasswordRecipientInfo 时必填）</li>
     *   <li>SCEP_ISSUED_CERT_DER_B64（可选，若提供则继续演示 BuildSuccessCertRep）</li>
     * </ul>
     */
    private static void demoScepPositiveCases(CryptoOffloadClient client, String fallbackCaKeyId) throws Exception {
        String pkioB64 = System.getenv("SCEP_ENROLL_PKIO_B64");
        if (pkioB64 == null || pkioB64.isBlank()) {
            System.out.println("[SCEP] skip: set SCEP_ENROLL_PKIO_B64 to run positive Parse/Build examples");
            return;
        }
        byte[] pkioDer = Base64.getDecoder().decode(pkioB64);

        String caKeyId = System.getenv("SCEP_CA_KEY_ID");
        if (caKeyId == null || caKeyId.isBlank()) {
            caKeyId = fallbackCaKeyId;
            System.out.printf(
                    "[SCEP] warning: SCEP_CA_KEY_ID not set, fallback to key_id=%s (may fail if not CA key)%n",
                    caKeyId);
        }
        String challengePassword = System.getenv().getOrDefault("SCEP_CHALLENGE_PASSWORD", "");

        var parsed = client.parseEnrollPkio(ParseEnrollPkioRequest.newBuilder()
                .setScepDer(com.google.protobuf.ByteString.copyFrom(pkioDer))
                .setCaKeyId(caKeyId)
                .setChallengePassword(challengePassword)
                .build());
        System.out.printf("[SCEP ParseEnrollPkio] csr_len=%d wrapper_len=%d tx=%s%n",
                parsed.getCsrDer().size(), parsed.getWrapperCertDer().size(),
                parsed.hasAttributes() ? parsed.getAttributes().getTransactionId() : "");

        String issuedB64 = System.getenv("SCEP_ISSUED_CERT_DER_B64");
        if (issuedB64 == null || issuedB64.isBlank()) {
            System.out.println("[SCEP] skip BuildScepSuccessCertRep: set SCEP_ISSUED_CERT_DER_B64");
            return;
        }
        byte[] issuedDer = Base64.getDecoder().decode(issuedB64);

        String txId = parsed.hasAttributes() ? parsed.getAttributes().getTransactionId() : "";
        if (txId == null || txId.isBlank()) {
            txId = "tx-from-example-positive";
        }

        byte[] recipientNonce = parsed.hasAttributes()
                ? parsed.getAttributes().getSenderNonce().toByteArray()
                : new byte[0];
        if (recipientNonce.length == 0) {
            recipientNonce = new byte[]{0x11, 0x22, 0x33, 0x44};
        }

        byte[] wrapper = parsed.getWrapperCertDer().toByteArray();
        if (!challengePassword.isBlank()) {
            // PasswordRecipientInfo 模式下 wrapper_cert_der 可省略。
            wrapper = new byte[0];
        }

        var rep = client.buildScepSuccessCertRep(BuildScepSuccessCertRepRequest.newBuilder()
                .setCaKeyId(caKeyId)
                .setTransactionId(txId)
                .setRecipientNonce(com.google.protobuf.ByteString.copyFrom(recipientNonce))
                .setIssuedCertDer(com.google.protobuf.ByteString.copyFrom(issuedDer))
                .setWrapperCertDer(com.google.protobuf.ByteString.copyFrom(wrapper))
                .setEnvelopeCipher(ScepEnvelopeCipher.SCEP_ENVELOPE_CIPHER_AES_128_CBC)
                .setChallengePassword(challengePassword)
                .build());
        System.out.printf("[SCEP BuildSuccessCertRep] certrep_len=%d%n", rep.getCertrepDer().size());
    }
}
