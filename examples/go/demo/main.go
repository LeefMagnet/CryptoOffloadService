// CryptoOffload Go SDK 完整接入示例。
//
// 前置条件：
//   1. make proto
//   2. 启动服务: cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
//   3. go run ./examples/go/demo
//
// 并发与 goroutine
//
//   - client.Client 线程安全：多个 goroutine 可共享同一 *Client。
//   - 连接池 MaxOpen 应 ≥ 预期并发 RPC 数，避免 Acquire 超时。
//   - 每个 RPC 在 goroutine 内阻塞等待 gRPC 响应即可；服务端 crypto 有独立 in-flight 限制。
//
// 建议用 goroutine 并发的场景（见 demoConcurrentSigns）：
//   - 批量 Sign / Verify、CMS Build / Verify
//   - 多终端 SCEP 入站：ParseEnrollPkio、ParseGetCertPkio（各请求独立）
//   - 多终端 CertRep：BuildScepSuccessCertRep / Failure / Pending
//
// 建议串行、不宜盲目并发的场景：
//   - ImportKey：启动/轮换时一次性导入
//   - KEY_LIFETIME_TEMPORARY 临时钥：同一 key_id 只能 Sign 一次
//   - 单条 SCEP 事务内 Parse → RA → Build 有顺序依赖；多条事务之间可并行
//   - GetCACert：Go SCEP 本地缓存响应，不经 Offload
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/cryptooffload/sdk-go/client"
	pb "github.com/cryptooffload/sdk-go/gen/cryptooffload/v1"
	"github.com/cryptooffload/sdk-go/pool"
)

func main() {
	addr := env("CRYPTO_OFFLOAD_ADDR", "127.0.0.1:50051")
	ctx := context.Background()

	// MaxOpen 建议 ≥ 并发 goroutine 数；SCEP 网关可按 offload 核数调整
	cli, err := client.New(ctx, client.Config{
		Config: pool.Config{
			Address:        addr,
			MinIdle:        2,
			MaxOpen:        8,
			MaxLifetime:    30 * time.Minute,
			IdleTimeout:    5 * time.Minute,
			DialTimeout:    5 * time.Second,
			AcquireTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer cli.Close()

	privPEM, certPEM := loadOrGenerateKeyMaterial()

	// --- 1. ImportKey：低频、串行；一次性导入，服务端解析 PEM 并缓存 PKey ---
	imported, err := cli.ImportKey(ctx, &pb.ImportKeyRequest{
		Kind:              pb.KeyKind_KEY_KIND_PRIVATE,
		Lifetime:          pb.KeyLifetime_KEY_LIFETIME_PERMANENT,
		Format:            pb.KeyFormat_KEY_FORMAT_PEM,
		KeyData:           privPEM,
		Label:             "demo-signing-key",
		CertificateData:   certPEM,
		CertificateFormat: pb.KeyFormat_KEY_FORMAT_PEM,
	})
	if err != nil {
		log.Fatalf("ImportKey: %v", err)
	}
	keyID := imported.GetMetadata().GetKeyId()
	fmt.Printf("[ImportKey] key_id=%s algorithm=%s bits=%d\n",
		keyID, imported.GetMetadata().GetAlgorithm(), imported.GetMetadata().GetKeyBits())

	// --- 2. Sign：热路径只传 key_id；高 QPS 时用 goroutine 并发（见 demoConcurrentSigns）---
	payload := []byte("hello crypto-offload")
	signResp, err := cli.Sign(ctx, &pb.SignRequest{
		KeyId:         keyID,
		Data:          payload,
		HashAlgorithm: pb.HashAlgorithm_HASH_SHA256,
		SignAlgorithm: pb.SignAlgorithm_SIGN_RSA_PKCS1_V15,
	})
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}
	fmt.Printf("[Sign] signature_len=%d\n", len(signResp.GetSignature()))

	// --- 3. 并发 Sign 演示：模拟多请求同时 offload ---
	if err := demoConcurrentSigns(ctx, cli, keyID, payload); err != nil {
		log.Fatalf("ConcurrentSign: %v", err)
	}

	// --- 4. 导入公钥并 Verify（单条串行；批量验签可对每条 Verify 起 goroutine）---
	pubPEM := extractPublicPEM(privPEM)
	pubImported, err := cli.ImportKey(ctx, &pb.ImportKeyRequest{
		Kind:     pb.KeyKind_KEY_KIND_PUBLIC,
		Lifetime: pb.KeyLifetime_KEY_LIFETIME_PERMANENT,
		Format:   pb.KeyFormat_KEY_FORMAT_PEM,
		KeyData:  pubPEM,
		Label:    "demo-verify-key",
	})
	if err != nil {
		log.Fatalf("ImportKey public: %v", err)
	}
	verifyResp, err := cli.Verify(ctx, &pb.VerifyRequest{
		KeyId:         pubImported.GetMetadata().GetKeyId(),
		Data:          payload,
		Signature:     signResp.GetSignature(),
		HashAlgorithm: pb.HashAlgorithm_HASH_SHA256,
		SignAlgorithm: pb.SignAlgorithm_SIGN_RSA_PKCS1_V15,
	})
	if err != nil {
		log.Fatalf("Verify: %v", err)
	}
	fmt.Printf("[Verify] valid=%v\n", verifyResp.GetValid())

	// --- 5. CMS Build / Verify（Build 可并发；同一 sign_key_id 并发安全）---
	cmsResp, err := cli.BuildCMS(ctx, &pb.BuildCmsRequest{
		Content:   payload,
		SignKeyId: keyID,
		Detached:  false,
	})
	if err != nil {
		log.Fatalf("BuildCMS: %v", err)
	}
	fmt.Printf("[BuildCMS] cms_len=%d\n", len(cmsResp.GetCmsDer()))

	cmsVerify, err := cli.VerifyCMS(ctx, &pb.VerifyCmsRequest{
		CmsDer:      cmsResp.GetCmsDer(),
		VerifyKeyId: pubImported.GetMetadata().GetKeyId(),
	})
	if err != nil {
		log.Fatalf("VerifyCMS: %v", err)
	}
	fmt.Printf("[VerifyCMS] valid=%v\n", cmsVerify.GetValid())

	// --- 6. 临时密钥：必须串行——首次 Sign 后 key 即销毁，不可并发复用同一 key_id ---
	tmpImported, err := cli.ImportKey(ctx, &pb.ImportKeyRequest{
		Kind:     pb.KeyKind_KEY_KIND_PRIVATE,
		Lifetime: pb.KeyLifetime_KEY_LIFETIME_TEMPORARY,
		Format:   pb.KeyFormat_KEY_FORMAT_PEM,
		KeyData:  privPEM,
	})
	if err != nil {
		log.Fatalf("ImportKey temporary: %v", err)
	}
	tmpID := tmpImported.GetMetadata().GetKeyId()
	_, err = cli.Sign(ctx, &pb.SignRequest{
		KeyId:         tmpID,
		Data:          payload,
		HashAlgorithm: pb.HashAlgorithm_HASH_SHA256,
	})
	if err != nil {
		log.Fatalf("Sign temporary: %v", err)
	}
	_, err = cli.GetKeyInfo(ctx, tmpID)
	if err != nil {
		fmt.Printf("[TemporaryKey] consumed as expected: %v\n", err)
	}

	keys, _ := cli.ListKeys(ctx)
	fmt.Printf("[ListKeys] count=%d\n", len(keys.GetKeys()))

	// --- 7. SCEP 正向用例（来自 Rust 单测语义，按环境变量启用）---
	if err := demoScepPositiveCases(ctx, cli, keyID); err != nil {
		log.Fatalf("SCEP positive cases: %v", err)
	}

	// SCEP 网关典型并发模式（伪代码，未在此 demo 调用）：
	//   go func() {
	//       parsed, _ := cli.ParseEnrollPkio(ctx, &pb.ParseEnrollPkioRequest{...})
	//       // RA 审批 ...
	//       rep, _ := cli.BuildScepSuccessCertRep(ctx, &pb.BuildScepSuccessCertRepRequest{
	//           CaKeyId: caKeyID, TransactionId: parsed.GetTransactionId(),
	//           RecipientNonce: parsed.GetSenderNonce(), IssuedCertDer: issuedDER,
	//           WrapperCertDer: parsed.GetWrapperCertDer(),
	//           // 与 Enroll PKIO Envelop OID 一致；RFC 8894 常用 AES-128，老 MDM 常用 DES3(5)
	//           EnvelopeCipher: pb.ScepEnvelopeCipher_SCEP_ENVELOPE_CIPHER_AES_128_CBC,
	//       })
	//       // 国密 Enroll：BuildScepGmSuccessCertRep，同样设置 EnvelopeCipher
	//   }()
}

// demoConcurrentSigns 用 goroutine 并发发起多条 Sign RPC。
//
// SCEP 场景：每条 HTTP 请求可在独立 goroutine 中 ParseEnrollPkio → RA → BuildCertRep；
// 不同终端事务之间无共享状态，适合与 net/http 每请求一 goroutine 模型配合。
func demoConcurrentSigns(ctx context.Context, cli *client.Client, keyID string, payload []byte) error {
	const parallelism = 8
	var wg sync.WaitGroup
	errCh := make(chan error, parallelism)

	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cli.Sign(ctx, &pb.SignRequest{
				KeyId:         keyID,
				Data:          payload,
				HashAlgorithm: pb.HashAlgorithm_HASH_SHA256,
				SignAlgorithm: pb.SignAlgorithm_SIGN_RSA_PKCS1_V15,
			})
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	fmt.Printf("[ConcurrentSign] completed %d parallel Sign RPCs\n", parallelism)
	return nil
}

// demoScepPositiveCases 对齐 server/tests/scep_tests.rs 的正向场景：
// 1) ParseEnrollPkio（支持 challenge_password）
// 2) BuildScepSuccessCertRep（challenge_password 非空时走 PasswordRecipientInfo）
//
// 运行时通过环境变量注入样本，避免把业务证书硬编码到示例仓库：
//   - SCEP_ENROLL_PKIO_B64        (必填，开启本演示)
//   - SCEP_CA_KEY_ID              (可选，推荐显式指定；必须是该 PKIO 对应 CA 私钥)
//   - SCEP_CHALLENGE_PASSWORD     (可选，PasswordRecipientInfo 时必填)
//   - SCEP_ISSUED_CERT_DER_B64    (可选，若提供则继续演示 BuildSuccessCertRep)
func demoScepPositiveCases(ctx context.Context, cli *client.Client, fallbackCAKeyID string) error {
	pkioB64 := os.Getenv("SCEP_ENROLL_PKIO_B64")
	if pkioB64 == "" {
		fmt.Println("[SCEP] skip: set SCEP_ENROLL_PKIO_B64 to run positive Parse/Build examples")
		return nil
	}
	pkioDER, err := base64.StdEncoding.DecodeString(pkioB64)
	if err != nil {
		return fmt.Errorf("decode SCEP_ENROLL_PKIO_B64: %w", err)
	}

	caKeyID := os.Getenv("SCEP_CA_KEY_ID")
	if caKeyID == "" {
		caKeyID = fallbackCAKeyID
		fmt.Printf("[SCEP] warning: SCEP_CA_KEY_ID not set, fallback to key_id=%s (may fail if not CA key)\n", caKeyID)
	}
	challengePassword := os.Getenv("SCEP_CHALLENGE_PASSWORD")

	parsed, err := cli.ParseEnrollPkio(ctx, &pb.ParseEnrollPkioRequest{
		ScepDer:           pkioDER,
		CaKeyId:           caKeyID,
		ChallengePassword: challengePassword,
	})
	if err != nil {
		return fmt.Errorf("ParseEnrollPkio: %w", err)
	}
	fmt.Printf("[SCEP ParseEnrollPkio] csr_len=%d wrapper_len=%d tx=%s\n",
		len(parsed.GetCsrDer()), len(parsed.GetWrapperCertDer()), parsed.GetAttributes().GetTransactionId())

	issuedB64 := os.Getenv("SCEP_ISSUED_CERT_DER_B64")
	if issuedB64 == "" {
		fmt.Println("[SCEP] skip BuildSuccessCertRep: set SCEP_ISSUED_CERT_DER_B64")
		return nil
	}
	issuedDER, err := base64.StdEncoding.DecodeString(issuedB64)
	if err != nil {
		return fmt.Errorf("decode SCEP_ISSUED_CERT_DER_B64: %w", err)
	}

	attrs := parsed.GetAttributes()
	txID := attrs.GetTransactionId()
	if txID == "" {
		txID = "tx-from-example-positive"
	}
	recipientNonce := attrs.GetSenderNonce()
	if len(recipientNonce) == 0 {
		recipientNonce = []byte{0x11, 0x22, 0x33, 0x44}
	}

	wrapper := parsed.GetWrapperCertDer()
	if challengePassword != "" {
		// PasswordRecipientInfo 模式下 wrapper_cert_der 可省略。
		wrapper = nil
	}

	rep, err := cli.BuildScepSuccessCertRep(ctx, &pb.BuildScepSuccessCertRepRequest{
		CaKeyId:           caKeyID,
		TransactionId:     txID,
		RecipientNonce:    recipientNonce,
		IssuedCertDer:     issuedDER,
		WrapperCertDer:    wrapper,
		EnvelopeCipher:    pb.ScepEnvelopeCipher_SCEP_ENVELOPE_CIPHER_AES_128_CBC,
		ChallengePassword: challengePassword,
	})
	if err != nil {
		return fmt.Errorf("BuildScepSuccessCertRep: %w", err)
	}
	fmt.Printf("[SCEP BuildSuccessCertRep] certrep_len=%d\n", len(rep.GetCertrepDer()))
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadOrGenerateKeyMaterial() ([]byte, []byte) {
	if k := os.Getenv("PRIVATE_KEY_PEM"); k != "" {
		priv, _ := os.ReadFile(k)
		cert, _ := os.ReadFile(env("CERTIFICATE_PEM", ""))
		return priv, cert
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "demo"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return privPEM, certPEM
}

func extractPublicPEM(privPEM []byte) []byte {
	block, _ := pem.Decode(privPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}
