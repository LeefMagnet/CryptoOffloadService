// CryptoOffload Go SDK 完整接入示例。
//
// 前置条件：
//   1. make proto
//   2. 启动服务: cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
//   3. go run ./examples/go/demo
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/cryptooffload/sdk-go/client"
	pb "github.com/cryptooffload/sdk-go/gen/cryptooffload/v1"
	"github.com/cryptooffload/sdk-go/pool"
)

func main() {
	addr := env("CRYPTO_OFFLOAD_ADDR", "127.0.0.1:50051")
	ctx := context.Background()

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

	// --- 1. ImportKey：一次性导入，服务端解析 PEM 并缓存 PKey ---
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

	// --- 2. Sign：后续仅传 key_id，不再传 PEM ---
	payload := []byte("hello crypto-offload")
	signResp, err := cli.Sign(ctx, &pb.SignRequest{
		KeyId:          keyID,
		Data:           payload,
		HashAlgorithm:  pb.HashAlgorithm_HASH_SHA256,
		SignAlgorithm:  pb.SignAlgorithm_SIGN_RSA_PKCS1_V15,
	})
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}
	fmt.Printf("[Sign] signature_len=%d\n", len(signResp.GetSignature()))

	// --- 3. 导入公钥并 Verify ---
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

	// --- 4. CMS Build / Verify ---
	cmsResp, err := cli.BuildCMS(ctx, &pb.BuildCmsRequest{
		Content:    payload,
		SignKeyId:  keyID,
		Detached:   false,
	})
	if err != nil {
		log.Fatalf("BuildCMS: %v", err)
	}
	fmt.Printf("[BuildCMS] cms_len=%d\n", len(cmsResp.GetCmsDer()))

	cmsVerify, err := cli.VerifyCMS(ctx, &pb.VerifyCmsRequest{
		CmsDer:       cmsResp.GetCmsDer(),
		VerifyKeyId:  pubImported.GetMetadata().GetKeyId(),
	})
	if err != nil {
		log.Fatalf("VerifyCMS: %v", err)
	}
	fmt.Printf("[VerifyCMS] valid=%v\n", cmsVerify.GetValid())

	// --- 5. 临时密钥：首次 Sign 后自动销毁 ---
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
