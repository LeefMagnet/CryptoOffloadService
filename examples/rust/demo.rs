//! CryptoOffload Rust SDK 完整接入示例。
//!
//! ```bash
//! cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051   # 终端 1
//! cargo run --example demo --manifest-path examples/rust/Cargo.toml  # 终端 2
//! ```

use anyhow::{Context, Result};
use base64::Engine as _;
use cryptooffload_sdk::pb::v1::*;
use cryptooffload_sdk::{Client, PoolConfig};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::var("CRYPTO_OFFLOAD_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".into());

    let client = Client::connect(PoolConfig {
        address: addr,
        min_idle: 2,
        max_open: 8,
        ..Default::default()
    })
    .await?;

    let (priv_pem, cert_pem) = generate_rsa2048_pem()?;
    let payload = b"hello crypto-offload".to_vec();

    // 1. ImportKey
    let imported = client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem.clone(),
            label: "demo-signing-key".into(),
            certificate_data: cert_pem,
            certificate_format: KeyFormat::Pem as i32,
        })
        .await?;
    let meta = imported.metadata.context("metadata")?;
    println!(
        "[ImportKey] key_id={} algorithm={}",
        meta.key_id, meta.algorithm
    );

    // 2. Sign
    let sig = client
        .sign(SignRequest {
            key_id: meta.key_id.clone(),
            data: payload.clone(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?;
    println!("[Sign] signature_len={}", sig.signature.len());

    // 3. Verify
    let pub_pem = extract_public_pem(&priv_pem)?;
    let pub_imported = client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Public as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: pub_pem,
            ..Default::default()
        })
        .await?;
    let pub_id = pub_imported.metadata.context("pub metadata")?.key_id;
    let verified = client
        .verify(VerifyRequest {
            key_id: pub_id.clone(),
            data: payload.clone(),
            signature: sig.signature,
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?;
    println!("[Verify] valid={}", verified.valid);

    // 4. CMS
    let cms = client
        .build_cms(BuildCmsRequest {
            content: payload.clone(),
            sign_key_id: meta.key_id.clone(),
            detached: false,
            ..Default::default()
        })
        .await?;
    println!("[BuildCMS] cms_len={}", cms.cms_der.len());
    let cms_ok = client
        .verify_cms(VerifyCmsRequest {
            cms_der: cms.cms_der,
            verify_key_id: pub_id,
            ..Default::default()
        })
        .await?;
    println!("[VerifyCMS] valid={}", cms_ok.valid);

    // 5. CMP ParseAndVerify（按环境变量启用）
    demo_cmp_parse_and_verify(&client, &meta.key_id).await?;

    // 6. SCEP 正向用例（来自 Rust 单测语义，按环境变量启用）
    demo_scep_positive_cases(&client, &meta.key_id).await?;

    Ok(())
}

/// CMP 单次 RPC Parse + Verify 演示。
///
/// 环境变量：
/// - CMP_PKI_MESSAGE_DER_B64（必填，开启演示）
/// - CMP_VERIFY_KEY_ID（可选，默认 fallback 到 fallback_verify_key_id）
async fn demo_cmp_parse_and_verify(client: &Client, fallback_verify_key_id: &str) -> Result<()> {
    let msg_b64 = match std::env::var("CMP_PKI_MESSAGE_DER_B64") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!("[CMP] skip: set CMP_PKI_MESSAGE_DER_B64 to run ParseAndVerify example");
            return Ok(());
        }
    };
    let pki_message_der = base64::engine::general_purpose::STANDARD
        .decode(msg_b64)
        .context("decode CMP_PKI_MESSAGE_DER_B64")?;
    let verify_key_id =
        std::env::var("CMP_VERIFY_KEY_ID").unwrap_or_else(|_| fallback_verify_key_id.into());
    if std::env::var("CMP_VERIFY_KEY_ID").is_err() {
        println!(
            "[CMP] warning: CMP_VERIFY_KEY_ID not set, fallback to key_id={}",
            verify_key_id
        );
    }
    let resp = client
        .parse_and_verify_cmp_pki_message(ParseAndVerifyCmpPkiMessageRequest {
            pki_message_der,
            verify_key_id,
            ..Default::default()
        })
        .await?;
    println!(
        "[CMP ParseAndVerify] valid={} body_type={} tx_len={} recip_nonce_len={}",
        resp.valid,
        resp.body_type,
        resp.transaction_id.len(),
        resp.recipient_nonce.len()
    );
    Ok(())
}

/// 对齐 server/tests/scep_tests.rs 的正向场景：
/// 1) ParseEnrollPkio（支持 challenge_password）
/// 2) BuildScepSuccessCertRep（challenge_password 非空时走 PasswordRecipientInfo）
///
/// 通过环境变量注入样本，避免在仓库中硬编码业务证书：
/// - SCEP_ENROLL_PKIO_B64（必填，开启演示）
/// - SCEP_CA_KEY_ID（可选，推荐显式指定；必须是该 PKIO 对应 CA 私钥）
/// - SCEP_CHALLENGE_PASSWORD（可选，PasswordRecipientInfo 时必填）
/// - SCEP_ISSUED_CERT_DER_B64（可选，若提供则继续演示 BuildSuccessCertRep）
async fn demo_scep_positive_cases(client: &Client, fallback_ca_key_id: &str) -> Result<()> {
    let pkio_b64 = match std::env::var("SCEP_ENROLL_PKIO_B64") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!("[SCEP] skip: set SCEP_ENROLL_PKIO_B64 to run positive Parse/Build examples");
            return Ok(());
        }
    };
    let pkio_der = base64::engine::general_purpose::STANDARD
        .decode(pkio_b64)
        .context("decode SCEP_ENROLL_PKIO_B64")?;

    let ca_key_id = std::env::var("SCEP_CA_KEY_ID").unwrap_or_else(|_| fallback_ca_key_id.into());
    if std::env::var("SCEP_CA_KEY_ID").is_err() {
        println!(
            "[SCEP] warning: SCEP_CA_KEY_ID not set, fallback to key_id={} (may fail if not CA key)",
            ca_key_id
        );
    }
    let challenge_password = std::env::var("SCEP_CHALLENGE_PASSWORD").unwrap_or_default();

    let parsed = client
        .parse_enroll_pkio(ParseEnrollPkioRequest {
            scep_der: pkio_der,
            ca_key_id: ca_key_id.clone(),
            challenge_password: challenge_password.clone(),
        })
        .await?;
    let tx = parsed
        .attributes
        .as_ref()
        .map(|a| a.transaction_id.clone())
        .unwrap_or_default();
    println!(
        "[SCEP ParseEnrollPkio] csr_len={} wrapper_len={} tx={}",
        parsed.csr_der.len(),
        parsed.wrapper_cert_der.len(),
        tx
    );

    let issued_b64 = match std::env::var("SCEP_ISSUED_CERT_DER_B64") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!("[SCEP] skip BuildScepSuccessCertRep: set SCEP_ISSUED_CERT_DER_B64");
            return Ok(());
        }
    };
    let issued_der = base64::engine::general_purpose::STANDARD
        .decode(issued_b64)
        .context("decode SCEP_ISSUED_CERT_DER_B64")?;

    let attrs = parsed.attributes.unwrap_or_default();
    let tx_id = if attrs.transaction_id.is_empty() {
        "tx-from-example-positive".to_string()
    } else {
        attrs.transaction_id
    };
    let recipient_nonce = if attrs.sender_nonce.is_empty() {
        vec![0x11, 0x22, 0x33, 0x44]
    } else {
        attrs.sender_nonce
    };
    let wrapper_cert_der = if challenge_password.is_empty() {
        parsed.wrapper_cert_der
    } else {
        // PasswordRecipientInfo 模式下 wrapper_cert_der 可省略。
        Vec::new()
    };

    let rep = client
        .build_scep_success_cert_rep(BuildScepSuccessCertRepRequest {
            ca_key_id: ca_key_id.clone(),
            transaction_id: tx_id,
            recipient_nonce,
            sender_nonce: Vec::new(),
            issued_cert_der: issued_der,
            wrapper_cert_der,
            envelope_cipher: ScepEnvelopeCipher::ScepEnvelopeCipherAes128Cbc as i32,
            challenge_password,
        })
        .await?;
    println!("[SCEP BuildSuccessCertRep] certrep_len={}", rep.certrep_der.len());
    Ok(())
}

fn generate_rsa2048_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    let priv_pem = pkey.private_key_to_pem_pkcs8()?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "demo")?;
    let name = name.build();
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert_pem = builder.build().to_pem()?;
    Ok((priv_pem, cert_pem))
}

fn extract_public_pem(private_pem: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pem(private_pem)?;
    Ok(pkey.public_key_to_pem()?)
}
