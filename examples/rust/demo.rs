//! CryptoOffload Rust SDK 完整接入示例。
//!
//! ```bash
//! cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051   # 终端 1
//! cargo run --example demo --manifest-path examples/rust/Cargo.toml  # 终端 2
//! ```

use anyhow::{Context, Result};
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
