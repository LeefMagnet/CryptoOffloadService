pub mod crypto_cms;
pub mod crypto_scep;
pub mod crypto_scep_ext;
pub mod crypto_sign;
pub mod key_store;
pub mod openssl_init;
pub mod scep_cert_alias;
pub mod scep_certrep;
pub mod scep_envelope;
pub mod scep_pkio;
pub mod scep_signed_attrs;
mod service_errors;
mod service_validators;
pub mod services;

pub mod cryptooffload {
    pub mod v1 {
        tonic::include_proto!("cryptooffload.v1");
    }
}

/// Protobuf 生成类型统一入口。
pub mod pb {
    pub use crate::cryptooffload::v1::*;
}

use std::net::SocketAddr;
use std::sync::Arc;

use services::{
    AppState, CmsServiceImpl, KeyServiceImpl, ScepExtServiceImpl, ScepServiceImpl, SignServiceImpl,
};
use tonic::transport::Server;

use crate::cryptooffload::v1::cms_service_server::CmsServiceServer;
use crate::cryptooffload::v1::key_service_server::KeyServiceServer;
use crate::cryptooffload::v1::scep_ext_service_server::ScepExtServiceServer;
use crate::cryptooffload::v1::scep_service_server::ScepServiceServer;
use crate::cryptooffload::v1::sign_service_server::SignServiceServer;

/// 服务端启动配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// 同时进行 OpenSSL 运算的最大 in-flight 任务数；0 表示按可见 CPU 核数。
    pub crypto_max_inflight: usize,
}

impl ServerConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            crypto_max_inflight: default_crypto_max_inflight(),
        }
    }
}

/// 默认 crypto 并发上限 = 可见逻辑 CPU 核数（与 cpuset 一致）。
pub fn default_crypto_max_inflight() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

pub async fn run_server(listen: SocketAddr) -> anyhow::Result<()> {
    run_server_with_config(ServerConfig::new(listen)).await
}

pub async fn run_server_with_config(config: ServerConfig) -> anyhow::Result<()> {
    openssl_init::init();

    let crypto_max_inflight = if config.crypto_max_inflight > 0 {
        config.crypto_max_inflight
    } else {
        default_crypto_max_inflight()
    };
    tracing::info!(
        listen = %config.listen,
        crypto_max_inflight,
        "crypto-offload-server starting"
    );

    let state = Arc::new(AppState::new(crypto_max_inflight));

    let key_svc = KeyServiceImpl::new(state.clone());
    let sign_svc = SignServiceImpl::new(state.clone());
    let cms_svc = CmsServiceImpl::new(state.clone());
    let scep_svc = ScepServiceImpl::new(state.clone());
    let scep_ext_svc = ScepExtServiceImpl::new(state);

    Server::builder()
        .add_service(KeyServiceServer::new(key_svc))
        .add_service(SignServiceServer::new(sign_svc))
        .add_service(CmsServiceServer::new(cms_svc))
        .add_service(ScepServiceServer::new(scep_svc))
        .add_service(ScepExtServiceServer::new(scep_ext_svc))
        .serve(config.listen)
        .await?;

    Ok(())
}

pub mod test_support {
    use std::net::SocketAddr;

    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509Builder, X509NameBuilder};

    pub fn generate_rsa2048_pem() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        let priv_pem = pkey.private_key_to_pem_pkcs8()?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "test")?;
        let name = name.build();

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();
        let cert_pem = cert.to_pem()?;
        Ok((priv_pem, cert_pem))
    }

    pub fn generate_rsa2048_der_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let (priv_pem, cert_pem) = generate_rsa2048_pem()?;
        let cert_der = X509::from_pem(&cert_pem)?.to_der()?;
        Ok((priv_pem, cert_der))
    }

    /// 生成 SM2 密钥对 + 自签证书（需 OpenSSL 支持 SM2/SM3）。
    pub fn generate_sm2_pem() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::SM2)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;
        let priv_pem = pkey.private_key_to_pem_pkcs8()?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "sm2-test")?;
        let name = name.build();

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.sign(&pkey, MessageDigest::sm3())?;
        let cert = builder.build();
        let cert_pem = cert.to_pem()?;
        Ok((priv_pem, cert_pem))
    }

    pub fn generate_ec256_pem() -> anyhow::Result<Vec<u8>> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;
        Ok(pkey.private_key_to_pem_pkcs8()?)
    }

    pub fn generate_ed25519_pem() -> anyhow::Result<Vec<u8>> {
        let pkey = PKey::generate_ed25519()?;
        Ok(pkey.private_key_to_pem_pkcs8()?)
    }

    pub fn extract_public_pem(private_pem: &[u8]) -> anyhow::Result<Vec<u8>> {
        let pkey = PKey::private_key_from_pem(private_pem)?;
        Ok(pkey.public_key_to_pem()?)
    }

    /// 生成 SCEP PKIO 测试报文：外层 SignedData（wrapper 签名）+ 内层 EnvelopedData（3DES，CA 解密）。
    /// 返回 `(pkio_der, csr_der, wrapper_cert_der)`。
    pub fn generate_scep_pkio(ca_cert: &X509) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        crate::openssl_init::init();
        use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
        use openssl::stack::Stack;
        use openssl::symm::Cipher;
        use openssl::x509::X509Req;

        let wrapper_key = {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)?
        };
        let wrapper_cert = {
            let mut name = X509NameBuilder::new()?;
            name.append_entry_by_text("CN", "scep-bench-wrapper")?;
            let name = name.build();
            let mut builder = X509Builder::new()?;
            builder.set_version(2)?;
            builder.set_subject_name(&name)?;
            builder.set_issuer_name(&name)?;
            builder.set_pubkey(&wrapper_key)?;
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(365)?;
            builder.set_not_before(&not_before)?;
            builder.set_not_after(&not_after)?;
            builder.sign(&wrapper_key, MessageDigest::sha256())?;
            builder.build()
        };

        let csr_der = {
            let client_key = {
                let rsa = Rsa::generate(2048)?;
                PKey::from_rsa(rsa)?
            };
            let mut name = X509NameBuilder::new()?;
            name.append_entry_by_text("CN", "scep-bench-client")?;
            let name = name.build();
            let mut req_builder = X509Req::builder()?;
            req_builder.set_subject_name(&name)?;
            req_builder.set_pubkey(&client_key)?;
            req_builder.sign(&client_key, MessageDigest::sha256())?;
            req_builder.build().to_der()?
        };

        let mut recipients = Stack::new()?;
        recipients.push(ca_cert.clone())?;
        let enveloped = Pkcs7::encrypt(
            &recipients,
            &csr_der,
            Cipher::des_ede3_cbc(),
            Pkcs7Flags::BINARY,
        )?;
        let enveloped_der = enveloped.to_der()?;

        let certs = Stack::new()?;
        let outer = Pkcs7::sign(
            &wrapper_cert,
            &wrapper_key,
            &certs,
            &enveloped_der,
            Pkcs7Flags::BINARY,
        )?;
        let pkio_der = outer.to_der()?;
        let wrapper_cert_der = wrapper_cert.to_der()?;
        Ok((pkio_der, csr_der, wrapper_cert_der))
    }

    /// GetCert 类 PKIO：内层为 CertAliasOrCn（alias），结构同 PKIO。
    pub fn generate_getcert_pkio(
        ca_cert: &X509,
        alias: &str,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        crate::openssl_init::init();
        use crate::scep_cert_alias::{encode_cert_alias_content, CertAliasType};
        use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
        use openssl::stack::Stack;
        use openssl::symm::Cipher;

        let inner_der = encode_cert_alias_content(CertAliasType::Alias, alias)?;

        let wrapper_key = {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)?
        };
        let wrapper_cert = {
            let mut name = X509NameBuilder::new()?;
            name.append_entry_by_text("CN", "scep-getcert-wrapper")?;
            let name = name.build();
            let mut builder = X509Builder::new()?;
            builder.set_version(2)?;
            builder.set_subject_name(&name)?;
            builder.set_issuer_name(&name)?;
            builder.set_pubkey(&wrapper_key)?;
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(365)?;
            builder.set_not_before(&not_before)?;
            builder.set_not_after(&not_after)?;
            builder.sign(&wrapper_key, MessageDigest::sha256())?;
            builder.build()
        };

        let mut recipients = Stack::new()?;
        recipients.push(ca_cert.clone())?;
        let enveloped = Pkcs7::encrypt(
            &recipients,
            &inner_der,
            Cipher::des_ede3_cbc(),
            Pkcs7Flags::BINARY,
        )?;
        let enveloped_der = enveloped.to_der()?;
        let certs = Stack::new()?;
        let outer = Pkcs7::sign(
            &wrapper_cert,
            &wrapper_key,
            &certs,
            &enveloped_der,
            Pkcs7Flags::BINARY,
        )?;
        let pkio_der = outer.to_der()?;
        let wrapper_cert_der = wrapper_cert.to_der()?;
        Ok((pkio_der, inner_der, wrapper_cert_der))
    }

    pub fn free_port() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr")
    }
}
