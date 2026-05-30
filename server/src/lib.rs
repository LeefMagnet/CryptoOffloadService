pub mod crypto_cms;
pub mod crypto_scep;
pub mod crypto_sign;
pub mod key_store;
pub mod openssl_init;
pub mod scep_certrep;
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

use services::{AppState, CmsServiceImpl, KeyServiceImpl, ScepServiceImpl, SignServiceImpl};
use tonic::transport::Server;

use crate::cryptooffload::v1::cms_service_server::CmsServiceServer;
use crate::cryptooffload::v1::key_service_server::KeyServiceServer;
use crate::cryptooffload::v1::scep_service_server::ScepServiceServer;
use crate::cryptooffload::v1::sign_service_server::SignServiceServer;
use crate::key_store::KeyStore;

pub async fn run_server(listen: SocketAddr) -> anyhow::Result<()> {
    openssl_init::init();

    let state = Arc::new(AppState {
        keys: KeyStore::new(),
    });

    let key_svc = KeyServiceImpl::new(state.clone());
    let sign_svc = SignServiceImpl::new(state.clone());
    let cms_svc = CmsServiceImpl::new(state.clone());
    let scep_svc = ScepServiceImpl::new(state);

    Server::builder()
        .add_service(KeyServiceServer::new(key_svc))
        .add_service(SignServiceServer::new(sign_svc))
        .add_service(CmsServiceServer::new(cms_svc))
        .add_service(ScepServiceServer::new(scep_svc))
        .serve(listen)
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

    pub fn free_port() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr")
    }
}
