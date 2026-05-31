//! SCEP PKIO 解析与 CertRep 构建（RFC 8894）。

use anyhow::{Context, Result};
use openssl::x509::X509;

use crate::key_store::{ca_private_with_cert, KeyAccess};
use crate::scep_certrep::{
    build_failure_certrep as build_failure_certrep_der,
    build_gm_success_certrep as build_gm_success_certrep_der,
    build_pending_certrep as build_pending_certrep_der,
    build_success_certrep as build_success_certrep_der,
    ScepFailureParams, ScepGmSuccessParams, ScepPendingParams, ScepSuccessParams,
};
use crate::scep_pkio;

pub fn parse_request(scep_der: &[u8], access: KeyAccess) -> Result<(Vec<u8>, Vec<u8>)> {
    crate::openssl_init::init();
    if scep_der.is_empty() {
        anyhow::bail!("scep_der must not be empty");
    }
    let (csr_der, wrapper_cert_der) = scep_pkio::decrypt_pkio_envelope(scep_der, &access)?;
    Ok((csr_der, wrapper_cert_der))
}

pub fn build_success_certrep(
    access: KeyAccess,
    transaction_id: &str,
    recipient_nonce: &[u8],
    sender_nonce: &[u8],
    issued_cert_der: &[u8],
    wrapper_cert_der: &[u8],
    envelope_cipher: i32,
) -> Result<Vec<u8>> {
    crate::openssl_init::init();
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let (ca_key, ca_cert) = ca_private_with_cert(material)?;

    let wrapper_cert =
        X509::from_der(wrapper_cert_der).context("invalid wrapper cert DER for response")?;
    let issued_cert =
        X509::from_der(issued_cert_der).context("invalid issued cert DER for response")?;

    build_success_certrep_der(
        &ca_cert,
        &ca_key,
        ScepSuccessParams {
            transaction_id,
            recipient_nonce,
            sender_nonce,
            issued_cert: &issued_cert,
            wrapper_cert: &wrapper_cert,
            ca_cert: &ca_cert,
            envelope_cipher,
        },
    )
}

pub fn build_gm_success_certrep(
    access: KeyAccess,
    transaction_id: &str,
    recipient_nonce: &[u8],
    sender_nonce: &[u8],
    sign_cert_der: &[u8],
    encryption_cert_der: &[u8],
    skf_content: &[u8],
    wrapper_cert_der: &[u8],
    envelope_cipher: i32,
) -> Result<Vec<u8>> {
    crate::openssl_init::init();
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let (ca_key, ca_cert) = ca_private_with_cert(material)?;

    let sign_cert = X509::from_der(sign_cert_der).context("invalid sign cert DER")?;
    let encryption_cert =
        X509::from_der(encryption_cert_der).context("invalid encryption cert DER")?;
    let wrapper_cert =
        X509::from_der(wrapper_cert_der).context("invalid wrapper cert DER for GM response")?;

    build_gm_success_certrep_der(
        &ca_cert,
        &ca_key,
        ScepGmSuccessParams {
            transaction_id,
            recipient_nonce,
            sender_nonce,
            sign_cert: &sign_cert,
            encryption_cert: &encryption_cert,
            skf_content,
            wrapper_cert: &wrapper_cert,
            ca_cert: &ca_cert,
            envelope_cipher,
        },
    )
}

pub fn build_failure_certrep(
    access: KeyAccess,
    transaction_id: &str,
    recipient_nonce: &[u8],
    sender_nonce: &[u8],
    fail_info: u8,
    fail_info_text: &str,
) -> Result<Vec<u8>> {
    crate::openssl_init::init();
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let (ca_key, ca_cert) = ca_private_with_cert(material)?;

    build_failure_certrep_der(
        &ca_cert,
        &ca_key,
        ScepFailureParams {
            transaction_id,
            recipient_nonce,
            sender_nonce,
            fail_info,
            fail_info_text,
        },
    )
}

pub fn build_pending_certrep(
    access: KeyAccess,
    transaction_id: &str,
    recipient_nonce: &[u8],
    sender_nonce: &[u8],
) -> Result<Vec<u8>> {
    crate::openssl_init::init();
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let (ca_key, ca_cert) = ca_private_with_cert(material)?;

    build_pending_certrep_der(
        &ca_cert,
        &ca_key,
        ScepPendingParams {
            transaction_id,
            recipient_nonce,
            sender_nonce,
        },
    )
}
