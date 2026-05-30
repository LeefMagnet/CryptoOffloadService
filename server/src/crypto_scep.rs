//! SCEP PKIO 解析与 CertRep 构建（RFC 8894）。

use anyhow::{anyhow, Context, Result};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;

use crate::key_store::{ca_private_with_cert, KeyAccess};
use crate::scep_certrep::{
    build_failure_certrep as build_failure_certrep_der,
    build_success_certrep as build_success_certrep_der,
    ScepFailureParams, ScepSuccessParams,
};

pub fn parse_request(scep_der: &[u8], access: KeyAccess) -> Result<(Vec<u8>, Vec<u8>)> {
    if scep_der.is_empty() {
        anyhow::bail!("scep_der must not be empty");
    }
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let (ca_key, ca_cert) = ca_private_with_cert(material)?;

    let outer = Pkcs7::from_der(scep_der).context("invalid outer PKCS7")?;
    let wrapper_cert_der = first_cert_der(&outer).context("failed to extract wrapper cert")?;
    let enveloped_der =
        extract_signed_content(&outer).context("failed to verify outer signed data")?;

    let inner =
        Pkcs7::from_der(&enveloped_der).context("inner content is not PKCS7 envelopedData")?;
    let csr_der = inner
        .decrypt(&ca_key, &ca_cert, Pkcs7Flags::empty())
        .context("failed to decrypt inner PKCS7 by CA key")?;
    Ok((csr_der, wrapper_cert_der))
}

pub fn build_success_certrep(
    access: KeyAccess,
    transaction_id: &str,
    recipient_nonce: &[u8],
    sender_nonce: &[u8],
    issued_cert_der: &[u8],
    wrapper_cert_der: &[u8],
) -> Result<Vec<u8>> {
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

fn first_cert_der(pkcs7: &Pkcs7) -> Result<Vec<u8>> {
    let signed = pkcs7
        .signed()
        .ok_or_else(|| anyhow!("PKCS7 is not signedData"))?;
    let certs = signed
        .certificates()
        .ok_or_else(|| anyhow!("signedData does not contain certificate"))?;
    let cert = certs
        .get(0)
        .ok_or_else(|| anyhow!("signedData certificate stack is empty"))?;
    cert.to_der().context("failed to encode wrapper cert DER")
}

fn extract_signed_content(pkcs7: &Pkcs7) -> Result<Vec<u8>> {
    let certs = Stack::new().context("failed to create verify cert stack")?;
    let store = X509StoreBuilder::new()
        .context("failed to create x509 store builder")?
        .build();
    let mut out = Vec::new();
    pkcs7
        .verify(
            &certs,
            &store,
            None,
            Some(&mut out),
            Pkcs7Flags::NOVERIFY | Pkcs7Flags::NOCHAIN,
        )
        .context("failed to verify and extract attached signed content")?;
    Ok(out)
}
