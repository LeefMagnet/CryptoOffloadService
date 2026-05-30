use anyhow::{bail, Context, Result};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;

use crate::key_store::{ensure_private, signing_cert, KeyAccess, KeyMaterial};

pub fn parse_cms(cms_der: &[u8], access: Option<KeyAccess>) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if cms_der.is_empty() {
        bail!("cms_der must not be empty");
    }
    let pkcs7 = Pkcs7::from_der(cms_der).context("parse CMS/PKCS#7")?;

    if let Some(access) = access {
        let material = match &access {
            KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
        };
        let private = ensure_private(material)?;
        let cert = pairing_cert(material)?;
        let content = pkcs7
            .decrypt(private, &cert, Pkcs7Flags::empty())
            .context("CMS decrypt (EnvelopedData)")?;
        return Ok((content, collect_signer_certs(&pkcs7)?));
    }

    let mut content = Vec::new();
    let store = X509StoreBuilder::new()
        .context("create cert store")?
        .build();
    let empty_certs = Stack::new().context("create cert stack")?;
    pkcs7
        .verify(
            &empty_certs,
            &store,
            None,
            Some(&mut content),
            Pkcs7Flags::NOVERIFY,
        )
        .context("CMS parse/extract content")?;
    Ok((content, collect_signer_certs(&pkcs7)?))
}

pub fn build_cms(
    content: &[u8],
    access: KeyAccess,
    detached: bool,
    extra_certificates: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if content.is_empty() {
        bail!("content must not be empty");
    }
    let material = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let private = ensure_private(material)?;
    let cert = signing_cert(material)?;

    let mut certs = Stack::new().context("create cert stack")?;
    certs.push(cert.clone()).context("push signer cert")?;
    for der in extra_certificates {
        let x = X509::from_der(der).context("parse extra certificate DER")?;
        certs.push(x).context("push extra cert")?;
    }

    let mut flags = Pkcs7Flags::BINARY;
    if detached {
        flags |= Pkcs7Flags::DETACHED;
    }

    let pkcs7 = Pkcs7::sign(&cert, private, &certs, content, flags)
        .context("CMS sign/build SignedData")?;
    pkcs7.to_der().context("encode CMS DER")
}

pub fn verify_cms(cms_der: &[u8], access: KeyAccess, content: &[u8]) -> Result<bool> {
    if cms_der.is_empty() {
        bail!("cms_der must not be empty");
    }
    let pkcs7 = Pkcs7::from_der(cms_der).context("parse CMS/PKCS#7")?;

    let mut store_builder = X509StoreBuilder::new().context("create cert store")?;
    let mut certs = Stack::new().context("create cert stack")?;
    if let KeyMaterial::Public { cert: Some(cert), .. } = match &access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    } {
        store_builder
            .add_cert(cert.clone())
            .context("add cert to store")?;
        certs.push(cert.clone()).context("push verify cert")?;
    }
    let store = store_builder.build();

    let mut out = Vec::new();
    let indata = if content.is_empty() { None } else { Some(content) };
    let flags = Pkcs7Flags::NOVERIFY;

    pkcs7
        .verify(&certs, &store, indata, Some(&mut out), flags)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

fn pairing_cert(material: &KeyMaterial) -> Result<X509> {
    match material {
        KeyMaterial::Private { cert: Some(cert), .. } => Ok(cert.clone()),
        KeyMaterial::Private { cert: None, .. } => {
            bail!("CMS decrypt requires certificate imported with private key")
        }
        KeyMaterial::Public { .. } => bail!("CMS decrypt requires a private key"),
    }
}

fn collect_signer_certs(pkcs7: &Pkcs7) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if let Some(signed) = pkcs7.signed() {
        if let Some(certs) = signed.certificates() {
            for cert in certs.iter() {
                out.push(cert.to_der().context("encode signer cert")?);
            }
        }
    }
    Ok(out)
}
