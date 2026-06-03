//! SCEP PKIO 公共解析：外层 SignedData 验签提取 + EnvelopedData 解密。

use anyhow::{anyhow, Context, Result};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;

use crate::key_store::{ca_private_with_cert, KeyAccess};

/// 解密 PKIO EnvelopedData，返回 `(内层明文, wrapper_cert_der)`。
///
/// `challenge_password`：内层为 CMS `PasswordRecipientInfo` 时必填（RFC 8894 §3.1）。
pub fn decrypt_pkio_envelope(
    scep_der: &[u8],
    access: &KeyAccess,
    challenge_password: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if scep_der.is_empty() {
        anyhow::bail!("scep_der must not be empty");
    }

    let outer = Pkcs7::from_der(scep_der).context("invalid outer PKCS7")?;
    let wrapper_cert_der = first_cert_der(&outer).context("failed to extract wrapper cert")?;
    let enveloped_der =
        extract_signed_content(&outer).context("failed to verify outer signed data")?;

    let plain = if crate::scep_password_envelope::enveloped_uses_password_recipient(&enveloped_der)?
    {
        let pw = challenge_password
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "challenge_password is required when EnvelopedData uses PasswordRecipientInfo"
                )
            })?;
        crate::scep_password_envelope::decrypt_envelope_password(&enveloped_der, pw)
            .context("failed to decrypt PasswordRecipientInfo envelope")?
    } else {
        let material = match access {
            KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
        };
        let (ca_key, ca_cert) = ca_private_with_cert(material)?;
        let inner =
            Pkcs7::from_der(&enveloped_der).context("inner content is not PKCS7 envelopedData")?;
        inner
            .decrypt(&ca_key, &ca_cert, Pkcs7Flags::empty())
            .context("failed to decrypt inner PKCS7 by CA RSA key")?
    };
    Ok((plain, wrapper_cert_der))
}

pub fn first_cert_der(pkcs7: &Pkcs7) -> Result<Vec<u8>> {
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

pub fn extract_signed_content(pkcs7: &Pkcs7) -> Result<Vec<u8>> {
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
