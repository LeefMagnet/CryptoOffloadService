use anyhow::{bail, Context, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};

use crate::key_store::{ensure_private, ensure_public, hash_algorithm_to_md, infer_sign_algorithm, KeyAccess, KeyMaterial};
use crate::pb::{HashAlgorithm, SignAlgorithm};

pub struct SignOutput {
    pub signature: Vec<u8>,
    pub hash_algorithm: i32,
    pub sign_algorithm: i32,
}

pub fn sign(
    access: KeyAccess,
    data: &[u8],
    hash_algorithm: i32,
    sign_algorithm: i32,
) -> Result<SignOutput> {
    if data.is_empty() {
        bail!("data must not be empty");
    }
    let material = match access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let private = ensure_private(&material)?;
    let md = hash_algorithm_to_md(hash_algorithm)?;
    let sign_alg = infer_sign_algorithm(&material, sign_algorithm)?;

    let signature = match sign_alg {
        SignAlgorithm::SignRsaPkcs1V15 => sign_rsa_pkcs1_v15(private, data, md)?,
        SignAlgorithm::SignRsaPss => sign_rsa_pss(private, data, md)?,
        SignAlgorithm::SignEcdsa => sign_ecdsa(private, data, md)?,
        SignAlgorithm::Unspecified => unreachable!(),
    };

    Ok(SignOutput {
        signature,
        hash_algorithm: hash_algorithm,
        sign_algorithm: sign_alg as i32,
    })
}

pub fn verify(
    access: KeyAccess,
    data: &[u8],
    signature: &[u8],
    hash_algorithm: i32,
    sign_algorithm: i32,
) -> Result<bool> {
    if data.is_empty() {
        bail!("data must not be empty");
    }
    if signature.is_empty() {
        bail!("signature must not be empty");
    }
    let material = match access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => m,
    };
    let public = ensure_public(&material)?;
    let md = hash_algorithm_to_md(hash_algorithm)?;
    let sign_alg = infer_sign_algorithm(&material, sign_algorithm)?;

    match sign_alg {
        SignAlgorithm::SignRsaPkcs1V15 => verify_rsa_pkcs1_v15(public, data, signature, md),
        SignAlgorithm::SignRsaPss => verify_rsa_pss(public, data, signature, md),
        SignAlgorithm::SignEcdsa => verify_ecdsa(public, data, signature, md),
        SignAlgorithm::Unspecified => unreachable!(),
    }
}

fn sign_rsa_pkcs1_v15(key: &PKey<openssl::pkey::Private>, data: &[u8], md: MessageDigest) -> Result<Vec<u8>> {
    let mut signer = Signer::new(md, key).context("create RSA PKCS#1 signer")?;
    signer.update(data).context("signer update")?;
    signer.sign_to_vec().context("RSA PKCS#1 sign")
}

fn sign_rsa_pss(key: &PKey<openssl::pkey::Private>, data: &[u8], md: MessageDigest) -> Result<Vec<u8>> {
    let mut signer = Signer::new(md, key).context("create RSA-PSS signer")?;
    signer.set_rsa_padding(Padding::PKCS1_PSS)?;
    signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
    signer.update(data).context("signer update")?;
    signer.sign_to_vec().context("RSA-PSS sign")
}

fn sign_ecdsa(key: &PKey<openssl::pkey::Private>, data: &[u8], md: MessageDigest) -> Result<Vec<u8>> {
    let mut signer = Signer::new(md, key).context("create ECDSA signer")?;
    signer.update(data).context("signer update")?;
    signer.sign_to_vec().context("ECDSA sign")
}

fn verify_rsa_pkcs1_v15(
    key: &PKey<openssl::pkey::Public>,
    data: &[u8],
    signature: &[u8],
    md: MessageDigest,
) -> Result<bool> {
    let mut verifier = Verifier::new(md, key).context("create RSA PKCS#1 verifier")?;
    verifier.update(data).context("verifier update")?;
    Ok(verifier.verify(signature).context("RSA PKCS#1 verify")?)
}

fn verify_rsa_pss(
    key: &PKey<openssl::pkey::Public>,
    data: &[u8],
    signature: &[u8],
    md: MessageDigest,
) -> Result<bool> {
    let mut verifier = Verifier::new(md, key).context("create RSA-PSS verifier")?;
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
    verifier.update(data).context("verifier update")?;
    Ok(verifier.verify(signature).context("RSA-PSS verify")?)
}

fn verify_ecdsa(
    key: &PKey<openssl::pkey::Public>,
    data: &[u8],
    signature: &[u8],
    md: MessageDigest,
) -> Result<bool> {
    let mut verifier = Verifier::new(md, key).context("create ECDSA verifier")?;
    verifier.update(data).context("verifier update")?;
    Ok(verifier.verify(signature).context("ECDSA verify")?)
}
