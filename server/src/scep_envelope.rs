//! PKCS#7 EnvelopedData 构建（含 OpenSSL `PKCS7_encrypt` 不支持的 AES-GCM）。

use anyhow::{Context, Result};
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::stack::Stack;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509Ref, X509};

const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_ENVELOPED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 3];
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_AES128_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 6];
const OID_AES256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];

const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// AES-GCM EnvelopedData（与 smallstep/pkcs7 `encryptAESGCM` 结构对齐）。
pub fn encrypt_envelope_aes_gcm(
    recipients: &Stack<X509>,
    plaintext: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>> {
    let (key_len, alg_oid) = match cipher {
        c if c == Cipher::aes_128_gcm() => (16, OID_AES128_GCM),
        c if c == Cipher::aes_256_gcm() => (32, OID_AES256_GCM),
        _ => anyhow::bail!("encrypt_envelope_aes_gcm requires AES-128-GCM or AES-256-GCM"),
    };

    let mut key = vec![0u8; key_len];
    rand_bytes(&mut key).context("generate content encryption key")?;
    let mut nonce = [0u8; GCM_NONCE_LEN];
    rand_bytes(&mut nonce).context("generate GCM nonce")?;

    let mut tag = [0u8; GCM_TAG_LEN];
    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut crypter =
        Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce)).context("Crypter::new AES-GCM")?;
    crypter.pad(false);
    let count1 = crypter
        .update(plaintext, &mut ciphertext)
        .context("GCM encrypt update")?;
    let count2 = crypter
        .finalize(&mut ciphertext[count1..])
        .context("GCM encrypt finalize")?;
    crypter.get_tag(&mut tag).context("GCM get tag")?;
    ciphertext.truncate(count1 + count2);
    ciphertext.extend_from_slice(&tag);

    let gcm_params = der_sequence(&[
        &der_explicit_octet_string(4, &nonce),
        &der_integer(GCM_TAG_LEN as i64),
    ]);
    let enc_content_info = der_sequence(&[
        &der_oid(OID_DATA),
        &der_algorithm_identifier(alg_oid, &gcm_params),
        &der_context_octet_string(0, &ciphertext),
    ]);

    let mut recipient_infos = Vec::new();
    for i in 0..recipients.len() {
        let cert = recipients.get(i).context("recipient cert")?;
        let encrypted_key = rsa_pkcs1_encrypt_content_key(cert, &key)?;
        let issuer_serial = issuer_and_serial_der(cert)?;
        let recipient = der_sequence(&[
            &der_integer(0),
            &issuer_serial,
            &der_algorithm_identifier(OID_RSA_ENCRYPTION, &[]),
            &der_octet_string(&encrypted_key),
        ]);
        recipient_infos.push(recipient);
    }
    let recipient_set = der_set(&recipient_infos);

    let enveloped_data = der_sequence(&[&der_integer(0), &recipient_set, &enc_content_info]);
    let content = der_explicit(0, &enveloped_data);
    let content_info = der_sequence(&[&der_oid(OID_ENVELOPED_DATA), &content]);
    Ok(content_info)
}

fn rsa_pkcs1_encrypt_content_key(cert: &X509Ref, key: &[u8]) -> Result<Vec<u8>> {
    let rsa = cert
        .public_key()
        .context("recipient public key")?
        .rsa()
        .context("recipient RSA key")?;
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa
        .public_encrypt(key, &mut buf, Padding::PKCS1)
        .context("RSA encrypt content key")?;
    buf.truncate(len);
    Ok(buf)
}

fn issuer_and_serial_der(cert: &X509Ref) -> Result<Vec<u8>> {
    let issuer = cert.issuer_name().to_der().context("issuer DER")?;
    let serial = cert
        .serial_number()
        .to_bn()
        .context("serial to bn")?
        .to_vec();
    Ok(der_sequence(&[&issuer, &der_integer_bytes(&serial)]))
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + content.len());
    out.push(tag);
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    der_wrap(0x30, &body)
}

fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    der_wrap(0x31, &body)
}

fn der_oid(components: &[u64]) -> Vec<u8> {
    assert!(components.len() >= 2);
    let mut body = vec![(40 * components[0] + components[1]) as u8];
    for &c in &components[2..] {
        body.extend(encode_base128(c));
    }
    der_wrap(0x06, &body)
}

fn encode_base128(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut rev = Vec::new();
    while value > 0 {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if !rev.is_empty() {
            byte |= 0x80;
        }
        rev.push(byte);
    }
    rev.reverse();
    rev
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_wrap(0x04, data)
}

fn der_context_octet_string(tag: u8, data: &[u8]) -> Vec<u8> {
    der_wrap(0xa0 | tag, data)
}

fn der_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    der_wrap(0xa0 | tag, content)
}

fn der_explicit_octet_string(tag: u8, data: &[u8]) -> Vec<u8> {
    der_wrap(0xa0 | tag, &der_octet_string(data))
}

fn der_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return der_wrap(0x02, &[0]);
    }
    let mut v = value;
    let mut bytes = Vec::new();
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    bytes.reverse();
    der_integer_bytes(&bytes)
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        v.remove(0);
    }
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    der_wrap(0x02, &v)
}

fn der_algorithm_identifier(oid: &[u64], params: &[u8]) -> Vec<u8> {
    if params.is_empty() {
        der_sequence(&[&der_oid(oid), &der_null()])
    } else {
        der_sequence(&[&der_oid(oid), params])
    }
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}
