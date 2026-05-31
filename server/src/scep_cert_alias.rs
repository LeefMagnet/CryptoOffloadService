//! CertAliasOrCn 与 SerialNumber 内层 content（docs/reference/scep/content_info.*）。

use anyhow::{anyhow, Context, Result};
use openssl::bn::BigNum;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertAliasType {
    Alias,
    CommonName,
    SerialNumber,
}

pub fn encode_cert_alias_content(content_type: CertAliasType, value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        anyhow::bail!("value must not be empty");
    }
    match content_type {
        CertAliasType::Alias => Ok(encode_context_utf8(0, value)),
        CertAliasType::CommonName => Ok(encode_context_utf8(1, value)),
        CertAliasType::SerialNumber => encode_serial_number(value),
    }
}

pub fn decode_cert_alias_content(content_der: &[u8]) -> Result<(CertAliasType, String)> {
    if content_der.is_empty() {
        anyhow::bail!("content_der must not be empty");
    }
    if let Some(s) = decode_context_utf8(content_der, 0)? {
        return Ok((CertAliasType::Alias, s));
    }
    if let Some(s) = decode_context_utf8(content_der, 1)? {
        return Ok((CertAliasType::CommonName, s));
    }
    if let Some(s) = try_decode_serial_number(content_der)? {
        return Ok((CertAliasType::SerialNumber, s));
    }
    Err(anyhow!("unrecognized CertAliasOrCn or SerialNumber DER"))
}

fn encode_context_utf8(choice: u8, value: &str) -> Vec<u8> {
    let utf8 = encode_der_utf8string(value);
    wrap_context_tag(choice, &utf8)
}

fn encode_der_utf8string(value: &str) -> Vec<u8> {
    let b = value.as_bytes();
    let mut out = Vec::with_capacity(2 + b.len());
    out.push(0x0c);
    out.extend(der_length(b.len()));
    out.extend_from_slice(b);
    out
}

fn wrap_context_tag(choice: u8, inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + inner.len());
    out.push(0xA0 | choice);
    out.extend(der_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n <= 0xff {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn decode_context_utf8(der: &[u8], choice: u8) -> Result<Option<String>> {
    if der.is_empty() {
        return Ok(None);
    }
    let expected_tag = 0xA0 | choice;
    if der[0] != expected_tag {
        return Ok(None);
    }
    let (len, hdr) = parse_der_length(&der[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    if end > der.len() {
        return Ok(None);
    }
    let inner = &der[start..end];
    if inner.first() != Some(&0x0c) {
        return Ok(None);
    }
    let (str_len, str_hdr) = parse_der_length(&inner[1..])?;
    let s0 = 1 + str_hdr;
    let s1 = s0 + str_len;
    if s1 > inner.len() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&inner[s0..s1]).into_owned(),
    ))
}

fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        anyhow::bail!("truncated DER length");
    }
    if bytes[0] & 0x80 == 0 {
        return Ok((bytes[0] as usize, 1));
    }
    let n = (bytes[0] & 0x7f) as usize;
    if n == 0 || bytes.len() < 1 + n {
        anyhow::bail!("invalid DER length");
    }
    let mut len = 0usize;
    for b in &bytes[1..=n] {
        len = (len << 8) | (*b as usize);
    }
    Ok((len, 1 + n))
}

fn encode_serial_number(serial_hex: &str) -> Result<Vec<u8>> {
    let bn = BigNum::from_hex_str(serial_hex).context("invalid serial hex")?;
    let int_der = encode_der_integer(&bn)?;
    Ok(wrap_der_sequence(&int_der))
}

fn encode_der_integer(bn: &BigNum) -> Result<Vec<u8>> {
    let mut bin = bn.to_vec();
    if bin.first().is_some_and(|b| b & 0x80 != 0) {
        bin.insert(0, 0);
    }
    let mut out = vec![0x02];
    out.extend(der_length(bin.len()));
    out.extend_from_slice(&bin);
    Ok(out)
}

fn try_decode_serial_number(der: &[u8]) -> Result<Option<String>> {
    if der.is_empty() || der[0] != 0x30 {
        return Ok(None);
    }
    let (seq_len, hdr) = parse_der_length(&der[1..])?;
    let body = &der[1 + hdr..1 + hdr + seq_len];
    if body.first() != Some(&0x02) {
        return Ok(None);
    }
    let (int_len, int_hdr) = parse_der_length(&body[1..])?;
    let int_bytes = &body[1 + int_hdr..1 + int_hdr + int_len];
    let bn = BigNum::from_slice(int_bytes).context("serial bn")?;
    Ok(Some(bn.to_hex_str()?.to_string()))
}

fn wrap_der_sequence(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + inner.len());
    out.push(0x30);
    out.extend(der_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

pub fn cert_alias_type_from_proto(v: i32) -> Result<CertAliasType> {
    match v {
        1 => Ok(CertAliasType::Alias),
        2 => Ok(CertAliasType::CommonName),
        3 => Ok(CertAliasType::SerialNumber),
        _ => Err(anyhow!("invalid cert alias content type")),
    }
}

pub fn cert_alias_type_to_proto(t: CertAliasType) -> i32 {
    match t {
        CertAliasType::Alias => 1,
        CertAliasType::CommonName => 2,
        CertAliasType::SerialNumber => 3,
    }
}
