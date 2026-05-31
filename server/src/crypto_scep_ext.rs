//! ScepExtService 业务逻辑：自定义 SCEP 协议扩展。

use anyhow::{anyhow, Result};

use crate::key_store::KeyAccess;
use crate::scep_cert_alias::{self, CertAliasType};
use crate::scep_http;
use crate::scep_pkio;
use crate::scep_signed_attrs::{self, parsed_to_proto};

pub fn parse_signed_attributes(pkcs7_der: &[u8]) -> Result<crate::pb::ScepSignedAttributes> {
    crate::openssl_init::init();
    let parsed = scep_signed_attrs::parse_from_pkcs7_der(pkcs7_der)?;
    Ok(parsed_to_proto(parsed))
}

pub fn parse_getcert_pkio(
    scep_der: &[u8],
    access: KeyAccess,
) -> Result<crate::pb::ParseGetCertPkioResponse> {
    crate::openssl_init::init();
    let (inner, wrapper_cert_der) = scep_pkio::decrypt_pkio_envelope(scep_der, &access)?;
    let attrs = scep_signed_attrs::parse_from_pkcs7_der(scep_der)?;
    let (alias_type, value) = scep_cert_alias::decode_cert_alias_content(&inner)?;
    let (content_type, alias_or_cn, serial_hex) = match alias_type {
        CertAliasType::Alias | CertAliasType::CommonName => (
            scep_cert_alias::cert_alias_type_to_proto(alias_type),
            value,
            String::new(),
        ),
        CertAliasType::SerialNumber => (
            scep_cert_alias::cert_alias_type_to_proto(alias_type),
            String::new(),
            value,
        ),
    };
    Ok(crate::pb::ParseGetCertPkioResponse {
        attributes: Some(parsed_to_proto(attrs)),
        content_type,
        alias_or_cn,
        serial_number_hex: serial_hex,
        wrapper_cert_der,
        raw_inner_content: inner,
    })
}

pub fn encode_cert_alias_content(content_type: i32, value: &str) -> Result<Vec<u8>> {
    let t = scep_cert_alias::cert_alias_type_from_proto(content_type)?;
    scep_cert_alias::encode_cert_alias_content(t, value)
}

pub fn decode_cert_alias_content(content_der: &[u8]) -> Result<(i32, String, String)> {
    let (t, v) = scep_cert_alias::decode_cert_alias_content(content_der)?;
    match t {
        CertAliasType::SerialNumber => Ok((
            scep_cert_alias::cert_alias_type_to_proto(t),
            String::new(),
            v,
        )),
        _ => Ok((scep_cert_alias::cert_alias_type_to_proto(t), v, String::new())),
    }
}

pub fn encode_http_query(operation: i32, message: &str, dir_name: &str) -> Result<String> {
    let op = scep_http::http_operation_from_proto(operation)?;
    Ok(scep_http::encode_http_query(op, message, dir_name))
}

pub fn verify_response_mime(operation: i32, content_type: &str) -> Result<bool> {
    let op = scep_http::http_operation_from_proto(operation)?;
    Ok(scep_http::verify_response_mime(op, content_type))
}

pub fn expected_mime(operation: i32) -> Result<String> {
    let op = scep_http::http_operation_from_proto(operation)?;
    Ok(scep_http::expected_mime(op).to_string())
}

pub fn validate_ext_field_len(field: &str, max: usize) -> Result<()> {
    if field.len() > max {
        Err(anyhow!("field too large"))
    } else {
        Ok(())
    }
}
