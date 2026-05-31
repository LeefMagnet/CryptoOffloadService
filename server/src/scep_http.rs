//! SCEP HTTP query 与 Content-Type 辅助（docs/reference/scep/request_message.*, response_message.*）。

use anyhow::{anyhow, Result};

const MIME_GET_CA: &str = "application/x-x509-ca-cert";
const MIME_GET_CA_RA: &str = "application/x-x509-ca-ra-cert";
const MIME_GET_NEXT_CA: &str = "application/x-x509-next-ca-cert";
const MIME_PKI: &str = "application/x-pki-message";

const DEFAULT_DIR: &str = "/scep/pkiclient";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOperation {
    GetCa = 1,
    GetCaRa = 2,
    Enroll = 3,
    GetCert = 5,
    GetCrl = 7,
    GetNextCa = 15,
    GetCaCaps = 31,
}

pub fn http_operation_from_proto(v: i32) -> Result<HttpOperation> {
    match v {
        1 => Ok(HttpOperation::GetCa),
        2 => Ok(HttpOperation::GetCaRa),
        3 => Ok(HttpOperation::Enroll),
        5 => Ok(HttpOperation::GetCert),
        7 => Ok(HttpOperation::GetCrl),
        15 => Ok(HttpOperation::GetNextCa),
        31 => Ok(HttpOperation::GetCaCaps),
        _ => Err(anyhow!("invalid scep http operation")),
    }
}

fn query_operation(op: HttpOperation) -> &'static str {
    match op {
        HttpOperation::GetCa | HttpOperation::GetCaRa => "GetCACert",
        HttpOperation::Enroll | HttpOperation::GetCert | HttpOperation::GetCrl => "PKIOperation",
        HttpOperation::GetNextCa => "GetNextCACert",
        HttpOperation::GetCaCaps => "GetCACaps",
    }
}

pub fn encode_http_query(operation: HttpOperation, message: &str, dir_name: &str) -> String {
    let dir = if dir_name.is_empty() {
        DEFAULT_DIR
    } else {
        dir_name
    };
    let mut result = dir.to_string();
    result.push('?');
    result.push_str("operation=");
    result.push_str(query_operation(operation));
    if !message.is_empty() {
        result.push_str("&message=");
        result.push_str(message);
    }
    result
}

pub fn expected_mime(operation: HttpOperation) -> &'static str {
    match operation {
        HttpOperation::GetCa => MIME_GET_CA,
        HttpOperation::GetCaRa => MIME_GET_CA_RA,
        HttpOperation::Enroll | HttpOperation::GetCert | HttpOperation::GetCrl => MIME_PKI,
        HttpOperation::GetNextCa => MIME_GET_NEXT_CA,
        HttpOperation::GetCaCaps => "text/plain",
    }
}

pub fn verify_response_mime(operation: HttpOperation, content_type: &str) -> bool {
    if operation == HttpOperation::GetCaCaps {
        return true;
    }
    if operation == HttpOperation::GetCa {
        return content_type.contains(MIME_GET_CA) || content_type.contains(MIME_GET_CA_RA);
    }
    content_type.contains(expected_mime(operation))
}
