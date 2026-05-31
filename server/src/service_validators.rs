use tonic::Status;

use crate::pb::{
    BuildCmsRequest, BuildScepFailureCertRepRequest, BuildScepGmSuccessCertRepRequest,
    BuildScepPendingCertRepRequest, BuildScepSuccessCertRepRequest,
};

pub const MAX_SMALL_PACKET: usize = 1024 * 1024;
const CMS_CONTENT_TYPE_UNSPECIFIED: i32 = 0;
const CMS_CONTENT_TYPE_DATA: i32 = 1;

pub fn ensure_small_packet(field: &str, bytes: &[u8]) -> Result<(), Status> {
    if bytes.len() > MAX_SMALL_PACKET {
        return Err(Status::invalid_argument(format!("{field} too large")));
    }
    Ok(())
}

pub fn ensure_non_empty(field: &str, value: &str) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    Ok(())
}

pub fn validate_cms_build_request(req: &BuildCmsRequest) -> Result<(), Status> {
    if req.content_type != CMS_CONTENT_TYPE_UNSPECIFIED && req.content_type != CMS_CONTENT_TYPE_DATA
    {
        return Err(Status::invalid_argument(
            "unsupported content_type: only CMS_CONTENT_TYPE_DATA is supported",
        ));
    }
    ensure_small_packet("content", &req.content)?;
    for cert in &req.extra_certificates {
        ensure_small_packet("extra certificate", cert)?;
    }
    Ok(())
}

pub fn validate_scep_success_request(req: &BuildScepSuccessCertRepRequest) -> Result<(), Status> {
    for (field, blob) in [
        ("recipient_nonce", req.recipient_nonce.as_slice()),
        ("sender_nonce", req.sender_nonce.as_slice()),
        ("issued_cert_der", req.issued_cert_der.as_slice()),
        ("wrapper_cert_der", req.wrapper_cert_der.as_slice()),
    ] {
        ensure_small_packet(field, blob)?;
    }
    ensure_non_empty("transaction_id", &req.transaction_id)?;
    if req.recipient_nonce.is_empty() {
        return Err(Status::invalid_argument("recipient_nonce is required"));
    }
    Ok(())
}

pub fn validate_scep_gm_success_request(
    req: &BuildScepGmSuccessCertRepRequest,
) -> Result<(), Status> {
    for (field, blob) in [
        ("recipient_nonce", req.recipient_nonce.as_slice()),
        ("sender_nonce", req.sender_nonce.as_slice()),
        ("sign_cert_der", req.sign_cert_der.as_slice()),
        ("encryption_cert_der", req.encryption_cert_der.as_slice()),
        ("skf_content", req.skf_content.as_slice()),
        ("wrapper_cert_der", req.wrapper_cert_der.as_slice()),
    ] {
        ensure_small_packet(field, blob)?;
    }
    ensure_non_empty("transaction_id", &req.transaction_id)?;
    if req.recipient_nonce.is_empty() {
        return Err(Status::invalid_argument("recipient_nonce is required"));
    }
    if req.sign_cert_der.is_empty() || req.encryption_cert_der.is_empty() {
        return Err(Status::invalid_argument(
            "sign_cert_der and encryption_cert_der are required",
        ));
    }
    if req.skf_content.is_empty() {
        return Err(Status::invalid_argument("skf_content is required"));
    }
    if req.wrapper_cert_der.is_empty() {
        return Err(Status::invalid_argument("wrapper_cert_der is required"));
    }
    Ok(())
}

pub fn validate_scep_failure_request(req: &BuildScepFailureCertRepRequest) -> Result<(), Status> {
    ensure_small_packet("recipient_nonce", &req.recipient_nonce)?;
    ensure_small_packet("sender_nonce", &req.sender_nonce)?;
    ensure_non_empty("transaction_id", &req.transaction_id)?;
    if req.recipient_nonce.is_empty() {
        return Err(Status::invalid_argument("recipient_nonce is required"));
    }
    if req.fail_info_text.is_empty() {
        return Err(Status::invalid_argument("fail_info_text is required"));
    }
    if req.fail_info > 4 {
        return Err(Status::invalid_argument("fail_info must be 0..=4"));
    }
    Ok(())
}

pub fn validate_scep_pending_request(req: &BuildScepPendingCertRepRequest) -> Result<(), Status> {
    ensure_small_packet("recipient_nonce", &req.recipient_nonce)?;
    ensure_small_packet("sender_nonce", &req.sender_nonce)?;
    ensure_non_empty("transaction_id", &req.transaction_id)?;
    if req.recipient_nonce.is_empty() {
        return Err(Status::invalid_argument("recipient_nonce is required"));
    }
    Ok(())
}
