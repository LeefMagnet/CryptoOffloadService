use tonic::Status;

use crate::pb::{
    BuildCmpProtectedPkiMessageRequest, BuildCmsRequest, BuildScepFailureCertRepRequest,
    BuildScepGmSuccessCertRepRequest, BuildScepPendingCertRepRequest,
    BuildScepSuccessCertRepRequest, ParseAndVerifyCmpPkiMessageRequest, ParseCmpPkiMessageRequest,
    ParseScepRequestRequest, VerifyCmpPkiMessageProtectionRequest,
};
use crate::scep_password_envelope;

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

pub fn validate_challenge_password_field(password: &str) -> Result<(), Status> {
    if password.is_empty() {
        return Ok(());
    }
    scep_password_envelope::validate_challenge_password(password)
        .map_err(|e| Status::invalid_argument(e.to_string()))
}

pub fn validate_parse_scep_request(req: &ParseScepRequestRequest) -> Result<(), Status> {
    ensure_small_packet("scep_der", &req.scep_der)?;
    ensure_non_empty("ca_key_id", &req.ca_key_id)?;
    validate_challenge_password_field(&req.challenge_password)?;
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
    validate_challenge_password_field(&req.challenge_password)?;
    let password_envelope = !req.challenge_password.is_empty();
    if !password_envelope && req.wrapper_cert_der.is_empty() {
        return Err(Status::invalid_argument(
            "wrapper_cert_der is required for RSA EnvelopedData; \
             set challenge_password for PasswordRecipientInfo",
        ));
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
    validate_challenge_password_field(&req.challenge_password)?;
    let password_envelope = !req.challenge_password.is_empty();
    if !password_envelope && req.wrapper_cert_der.is_empty() {
        return Err(Status::invalid_argument(
            "wrapper_cert_der is required for RSA EnvelopedData; \
             set challenge_password for PasswordRecipientInfo",
        ));
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

pub fn validate_cmp_parse_request(req: &ParseCmpPkiMessageRequest) -> Result<(), Status> {
    ensure_small_packet("pki_message_der", &req.pki_message_der)?;
    if req.pki_message_der.is_empty() {
        return Err(Status::invalid_argument("pki_message_der is required"));
    }
    Ok(())
}

pub fn validate_cmp_verify_request(
    req: &VerifyCmpPkiMessageProtectionRequest,
) -> Result<(), Status> {
    ensure_small_packet("pki_message_der", &req.pki_message_der)?;
    ensure_non_empty("verify_key_id", &req.verify_key_id)?;
    if req.pki_message_der.is_empty() {
        return Err(Status::invalid_argument("pki_message_der is required"));
    }
    Ok(())
}

pub fn validate_cmp_parse_verify_request(
    req: &ParseAndVerifyCmpPkiMessageRequest,
) -> Result<(), Status> {
    ensure_small_packet("pki_message_der", &req.pki_message_der)?;
    ensure_non_empty("verify_key_id", &req.verify_key_id)?;
    if req.pki_message_der.is_empty() {
        return Err(Status::invalid_argument("pki_message_der is required"));
    }
    Ok(())
}

pub fn validate_cmp_build_request(req: &BuildCmpProtectedPkiMessageRequest) -> Result<(), Status> {
    ensure_small_packet("pki_header_der", &req.pki_header_der)?;
    ensure_small_packet("pki_body_der", &req.pki_body_der)?;
    ensure_non_empty("sign_key_id", &req.sign_key_id)?;
    if req.pki_header_der.is_empty() {
        return Err(Status::invalid_argument("pki_header_der is required"));
    }
    if req.pki_body_der.is_empty() {
        return Err(Status::invalid_argument("pki_body_der is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::BuildScepGmSuccessCertRepRequest;
    use tonic::Code;

    fn valid_gm_success_req() -> BuildScepGmSuccessCertRepRequest {
        BuildScepGmSuccessCertRepRequest {
            ca_key_id: "ca-1".into(),
            transaction_id: "tx-gm-001".into(),
            recipient_nonce: b"\x01\x02\x03\x04".to_vec(),
            sender_nonce: vec![],
            sign_cert_der: b"\x30\x00".to_vec(),
            encryption_cert_der: b"\x30\x00".to_vec(),
            skf_content: b"BASE64SKFDATA==".to_vec(),
            wrapper_cert_der: b"\x30\x00".to_vec(),
            envelope_cipher: 1,
            challenge_password: "".into(),
        }
    }

    #[test]
    fn gm_success_accepts_valid_request_with_wrapper() {
        let req = valid_gm_success_req();
        assert!(validate_scep_gm_success_request(&req).is_ok());
    }

    #[test]
    fn gm_success_accepts_valid_request_with_challenge_no_wrapper() {
        let mut req = valid_gm_success_req();
        req.wrapper_cert_der.clear();
        req.challenge_password = "device-secret".into();
        assert!(validate_scep_gm_success_request(&req).is_ok());
    }

    #[test]
    fn gm_success_rejects_empty_transaction_id() {
        let mut req = valid_gm_success_req();
        req.transaction_id.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("transaction_id"));
    }

    #[test]
    fn gm_success_rejects_empty_recipient_nonce() {
        let mut req = valid_gm_success_req();
        req.recipient_nonce.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("recipient_nonce"));
    }

    #[test]
    fn gm_success_rejects_empty_sign_cert_der() {
        let mut req = valid_gm_success_req();
        req.sign_cert_der.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("sign_cert_der"));
    }

    #[test]
    fn gm_success_rejects_empty_encryption_cert_der() {
        let mut req = valid_gm_success_req();
        req.encryption_cert_der.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("encryption_cert_der"));
    }

    #[test]
    fn gm_success_rejects_empty_skf_content() {
        let mut req = valid_gm_success_req();
        req.skf_content.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("skf_content"));
    }

    #[test]
    fn gm_success_rejects_missing_wrapper_without_challenge() {
        let mut req = valid_gm_success_req();
        req.wrapper_cert_der.clear();
        req.challenge_password.clear();
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("wrapper_cert_der"));
    }

    #[test]
    fn gm_success_rejects_oversized_blobs() {
        let mut req = valid_gm_success_req();
        let huge = vec![0u8; MAX_SMALL_PACKET + 1];
        req.sender_nonce = huge;
        let err = validate_scep_gm_success_request(&req).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("too large"));
    }
}
