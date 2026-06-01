use std::sync::Arc;

use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::crypto_cms;
use crate::crypto_scep;
use crate::crypto_scep_ext;
use crate::crypto_sign;
use crate::key_store::KeyStore;
use crate::pb::cms_service_server::CmsService;
use crate::pb::key_service_server::KeyService;
use crate::pb::scep_ext_service_server::ScepExtService;
use crate::pb::scep_service_server::ScepService;
use crate::pb::sign_service_server::SignService;
use crate::pb::*;
use crate::service_errors::{map_crypto_err, map_key_store_err};
use crate::service_validators::{
    ensure_small_packet, validate_cms_build_request, validate_challenge_password_field,
    validate_parse_scep_request, validate_scep_failure_request, validate_scep_gm_success_request,
    validate_scep_pending_request, validate_scep_success_request,
};

const SCEP_ENVELOPE_CIPHER_UNSPECIFIED: i32 = 0;
const SCEP_ENVELOPE_CIPHER_AES_128_CBC: i32 = 1;
const SCEP_ENVELOPE_CIPHER_DES_CBC_UNSUPPORTED: i32 = 6;

fn optional_password_ref(password: &str) -> Option<&str> {
    if password.is_empty() {
        None
    } else {
        Some(password)
    }
}

fn normalize_scep_envelope_cipher(requested: i32) -> Result<i32, Status> {
    // proto3 enum 在字段省略时会传 0。服务端将默认值升级为 AES-128-CBC。
    if requested == SCEP_ENVELOPE_CIPHER_UNSPECIFIED {
        return Ok(SCEP_ENVELOPE_CIPHER_AES_128_CBC);
    }
    if requested == SCEP_ENVELOPE_CIPHER_DES_CBC_UNSUPPORTED {
        return Err(Status::invalid_argument(
            "SCEP_ENVELOPE_CIPHER_DES_CBC is unsupported; use AES_128_CBC/AES_256_CBC/AES_GCM/DES3_CBC",
        ));
    }
    Ok(requested)
}


pub struct AppState {
    pub keys: KeyStore,
    crypto_semaphore: Arc<Semaphore>,
}

impl AppState {
    pub fn new(crypto_max_inflight: usize) -> Self {
        let n = crypto_max_inflight.max(1);
        Self {
            keys: KeyStore::new(),
            crypto_semaphore: Arc::new(Semaphore::new(n)),
        }
    }
}

pub struct KeyServiceImpl {
    state: Arc<AppState>,
}

pub struct SignServiceImpl {
    state: Arc<AppState>,
}

pub struct CmsServiceImpl {
    state: Arc<AppState>,
}

pub struct ScepServiceImpl {
    state: Arc<AppState>,
}

pub struct ScepExtServiceImpl {
    state: Arc<AppState>,
}

impl KeyServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl SignServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl CmsServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl ScepServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl ScepExtServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

async fn run_crypto<T, F>(state: &Arc<AppState>, f: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, anyhow::Error> + Send + 'static,
{
    let permit = state
        .crypto_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Status::unavailable("crypto concurrency semaphore closed"))?;

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| Status::internal(format!("crypto task join error: {e}")))?
    .map_err(map_crypto_err)
}

#[tonic::async_trait]
impl KeyService for KeyServiceImpl {
    async fn import_key(
        &self,
        request: Request<ImportKeyRequest>,
    ) -> Result<Response<ImportKeyResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("key_data", &req.key_data)?;
        ensure_small_packet("certificate_data", &req.certificate_data)?;
        let metadata = self
            .state
            .keys
            .import_key(
                req.kind,
                req.lifetime,
                req.format,
                &req.key_data,
                &req.label,
                &req.certificate_data,
                req.certificate_format,
            )
            .map_err(map_key_store_err)?;
        Ok(Response::new(ImportKeyResponse {
            metadata: Some(metadata),
        }))
    }

    async fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let req = request.into_inner();
        let deleted = self
            .state
            .keys
            .delete_key(&req.key_id)
            .map_err(map_key_store_err)?;
        Ok(Response::new(DeleteKeyResponse { deleted }))
    }

    async fn get_key_info(
        &self,
        request: Request<GetKeyInfoRequest>,
    ) -> Result<Response<GetKeyInfoResponse>, Status> {
        let req = request.into_inner();
        let metadata = self
            .state
            .keys
            .get_metadata(&req.key_id)
            .map_err(map_key_store_err)?;
        Ok(Response::new(GetKeyInfoResponse {
            metadata: Some(metadata),
        }))
    }

    async fn list_keys(
        &self,
        _request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let keys = self
            .state
            .keys
            .list_metadata()
            .map_err(map_key_store_err)?;
        Ok(Response::new(ListKeysResponse { keys }))
    }
}

#[tonic::async_trait]
impl SignService for SignServiceImpl {
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("data", &req.data)?;
        let access = self
            .state
            .keys
            .access_key(&req.key_id)
            .map_err(map_key_store_err)?;
        let data = req.data;
        let hash_algorithm = req.hash_algorithm;
        let sign_algorithm = req.sign_algorithm;
        let state = self.state.clone();
        let output = run_crypto(&state, move || {
            crypto_sign::sign(access, &data, hash_algorithm, sign_algorithm)
        })
        .await?;

        Ok(Response::new(SignResponse {
            signature: output.signature,
            hash_algorithm: output.hash_algorithm,
            sign_algorithm: output.sign_algorithm,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("data", &req.data)?;
        ensure_small_packet("signature", &req.signature)?;
        let access = self
            .state
            .keys
            .access_key(&req.key_id)
            .map_err(map_key_store_err)?;
        let data = req.data;
        let signature = req.signature;
        let hash_algorithm = req.hash_algorithm;
        let sign_algorithm = req.sign_algorithm;
        let state = self.state.clone();
        let valid = run_crypto(&state, move || {
            crypto_sign::verify(
                access,
                &data,
                &signature,
                hash_algorithm,
                sign_algorithm,
            )
        })
        .await?;

        Ok(Response::new(VerifyResponse { valid }))
    }
}

#[tonic::async_trait]
impl CmsService for CmsServiceImpl {
    async fn parse(
        &self,
        request: Request<ParseCmsRequest>,
    ) -> Result<Response<ParseCmsResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("cms_der", &req.cms_der)?;
        let access = if req.decrypt_key_id.is_empty() {
            None
        } else {
            Some(
                self.state
                    .keys
                    .access_key(&req.decrypt_key_id)
                    .map_err(map_key_store_err)?,
            )
        };
        let cms_der = req.cms_der;
        let state = self.state.clone();
        let parsed = run_crypto(&state, move || crypto_cms::parse_cms(&cms_der, access)).await?;

        Ok(Response::new(ParseCmsResponse {
            content: parsed.0,
            signer_certificates: parsed.1,
        }))
    }

    async fn build(
        &self,
        request: Request<BuildCmsRequest>,
    ) -> Result<Response<BuildCmsResponse>, Status> {
        let req = request.into_inner();
        validate_cms_build_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.sign_key_id)
            .map_err(map_key_store_err)?;
        let content = req.content;
        let extra = req.extra_certificates;
        let detached = req.detached;
        let state = self.state.clone();
        let cms_der =
            run_crypto(&state, move || crypto_cms::build_cms(&content, access, detached, &extra))
                .await?;

        Ok(Response::new(BuildCmsResponse { cms_der }))
    }

    async fn verify(
        &self,
        request: Request<VerifyCmsRequest>,
    ) -> Result<Response<VerifyCmsResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("cms_der", &req.cms_der)?;
        ensure_small_packet("content", &req.content)?;
        let access = self
            .state
            .keys
            .access_key(&req.verify_key_id)
            .map_err(map_key_store_err)?;
        let cms_der = req.cms_der;
        let content = req.content;
        let state = self.state.clone();
        let valid =
            run_crypto(&state, move || crypto_cms::verify_cms(&cms_der, access, &content)).await?;

        Ok(Response::new(VerifyCmsResponse { valid }))
    }
}

#[tonic::async_trait]
impl ScepService for ScepServiceImpl {
    async fn parse_request(
        &self,
        request: Request<ParseScepRequestRequest>,
    ) -> Result<Response<ParseScepRequestResponse>, Status> {
        let req = request.into_inner();
        validate_parse_scep_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let challenge_password = req.challenge_password;
        let state = self.state.clone();
        let parsed = run_crypto(&state, move || {
            let cp = optional_password_ref(&challenge_password);
            crypto_scep::parse_request(&scep_der, access, cp)
        })
        .await?;

        Ok(Response::new(ParseScepRequestResponse {
            csr_der: parsed.0,
            wrapper_cert_der: parsed.1,
        }))
    }

    async fn build_success_cert_rep(
        &self,
        request: Request<BuildScepSuccessCertRepRequest>,
    ) -> Result<Response<BuildScepCertRepResponse>, Status> {
        let req = request.into_inner();
        validate_scep_success_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let transaction_id = req.transaction_id;
        let recipient_nonce = req.recipient_nonce;
        let sender_nonce = req.sender_nonce;
        let issued_cert_der = req.issued_cert_der;
        let wrapper_cert_der = req.wrapper_cert_der;
        let challenge_password = req.challenge_password;
        let envelope_cipher = normalize_scep_envelope_cipher(req.envelope_cipher)?;
        let state = self.state.clone();
        let certrep_der = run_crypto(&state, move || {
            crypto_scep::build_success_certrep(
                access,
                &transaction_id,
                &recipient_nonce,
                &sender_nonce,
                &issued_cert_der,
                &wrapper_cert_der,
                envelope_cipher,
                optional_password_ref(&challenge_password),
            )
        })
        .await?;

        Ok(Response::new(BuildScepCertRepResponse { certrep_der }))
    }

    async fn build_gm_success_cert_rep(
        &self,
        request: Request<BuildScepGmSuccessCertRepRequest>,
    ) -> Result<Response<BuildScepCertRepResponse>, Status> {
        let req = request.into_inner();
        validate_scep_gm_success_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let transaction_id = req.transaction_id;
        let recipient_nonce = req.recipient_nonce;
        let sender_nonce = req.sender_nonce;
        let sign_cert_der = req.sign_cert_der;
        let encryption_cert_der = req.encryption_cert_der;
        let skf_content = req.skf_content;
        let wrapper_cert_der = req.wrapper_cert_der;
        let challenge_password = req.challenge_password;
        let envelope_cipher = normalize_scep_envelope_cipher(req.envelope_cipher)?;
        let state = self.state.clone();
        let certrep_der = run_crypto(&state, move || {
            crypto_scep::build_gm_success_certrep(
                access,
                &transaction_id,
                &recipient_nonce,
                &sender_nonce,
                &sign_cert_der,
                &encryption_cert_der,
                &skf_content,
                &wrapper_cert_der,
                envelope_cipher,
                optional_password_ref(&challenge_password),
            )
        })
        .await?;

        Ok(Response::new(BuildScepCertRepResponse { certrep_der }))
    }

    async fn build_failure_cert_rep(
        &self,
        request: Request<BuildScepFailureCertRepRequest>,
    ) -> Result<Response<BuildScepCertRepResponse>, Status> {
        let req = request.into_inner();
        validate_scep_failure_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let transaction_id = req.transaction_id;
        let recipient_nonce = req.recipient_nonce;
        let sender_nonce = req.sender_nonce;
        let fail_info = req.fail_info as u8;
        let fail_info_text = req.fail_info_text;
        let state = self.state.clone();
        let certrep_der = run_crypto(&state, move || {
            crypto_scep::build_failure_certrep(
                access,
                &transaction_id,
                &recipient_nonce,
                &sender_nonce,
                fail_info,
                &fail_info_text,
            )
        })
        .await?;

        Ok(Response::new(BuildScepCertRepResponse { certrep_der }))
    }

    async fn build_pending_cert_rep(
        &self,
        request: Request<BuildScepPendingCertRepRequest>,
    ) -> Result<Response<BuildScepCertRepResponse>, Status> {
        let req = request.into_inner();
        validate_scep_pending_request(&req)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let transaction_id = req.transaction_id;
        let recipient_nonce = req.recipient_nonce;
        let sender_nonce = req.sender_nonce;
        let state = self.state.clone();
        let certrep_der = run_crypto(&state, move || {
            crypto_scep::build_pending_certrep(
                access,
                &transaction_id,
                &recipient_nonce,
                &sender_nonce,
            )
        })
        .await?;

        Ok(Response::new(BuildScepCertRepResponse { certrep_der }))
    }
}

#[tonic::async_trait]
impl ScepExtService for ScepExtServiceImpl {
    async fn parse_signed_attributes(
        &self,
        request: Request<ParseScepSignedAttributesRequest>,
    ) -> Result<Response<ParseScepSignedAttributesResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("pkcs7_der", &req.pkcs7_der)?;
        let pkcs7_der = req.pkcs7_der;
        let state = self.state.clone();
        let attributes = run_crypto(&state, move || {
            crypto_scep_ext::parse_signed_attributes(&pkcs7_der)
        })
        .await?;
        Ok(Response::new(ParseScepSignedAttributesResponse {
            attributes: Some(attributes),
        }))
    }

    async fn parse_get_cert_pkio(
        &self,
        request: Request<ParseGetCertPkioRequest>,
    ) -> Result<Response<ParseGetCertPkioResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("scep_der", &req.scep_der)?;
        validate_challenge_password_field(&req.challenge_password)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let challenge_password = req.challenge_password;
        let state = self.state.clone();
        let resp = run_crypto(&state, move || {
            crypto_scep_ext::parse_getcert_pkio(
                &scep_der,
                access,
                optional_password_ref(&challenge_password),
            )
        })
        .await?;
        Ok(Response::new(resp))
    }

    async fn parse_enroll_pkio(
        &self,
        request: Request<ParseEnrollPkioRequest>,
    ) -> Result<Response<ParseEnrollPkioResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("scep_der", &req.scep_der)?;
        validate_challenge_password_field(&req.challenge_password)?;
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let challenge_password = req.challenge_password;
        let state = self.state.clone();
        let resp = run_crypto(&state, move || {
            crypto_scep_ext::parse_enroll_pkio(
                &scep_der,
                access,
                optional_password_ref(&challenge_password),
            )
        })
        .await?;
        Ok(Response::new(resp))
    }

    async fn encode_cert_alias_content(
        &self,
        request: Request<EncodeCertAliasContentRequest>,
    ) -> Result<Response<EncodeCertAliasContentResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("value", req.value.as_bytes())?;
        let content_type = req.content_type;
        let value = req.value;
        let state = self.state.clone();
        let content_der = run_crypto(&state, move || {
            crypto_scep_ext::encode_cert_alias_content(content_type, &value)
        })
        .await?;
        Ok(Response::new(EncodeCertAliasContentResponse { content_der }))
    }

    async fn decode_cert_alias_content(
        &self,
        request: Request<DecodeCertAliasContentRequest>,
    ) -> Result<Response<DecodeCertAliasContentResponse>, Status> {
        let req = request.into_inner();
        ensure_small_packet("content_der", &req.content_der)?;
        let content_der = req.content_der;
        let state = self.state.clone();
        let (content_type, alias_or_cn, serial_number_hex) =
            run_crypto(&state, move || crypto_scep_ext::decode_cert_alias_content(&content_der))
                .await?;
        Ok(Response::new(DecodeCertAliasContentResponse {
            content_type,
            alias_or_cn,
            serial_number_hex,
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::{
        normalize_scep_envelope_cipher, SCEP_ENVELOPE_CIPHER_AES_128_CBC,
        SCEP_ENVELOPE_CIPHER_DES_CBC_UNSUPPORTED, SCEP_ENVELOPE_CIPHER_UNSPECIFIED,
    };

    #[test]
    fn normalize_scep_envelope_cipher_defaults_to_aes128cbc() {
        assert_eq!(
            normalize_scep_envelope_cipher(SCEP_ENVELOPE_CIPHER_UNSPECIFIED).expect("normalize"),
            SCEP_ENVELOPE_CIPHER_AES_128_CBC
        );
    }

    #[test]
    fn normalize_scep_envelope_cipher_keeps_non_default_value() {
        assert_eq!(normalize_scep_envelope_cipher(2).expect("normalize"), 2);
        assert_eq!(normalize_scep_envelope_cipher(5).expect("normalize"), 5);
    }

    #[test]
    fn validate_scep_success_allows_password_without_wrapper() {
        use crate::pb::BuildScepSuccessCertRepRequest;
        use crate::service_validators::validate_scep_success_request;

        let req = BuildScepSuccessCertRepRequest {
            ca_key_id: "ca".into(),
            transaction_id: "tx".into(),
            recipient_nonce: vec![1, 2, 3, 4],
            issued_cert_der: vec![0x30],
            wrapper_cert_der: vec![],
            envelope_cipher: SCEP_ENVELOPE_CIPHER_AES_128_CBC,
            challenge_password: "high-entropy-shared-secret".into(),
            sender_nonce: vec![],
        };
        validate_scep_success_request(&req).expect("password envelope without wrapper");
    }

    fn normalize_scep_envelope_cipher_rejects_des_cbc_unsupported() {
        let err = normalize_scep_envelope_cipher(SCEP_ENVELOPE_CIPHER_DES_CBC_UNSUPPORTED)
            .expect_err("des-cbc must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
