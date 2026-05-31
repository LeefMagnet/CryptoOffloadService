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

const MAX_SMALL_PACKET: usize = 1024 * 1024;

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
        if req.key_data.len() > MAX_SMALL_PACKET || req.certificate_data.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("key or certificate data too large"));
        }
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
        if req.data.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("data too large"));
        }
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
        if req.data.len() > MAX_SMALL_PACKET || req.signature.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("data or signature too large"));
        }
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
        if req.cms_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("cms_der too large"));
        }
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
        if req.content.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("content too large"));
        }
        for cert in &req.extra_certificates {
            if cert.len() > MAX_SMALL_PACKET {
                return Err(Status::invalid_argument("extra certificate too large"));
            }
        }
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
        if req.cms_der.len() > MAX_SMALL_PACKET || req.content.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("cms_der or content too large"));
        }
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
        if req.scep_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("scep_der too large"));
        }
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let state = self.state.clone();
        let parsed =
            run_crypto(&state, move || crypto_scep::parse_request(&scep_der, access)).await?;

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
        for blob in [
            &req.recipient_nonce,
            &req.sender_nonce,
            &req.issued_cert_der,
            &req.wrapper_cert_der,
        ] {
            if blob.len() > MAX_SMALL_PACKET {
                return Err(Status::invalid_argument("SCEP request field too large"));
            }
        }
        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument("transaction_id is required"));
        }
        if req.recipient_nonce.is_empty() {
            return Err(Status::invalid_argument("recipient_nonce is required"));
        }
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
        let envelope_cipher = req.envelope_cipher;
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
        for blob in [
            &req.recipient_nonce,
            &req.sender_nonce,
            &req.sign_cert_der,
            &req.encryption_cert_der,
            &req.skf_content,
            &req.wrapper_cert_der,
        ] {
            if blob.len() > MAX_SMALL_PACKET {
                return Err(Status::invalid_argument("SCEP request field too large"));
            }
        }
        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument("transaction_id is required"));
        }
        if req.recipient_nonce.is_empty() {
            return Err(Status::invalid_argument("recipient_nonce is required"));
        }
        if req.sign_cert_der.is_empty() || req.encryption_cert_der.is_empty() {
            return Err(Status::invalid_argument("sign_cert_der and encryption_cert_der are required"));
        }
        if req.skf_content.is_empty() {
            return Err(Status::invalid_argument("skf_content is required"));
        }
        if req.wrapper_cert_der.is_empty() {
            return Err(Status::invalid_argument("wrapper_cert_der is required"));
        }
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
        let envelope_cipher = req.envelope_cipher;
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
        for blob in [&req.recipient_nonce, &req.sender_nonce] {
            if blob.len() > MAX_SMALL_PACKET {
                return Err(Status::invalid_argument("SCEP request field too large"));
            }
        }
        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument("transaction_id is required"));
        }
        if req.recipient_nonce.is_empty() {
            return Err(Status::invalid_argument("recipient_nonce is required"));
        }
        if req.fail_info_text.is_empty() {
            return Err(Status::invalid_argument("fail_info_text is required"));
        }
        if req.fail_info > 4 {
            return Err(Status::invalid_argument("fail_info must be 0..=4"));
        }
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
        for blob in [&req.recipient_nonce, &req.sender_nonce] {
            if blob.len() > MAX_SMALL_PACKET {
                return Err(Status::invalid_argument("SCEP request field too large"));
            }
        }
        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument("transaction_id is required"));
        }
        if req.recipient_nonce.is_empty() {
            return Err(Status::invalid_argument("recipient_nonce is required"));
        }
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
        if req.pkcs7_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("pkcs7_der too large"));
        }
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
        if req.scep_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("scep_der too large"));
        }
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let state = self.state.clone();
        let resp = run_crypto(&state, move || {
            crypto_scep_ext::parse_getcert_pkio(&scep_der, access)
        })
        .await?;
        Ok(Response::new(resp))
    }

    async fn parse_enroll_pkio(
        &self,
        request: Request<ParseEnrollPkioRequest>,
    ) -> Result<Response<ParseEnrollPkioResponse>, Status> {
        let req = request.into_inner();
        if req.scep_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("scep_der too large"));
        }
        let access = self
            .state
            .keys
            .access_key(&req.ca_key_id)
            .map_err(map_key_store_err)?;
        let scep_der = req.scep_der;
        let state = self.state.clone();
        let resp = run_crypto(&state, move || {
            crypto_scep_ext::parse_enroll_pkio(&scep_der, access)
        })
        .await?;
        Ok(Response::new(resp))
    }

    async fn encode_cert_alias_content(
        &self,
        request: Request<EncodeCertAliasContentRequest>,
    ) -> Result<Response<EncodeCertAliasContentResponse>, Status> {
        let req = request.into_inner();
        if req.value.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("value too large"));
        }
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
        if req.content_der.len() > MAX_SMALL_PACKET {
            return Err(Status::invalid_argument("content_der too large"));
        }
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

fn map_key_store_err(err: anyhow::Error) -> Status {
    let msg = err.to_string();
    if msg.contains("lock poisoned") {
        Status::unavailable(msg)
    } else {
        Status::invalid_argument(msg)
    }
}

fn map_crypto_err(err: anyhow::Error) -> Status {
    Status::invalid_argument(err.to_string())
}
