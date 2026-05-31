use std::sync::Arc;

use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::crypto_cms;
use crate::crypto_scep;
use crate::crypto_sign;
use crate::key_store::KeyStore;
use crate::pb::cms_service_server::CmsService;
use crate::pb::key_service_server::KeyService;
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
        let state = self.state.clone();
        let certrep_der = run_crypto(&state, move || {
            crypto_scep::build_success_certrep(
                access,
                &transaction_id,
                &recipient_nonce,
                &sender_nonce,
                &issued_cert_der,
                &wrapper_cert_der,
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
