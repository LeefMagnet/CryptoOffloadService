use std::sync::Arc;

use anyhow::{Context, Result};

use crate::pb::v1::cms_service_client::CmsServiceClient;
use crate::pb::v1::key_service_client::KeyServiceClient;
use crate::pb::v1::scep_service_client::ScepServiceClient;
use crate::pb::v1::sign_service_client::SignServiceClient;
use crate::pb::v1::*;
use crate::pool::{Pool, PoolConfig, PooledConn};

/// 高层客户端：从连接池借连接，执行 RPC 后自动归还。
pub struct Client {
    pool: Arc<Pool>,
}

impl Client {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            pool: Pool::new(config),
        }
    }

    pub async fn connect(config: PoolConfig) -> Result<Self> {
        let pool = Pool::new(config);
        pool.warmup().await?;
        Ok(Self { pool })
    }

    pub async fn import_key(
        &self,
        req: ImportKeyRequest,
    ) -> Result<ImportKeyResponse> {
        self.with_key(|mut client| async move {
            client
                .import_key(req)
                .await
                .map(|r| r.into_inner())
                .context("ImportKey rpc")
        })
        .await
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<DeleteKeyResponse> {
        self.with_key(|mut client| async move {
            client
                .delete_key(DeleteKeyRequest {
                    key_id: key_id.to_string(),
                })
                .await
                .map(|r| r.into_inner())
                .context("DeleteKey rpc")
        })
        .await
    }

    pub async fn get_key_info(&self, key_id: &str) -> Result<GetKeyInfoResponse> {
        self.with_key(|mut client| async move {
            client
                .get_key_info(GetKeyInfoRequest {
                    key_id: key_id.to_string(),
                })
                .await
                .map(|r| r.into_inner())
                .context("GetKeyInfo rpc")
        })
        .await
    }

    pub async fn list_keys(&self) -> Result<ListKeysResponse> {
        self.with_key(|mut client| async move {
            client
                .list_keys(ListKeysRequest {})
                .await
                .map(|r| r.into_inner())
                .context("ListKeys rpc")
        })
        .await
    }

    pub async fn sign(&self, req: SignRequest) -> Result<SignResponse> {
        self.with_sign(|mut client| async move {
            client
                .sign(req)
                .await
                .map(|r| r.into_inner())
                .context("Sign rpc")
        })
        .await
    }

    pub async fn verify(&self, req: VerifyRequest) -> Result<VerifyResponse> {
        self.with_sign(|mut client| async move {
            client
                .verify(req)
                .await
                .map(|r| r.into_inner())
                .context("Verify rpc")
        })
        .await
    }

    pub async fn parse_cms(&self, req: ParseCmsRequest) -> Result<ParseCmsResponse> {
        self.with_cms(|mut client| async move {
            client
                .parse(req)
                .await
                .map(|r| r.into_inner())
                .context("Parse cms rpc")
        })
        .await
    }

    pub async fn build_cms(&self, req: BuildCmsRequest) -> Result<BuildCmsResponse> {
        self.with_cms(|mut client| async move {
            client
                .build(req)
                .await
                .map(|r| r.into_inner())
                .context("Build cms rpc")
        })
        .await
    }

    pub async fn verify_cms(&self, req: VerifyCmsRequest) -> Result<VerifyCmsResponse> {
        self.with_cms(|mut client| async move {
            client
                .verify(req)
                .await
                .map(|r| r.into_inner())
                .context("Verify cms rpc")
        })
        .await
    }

    pub async fn parse_scep_request(
        &self,
        req: ParseScepRequestRequest,
    ) -> Result<ParseScepRequestResponse> {
        self.with_scep(|mut client| async move {
            client
                .parse_request(req)
                .await
                .map(|r| r.into_inner())
                .context("ParseScepRequest rpc")
        })
        .await
    }

    pub async fn build_scep_success_cert_rep(
        &self,
        req: BuildScepSuccessCertRepRequest,
    ) -> Result<BuildScepCertRepResponse> {
        self.with_scep(|mut client| async move {
            client
                .build_success_cert_rep(req)
                .await
                .map(|r| r.into_inner())
                .context("BuildScepSuccessCertRep rpc")
        })
        .await
    }

    pub async fn build_scep_failure_cert_rep(
        &self,
        req: BuildScepFailureCertRepRequest,
    ) -> Result<BuildScepCertRepResponse> {
        self.with_scep(|mut client| async move {
            client
                .build_failure_cert_rep(req)
                .await
                .map(|r| r.into_inner())
                .context("BuildScepFailureCertRep rpc")
        })
        .await
    }

    async fn with_key<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(KeyServiceClient<tonic::transport::Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let conn = self.pool.acquire().await?;
        let channel = conn.channel()?;
        f(KeyServiceClient::new(channel)).await
    }

    async fn with_sign<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(SignServiceClient<tonic::transport::Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let conn = self.pool.acquire().await?;
        let channel = conn.channel()?;
        f(SignServiceClient::new(channel)).await
    }

    async fn with_cms<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(CmsServiceClient<tonic::transport::Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let conn = self.pool.acquire().await?;
        let channel = conn.channel()?;
        f(CmsServiceClient::new(channel)).await
    }

    async fn with_scep<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(ScepServiceClient<tonic::transport::Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let conn = self.pool.acquire().await?;
        let channel = conn.channel()?;
        f(ScepServiceClient::new(channel)).await
    }
}
