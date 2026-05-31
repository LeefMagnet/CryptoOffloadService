//! gRPC 压测客户端：测量 Sign/Verify/CMS/SCEP/ImportKey 吞吐与延迟。

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tonic::transport::Channel;

pub mod cryptooffload {
    pub mod v1 {
        tonic::include_proto!("cryptooffload.v1");
    }
}

use cryptooffload::v1::cms_service_client::CmsServiceClient;
use cryptooffload::v1::key_service_client::KeyServiceClient;
use cryptooffload::v1::scep_service_client::ScepServiceClient;
use cryptooffload::v1::sign_service_client::SignServiceClient;
use cryptooffload::v1::{
    BuildCmsRequest, BuildScepFailureCertRepRequest, BuildScepPendingCertRepRequest,
    BuildScepSuccessCertRepRequest,
    HashAlgorithm, ImportKeyRequest, KeyFormat, KeyKind, KeyLifetime, ParseCmsRequest,
    ParseScepRequestRequest, SignAlgorithm, SignRequest, VerifyCmsRequest, VerifyRequest,
};

const ENVELOPE_UNSPECIFIED: i32 = 0;
const ENVELOPE_AES128_CBC: i32 = 1;
const ENVELOPE_AES256_CBC: i32 = 2;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchMode {
    ImportKey,
    Sign,
    Verify,
    SignVerify,
    SignRsaPss,
    SignVerifyRsaPss,
    SignSm2,
    SignVerifySm2,
    SignEd25519,
    SignVerifyEd25519,
    CmsBuild,
    CmsParse,
    CmsVerify,
    CmsBuildParse,
    /// SCEP SUCCESS CertRep，默认算法（UNSPECIFIED->AES-128-CBC；同 `scep-certrep-success`）
    #[value(name = "scep-certrep-success")]
    ScepCertrepSuccessDefault,
    /// SCEP SUCCESS CertRep，AES-128-CBC Envelop（RFC 8894 推荐）
    #[value(name = "scep-certrep-success-aes128-cbc")]
    ScepCertrepSuccessAes128Cbc,
    /// SCEP SUCCESS CertRep，AES-256-CBC Envelop（step-ca 推荐）
    #[value(name = "scep-certrep-success-aes256-cbc")]
    ScepCertrepSuccessAes256Cbc,
    /// SCEP FAILURE CertRep（pkiStatus=2，无 Envelop）
    ScepCertrepFailure,
    /// SCEP PENDING CertRep（pkiStatus=3，待人工审批，无 Envelop）
    ScepCertrepPending,
    /// SCEP ParseRequest：验外层 SignedData + 解密 Envelop → csr_der + wrapper_cert_der
    ScepParseRequest,
    /// SCEP SUCCESS CertRep CMS 验签（CmsService.Verify + CA 证书）
    ScepCertrepVerify,
    /// ParseRequest + BuildSuccessCertRep 组合
    ScepParseBuildSuccess,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    address: String,
    #[arg(long, value_enum, default_value_t = BenchMode::Sign)]
    mode: BenchMode,
    #[arg(long, default_value_t = 8)]
    clients: usize,
    #[arg(long, default_value_t = 20_000)]
    total_requests: usize,
    #[arg(long, default_value_t = 3)]
    warmup_seconds: u64,
    #[arg(long, default_value_t = 256)]
    payload_size: usize,
    #[arg(long)]
    private_key_pem: Option<std::path::PathBuf>,
    #[arg(long)]
    certificate_pem: Option<std::path::PathBuf>,
    #[arg(long, default_value = "")]
    server_profile: String,
}

struct BenchKeys {
    private_key_id: String,
    public_key_id: String,
    cms_key_id: String,
    sample_signature: Vec<u8>,
    payload: Vec<u8>,
    cms_der: Vec<u8>,
    sm2_private_key_id: Option<String>,
    sm2_public_key_id: Option<String>,
    ed25519_private_key_id: String,
    ed25519_public_key_id: String,
    ca_key_id: String,
    ca_cert_key_id: String,
    issued_cert_der: Vec<u8>,
    wrapper_cert_der: Vec<u8>,
    scep_pkio_der: Vec<u8>,
    scep_success_certrep_der: Vec<u8>,
    recipient_nonce: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    crypto_offload_server::openssl_init::init();
    let args = Args::parse();
    print_env_banner(&args);

    let channel = Channel::from_shared(args.address.clone())
        .context("invalid address")?
        .connect()
        .await
        .context("connect grpc")?;

    let payload = vec![0xABu8; args.payload_size.max(1)];
    let keys = prepare_keys(&channel, &args, &payload).await?;

    if requires_sm2(args.mode) && keys.sm2_private_key_id.is_none() {
        anyhow::bail!("mode {:?} requires SM2 support in OpenSSL; unavailable on this host", args.mode);
    }

    println!("warmup {}s ...", args.warmup_seconds);
    let warmup_deadline = Instant::now() + Duration::from_secs(args.warmup_seconds);
    while Instant::now() < warmup_deadline {
        run_one(&channel, args.mode, &keys).await?;
    }
    println!("warmup done");

    let per_client = args.total_requests / args.clients;
    let remainder = args.total_requests % args.clients;
    let latencies = Arc::new(Mutex::new(Vec::<u128>::with_capacity(args.total_requests)));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(args.clients);
    for i in 0..args.clients {
        let n = if i == 0 { per_client + remainder } else { per_client };
        let ch = channel.clone();
        let keys = keys.clone_for_worker();
        let latencies = latencies.clone();
        let mode = args.mode;
        handles.push(tokio::spawn(async move {
            for _ in 0..n {
                let t0 = Instant::now();
                run_one(&ch, mode, &keys).await?;
                latencies.lock().await.push(t0.elapsed().as_micros());
            }
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in handles {
        h.await.context("join")??;
    }
    let elapsed = start.elapsed();

    let mut l = latencies.lock().await;
    l.sort_unstable();
    let count = l.len().max(1);
    let p50 = l[count * 50 / 100];
    let p95 = l[count * 95 / 100];
    let p99 = l[count * 99 / 100];
    let qps = args.total_requests as f64 / elapsed.as_secs_f64();

    println!();
    println!("=== benchmark result ===");
    println!("mode: {:?}", args.mode);
    println!("total_requests: {}", args.total_requests);
    println!("clients: {}", args.clients);
    println!("payload_bytes: {}", args.payload_size);
    if !keys.cms_der.is_empty() {
        println!("cms_der_bytes: {}", keys.cms_der.len());
    }
    println!("elapsed_ms: {:.2}", elapsed.as_secs_f64() * 1000.0);
    println!("qps: {:.2}", qps);
    println!("latency_us: p50={} p95={} p99={}", p50, p95, p99);
    Ok(())
}

fn requires_sm2(mode: BenchMode) -> bool {
    matches!(mode, BenchMode::SignSm2 | BenchMode::SignVerifySm2)
}

fn print_env_banner(args: &Args) {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let (cpu_model, physical_cores) = read_cpu_info();
    let cpuset = read_effective_cpuset();

    println!("=== benchmark environment ===");
    println!("hostname: {hostname}");
    println!("cpu_model: {cpu_model}");
    println!("cpu_physical_cores: {physical_cores}");
    println!("cpu_logical_cores: {logical}");
    if let Some(set) = cpuset {
        println!("process_cpuset: {set}");
    } else {
        println!("process_cpuset: (not restricted / unavailable)");
    }
    println!("benchmark_clients: {}", args.clients);
    println!("target_address: {}", args.address);
    if !args.server_profile.is_empty() {
        println!("server_profile: {}", args.server_profile);
    } else {
        println!(
            "server_profile: (unset — 请用 --server-profile 标注服务端 cpuset/worker 配置)"
        );
    }
    println!(
        "note: clients={} 是客户端并发连接数；QPS 受服务端可见 CPU 核数、cpuset、OpenSSL 线程竞争影响",
        args.clients
    );
    println!();
}

fn read_cpu_info() -> (String, usize) {
    let mut model = "unknown".to_string();
    let mut logical = 0usize;
    let mut core_pairs = std::collections::HashSet::new();
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        let mut phys = String::new();
        let mut core = String::new();
        for line in text.lines() {
            if line.starts_with("model name") {
                if let Some(v) = line.split(':').nth(1) {
                    model = v.trim().to_string();
                }
            } else if line.starts_with("processor") {
                logical += 1;
            } else if line.starts_with("physical id") {
                phys = line.split(':').nth(1).unwrap_or("0").trim().to_string();
            } else if line.starts_with("core id") {
                core = line.split(':').nth(1).unwrap_or("0").trim().to_string();
                core_pairs.insert(format!("{phys}:{core}"));
                phys.clear();
                core.clear();
            }
        }
    }
    let physical = if !core_pairs.is_empty() {
        core_pairs.len()
    } else if logical > 0 {
        logical
    } else {
        1
    };
    (model, physical)
}

fn read_effective_cpuset() -> Option<String> {
    for path in [
        "/sys/fs/cgroup/cpuset.cpus.effective",
        "/sys/fs/cgroup/cpuset/cpuset.cpus",
    ] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

impl BenchKeys {
    fn clone_for_worker(&self) -> Self {
        Self {
            private_key_id: self.private_key_id.clone(),
            public_key_id: self.public_key_id.clone(),
            cms_key_id: self.cms_key_id.clone(),
            sample_signature: self.sample_signature.clone(),
            payload: self.payload.clone(),
            cms_der: self.cms_der.clone(),
            sm2_private_key_id: self.sm2_private_key_id.clone(),
            sm2_public_key_id: self.sm2_public_key_id.clone(),
            ed25519_private_key_id: self.ed25519_private_key_id.clone(),
            ed25519_public_key_id: self.ed25519_public_key_id.clone(),
            ca_key_id: self.ca_key_id.clone(),
            ca_cert_key_id: self.ca_cert_key_id.clone(),
            issued_cert_der: self.issued_cert_der.clone(),
            wrapper_cert_der: self.wrapper_cert_der.clone(),
            scep_pkio_der: self.scep_pkio_der.clone(),
            scep_success_certrep_der: self.scep_success_certrep_der.clone(),
            recipient_nonce: self.recipient_nonce.clone(),
        }
    }
}

async fn prepare_keys(channel: &Channel, args: &Args, payload: &[u8]) -> Result<BenchKeys> {
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel.clone());
    let mut cms_client = CmsServiceClient::new(channel.clone());
    let mut scep_client = ScepServiceClient::new(channel.clone());

    let (priv_pem, cert_der) = load_or_generate_key_material(args)?;

    let t0 = Instant::now();

    let priv_meta = import_private(&mut key_client, priv_pem.clone(), "bench-private", &[], KeyFormat::Unspecified).await?;
    let pub_meta = import_public(&mut key_client, extract_public_pem(&priv_pem)?, "bench-public").await?;
    let cms_meta = import_private(
        &mut key_client,
        priv_pem,
        "bench-cms",
        &cert_der,
        KeyFormat::Der,
    )
    .await?;

    // SCEP: CA + PKIO fixture + issued cert
    let (ca_pem, ca_cert_der) = generate_rsa2048_pem()?;
    let ca_cert = X509::from_der(&ca_cert_der).context("parse CA cert")?;
    let (scep_pkio_der, _expected_csr, pkio_wrapper_cert_der) =
        crypto_offload_server::test_support::generate_scep_pkio(&ca_cert)?;
    let (_issued_pem, issued_cert_der) = generate_rsa2048_pem()?;
    let ca_meta = import_private(
        &mut key_client,
        ca_pem,
        "bench-scep-ca",
        &ca_cert_der,
        KeyFormat::Der,
    )
    .await?;
    let ca_cert_meta = import_certificate(
        &mut key_client,
        ca_cert_der.clone(),
        "bench-scep-ca-cert",
    )
    .await?;

    let recipient_nonce = vec![0x01, 0x02, 0x03, 0x04];
    let scep_success_req = scep_success_certrep_request(
        &ca_meta.key_id,
        &recipient_nonce,
        &issued_cert_der,
        &pkio_wrapper_cert_der,
        ENVELOPE_UNSPECIFIED,
    );
    let scep_success_certrep_der = scep_client
        .build_success_cert_rep(scep_success_req)
        .await?
        .into_inner()
        .certrep_der;

    // Ed25519
    let ed25519_pem = generate_ed25519_pem()?;
    let ed25519_priv = import_private(&mut key_client, ed25519_pem.clone(), "bench-ed25519-priv", &[], KeyFormat::Unspecified).await?;
    let ed25519_pub = import_public(&mut key_client, extract_public_pem(&ed25519_pem)?, "bench-ed25519-pub").await?;

    // SM2（可选）
    let (sm2_private_key_id, sm2_public_key_id) = match generate_sm2_pem() {
            Ok((sm2_pem, sm2_cert_pem)) => {
                let sm2_cert_der = X509::from_pem(&sm2_cert_pem)?.to_der()?;
                let sm2_priv = import_private(
                    &mut key_client,
                    sm2_pem.clone(),
                    "bench-sm2-priv",
                    &sm2_cert_der,
                    KeyFormat::Der,
                )
                .await?;
                let sm2_pub = import_public(
                    &mut key_client,
                    extract_public_pem(&sm2_pem)?,
                    "bench-sm2-pub",
                )
                .await?;
                (Some(sm2_priv.key_id), Some(sm2_pub.key_id))
            }
            Err(e) => {
                eprintln!("WARN: SM2 key generation unavailable: {e}");
                (None, None)
            }
        };

    let cms_der = cms_client
        .build(BuildCmsRequest {
            content: payload.to_vec(),
            sign_key_id: cms_meta.key_id.clone(),
            detached: false,
            ..Default::default()
        })
        .await?
        .into_inner()
        .cms_der;

    println!(
        "key_import_ms: {:.2} (one-time setup, excluded from qps)",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    let sample_signature = sign_client
        .sign(SignRequest {
            key_id: priv_meta.key_id.clone(),
            data: payload.to_vec(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?
        .into_inner()
        .signature;

    Ok(BenchKeys {
        private_key_id: priv_meta.key_id,
        public_key_id: pub_meta.key_id,
        cms_key_id: cms_meta.key_id,
        sample_signature,
        payload: payload.to_vec(),
        cms_der,
        sm2_private_key_id,
        sm2_public_key_id,
        ed25519_private_key_id: ed25519_priv.key_id,
        ed25519_public_key_id: ed25519_pub.key_id,
        ca_key_id: ca_meta.key_id,
        ca_cert_key_id: ca_cert_meta.key_id,
        issued_cert_der,
        wrapper_cert_der: pkio_wrapper_cert_der,
        scep_pkio_der,
        scep_success_certrep_der,
        recipient_nonce,
    })
}

struct ImportedKey {
    key_id: String,
}

async fn import_private(
    client: &mut KeyServiceClient<Channel>,
    key_data: Vec<u8>,
    label: &str,
    cert: &[u8],
    cert_fmt: KeyFormat,
) -> Result<ImportedKey> {
    let meta = client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data,
            label: label.into(),
            certificate_data: cert.to_vec(),
            certificate_format: cert_fmt as i32,
        })
        .await?
        .into_inner()
        .metadata
        .context("import private key")?;
    Ok(ImportedKey {
        key_id: meta.key_id,
    })
}

async fn import_public(
    client: &mut KeyServiceClient<Channel>,
    key_data: Vec<u8>,
    label: &str,
) -> Result<ImportedKey> {
    let meta = client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Public as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data,
            label: label.into(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .metadata
        .context("import public key")?;
    Ok(ImportedKey {
        key_id: meta.key_id,
    })
}

async fn import_certificate(
    client: &mut KeyServiceClient<Channel>,
    cert_der: Vec<u8>,
    label: &str,
) -> Result<ImportedKey> {
    let meta = client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Certificate as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Der as i32,
            certificate_data: cert_der,
            certificate_format: KeyFormat::Der as i32,
            label: label.into(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .metadata
        .context("import certificate")?;
    Ok(ImportedKey {
        key_id: meta.key_id,
    })
}

fn load_or_generate_key_material(args: &Args) -> Result<(Vec<u8>, Vec<u8>)> {
    match (&args.private_key_pem, &args.certificate_pem) {
        (Some(k), Some(c)) => {
            let cert_pem = std::fs::read(c)?;
            let cert_der = X509::from_pem(&cert_pem)?.to_der()?;
            Ok((std::fs::read(k)?, cert_der))
        }
        (None, None) => generate_rsa2048_pem(),
        _ => anyhow::bail!("private-key-pem and certificate-pem must be provided together"),
    }
}

fn extract_public_pem(private_pem: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pem(private_pem).context("parse private pem")?;
    pkey.public_key_to_pem().context("encode public pem")
}

async fn run_one(channel: &Channel, mode: BenchMode, keys: &BenchKeys) -> Result<()> {
    match mode {
        BenchMode::ImportKey => {
            let (pem, _) = generate_rsa2048_pem()?;
            KeyServiceClient::new(channel.clone())
                .import_key(ImportKeyRequest {
                    kind: KeyKind::Private as i32,
                    lifetime: KeyLifetime::Temporary as i32,
                    format: KeyFormat::Pem as i32,
                    key_data: pem,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::Sign => {
            sign_rsa_pkcs1(channel, keys).await?;
        }
        BenchMode::Verify => {
            verify_rsa_pkcs1(channel, keys).await?;
        }
        BenchMode::SignVerify => {
            sign_verify_rsa_pkcs1(channel, keys).await?;
        }
        BenchMode::SignRsaPss => {
            SignServiceClient::new(channel.clone())
                .sign(SignRequest {
                    key_id: keys.private_key_id.clone(),
                    data: keys.payload.clone(),
                    hash_algorithm: HashAlgorithm::HashSha256 as i32,
                    sign_algorithm: SignAlgorithm::SignRsaPss as i32,
                })
                .await?;
        }
        BenchMode::SignVerifyRsaPss => {
            let mut c = SignServiceClient::new(channel.clone());
            let sig = c
                .sign(SignRequest {
                    key_id: keys.private_key_id.clone(),
                    data: keys.payload.clone(),
                    hash_algorithm: HashAlgorithm::HashSha256 as i32,
                    sign_algorithm: SignAlgorithm::SignRsaPss as i32,
                })
                .await?
                .into_inner()
                .signature;
            let _ = c
                .verify(VerifyRequest {
                    key_id: keys.public_key_id.clone(),
                    data: keys.payload.clone(),
                    signature: sig,
                    hash_algorithm: HashAlgorithm::HashSha256 as i32,
                    sign_algorithm: SignAlgorithm::SignRsaPss as i32,
                })
                .await?;
        }
        BenchMode::SignSm2 => {
            let priv_id = keys.sm2_private_key_id.as_ref().context("sm2 key")?;
            SignServiceClient::new(channel.clone())
                .sign(SignRequest {
                    key_id: priv_id.clone(),
                    data: keys.payload.clone(),
                    sign_algorithm: SignAlgorithm::SignSm2 as i32,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::SignVerifySm2 => {
            let priv_id = keys.sm2_private_key_id.as_ref().context("sm2 key")?;
            let pub_id = keys.sm2_public_key_id.as_ref().context("sm2 key")?;
            let mut c = SignServiceClient::new(channel.clone());
            let sig = c
                .sign(SignRequest {
                    key_id: priv_id.clone(),
                    data: keys.payload.clone(),
                    sign_algorithm: SignAlgorithm::SignSm2 as i32,
                    ..Default::default()
                })
                .await?
                .into_inner()
                .signature;
            let _ = c
                .verify(VerifyRequest {
                    key_id: pub_id.clone(),
                    data: keys.payload.clone(),
                    signature: sig,
                    sign_algorithm: SignAlgorithm::SignSm2 as i32,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::SignEd25519 => {
            SignServiceClient::new(channel.clone())
                .sign(SignRequest {
                    key_id: keys.ed25519_private_key_id.clone(),
                    data: keys.payload.clone(),
                    sign_algorithm: SignAlgorithm::SignEd25519 as i32,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::SignVerifyEd25519 => {
            let mut c = SignServiceClient::new(channel.clone());
            let sig = c
                .sign(SignRequest {
                    key_id: keys.ed25519_private_key_id.clone(),
                    data: keys.payload.clone(),
                    sign_algorithm: SignAlgorithm::SignEd25519 as i32,
                    ..Default::default()
                })
                .await?
                .into_inner()
                .signature;
            let _ = c
                .verify(VerifyRequest {
                    key_id: keys.ed25519_public_key_id.clone(),
                    data: keys.payload.clone(),
                    signature: sig,
                    sign_algorithm: SignAlgorithm::SignEd25519 as i32,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsBuild => {
            CmsServiceClient::new(channel.clone())
                .build(BuildCmsRequest {
                    content: keys.payload.clone(),
                    sign_key_id: keys.cms_key_id.clone(),
                    detached: false,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsParse => {
            CmsServiceClient::new(channel.clone())
                .parse(ParseCmsRequest {
                    cms_der: keys.cms_der.clone(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsVerify => {
            CmsServiceClient::new(channel.clone())
                .verify(VerifyCmsRequest {
                    cms_der: keys.cms_der.clone(),
                    verify_key_id: keys.public_key_id.clone(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsBuildParse => {
            let mut c = CmsServiceClient::new(channel.clone());
            let built = c
                .build(BuildCmsRequest {
                    content: keys.payload.clone(),
                    sign_key_id: keys.cms_key_id.clone(),
                    detached: false,
                    ..Default::default()
                })
                .await?
                .into_inner()
                .cms_der;
            let _ = c
                .parse(ParseCmsRequest {
                    cms_der: built,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::ScepCertrepSuccessDefault => {
            scep_build_success_certrep(channel, keys, ENVELOPE_UNSPECIFIED).await?;
        }
        BenchMode::ScepCertrepSuccessAes128Cbc => {
            scep_build_success_certrep(channel, keys, ENVELOPE_AES128_CBC).await?;
        }
        BenchMode::ScepCertrepSuccessAes256Cbc => {
            scep_build_success_certrep(channel, keys, ENVELOPE_AES256_CBC).await?;
        }
        BenchMode::ScepCertrepFailure => {
            ScepServiceClient::new(channel.clone())
                .build_failure_cert_rep(BuildScepFailureCertRepRequest {
                    ca_key_id: keys.ca_key_id.clone(),
                    transaction_id: "bench-tx-failure".into(),
                    recipient_nonce: keys.recipient_nonce.clone(),
                    fail_info: 2,
                    fail_info_text: "benchmark bad request".into(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::ScepCertrepPending => {
            ScepServiceClient::new(channel.clone())
                .build_pending_cert_rep(BuildScepPendingCertRepRequest {
                    ca_key_id: keys.ca_key_id.clone(),
                    transaction_id: "bench-tx-pending".into(),
                    recipient_nonce: keys.recipient_nonce.clone(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::ScepParseRequest => {
            ScepServiceClient::new(channel.clone())
                .parse_request(ParseScepRequestRequest {
                    scep_der: keys.scep_pkio_der.clone(),
                    ca_key_id: keys.ca_key_id.clone(),
                })
                .await?;
        }
        BenchMode::ScepCertrepVerify => {
            CmsServiceClient::new(channel.clone())
                .verify(VerifyCmsRequest {
                    cms_der: keys.scep_success_certrep_der.clone(),
                    verify_key_id: keys.ca_cert_key_id.clone(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::ScepParseBuildSuccess => {
            let mut scep = ScepServiceClient::new(channel.clone());
            let parsed = scep
                .parse_request(ParseScepRequestRequest {
                    scep_der: keys.scep_pkio_der.clone(),
                    ca_key_id: keys.ca_key_id.clone(),
                })
                .await?
                .into_inner();
            let _ = scep
                .build_success_cert_rep(scep_success_certrep_request(
                    &keys.ca_key_id,
                    &keys.recipient_nonce,
                    &keys.issued_cert_der,
                    &parsed.wrapper_cert_der,
                    ENVELOPE_UNSPECIFIED,
                ))
                .await?;
        }
    }
    Ok(())
}

async fn scep_build_success_certrep(
    channel: &Channel,
    keys: &BenchKeys,
    envelope_cipher: i32,
) -> Result<()> {
    ScepServiceClient::new(channel.clone())
        .build_success_cert_rep(scep_success_certrep_request(
            &keys.ca_key_id,
            &keys.recipient_nonce,
            &keys.issued_cert_der,
            &keys.wrapper_cert_der,
            envelope_cipher,
        ))
        .await?;
    Ok(())
}

fn scep_success_certrep_request(
    ca_key_id: &str,
    recipient_nonce: &[u8],
    issued_cert_der: &[u8],
    wrapper_cert_der: &[u8],
    envelope_cipher: i32,
) -> BuildScepSuccessCertRepRequest {
    BuildScepSuccessCertRepRequest {
        ca_key_id: ca_key_id.to_string(),
        transaction_id: format!("bench-tx-success-{envelope_cipher}"),
        recipient_nonce: recipient_nonce.to_vec(),
        issued_cert_der: issued_cert_der.to_vec(),
        wrapper_cert_der: wrapper_cert_der.to_vec(),
        envelope_cipher,
        ..Default::default()
    }
}

async fn sign_rsa_pkcs1(channel: &Channel, keys: &BenchKeys) -> Result<()> {
    SignServiceClient::new(channel.clone())
        .sign(SignRequest {
            key_id: keys.private_key_id.clone(),
            data: keys.payload.clone(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?;
    Ok(())
}

async fn verify_rsa_pkcs1(channel: &Channel, keys: &BenchKeys) -> Result<()> {
    SignServiceClient::new(channel.clone())
        .verify(VerifyRequest {
            key_id: keys.public_key_id.clone(),
            data: keys.payload.clone(),
            signature: keys.sample_signature.clone(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?;
    Ok(())
}

async fn sign_verify_rsa_pkcs1(channel: &Channel, keys: &BenchKeys) -> Result<()> {
    let mut c = SignServiceClient::new(channel.clone());
    let sig = c
        .sign(SignRequest {
            key_id: keys.private_key_id.clone(),
            data: keys.payload.clone(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?
        .into_inner()
        .signature;
    let _ = c
        .verify(VerifyRequest {
            key_id: keys.public_key_id.clone(),
            data: keys.payload.clone(),
            signature: sig,
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await?;
    Ok(())
}

fn generate_rsa2048_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let rsa = Rsa::generate(2048).context("generate rsa")?;
    let pkey = PKey::from_rsa(rsa)?;
    let priv_pem = pkey.private_key_to_pem_pkcs8()?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "benchmark")?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0).context("not_before")?;
    let not_after = Asn1Time::days_from_now(365).context("not_after")?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();
    Ok((priv_pem, cert.to_der()?))
}

fn generate_ed25519_pem() -> Result<Vec<u8>> {
    Ok(PKey::generate_ed25519()?.private_key_to_pem_pkcs8()?)
}

fn generate_sm2_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::SM2)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    let priv_pem = pkey.private_key_to_pem_pkcs8()?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "bench-sm2")?;
    let name = name.build();
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0).context("not_before")?;
    let not_after = Asn1Time::days_from_now(365).context("not_after")?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.sign(&pkey, MessageDigest::sm3())?;
    Ok((priv_pem, builder.build().to_pem()?))
}
