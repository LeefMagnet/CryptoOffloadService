//! gRPC 压测客户端：测量 Sign/Verify/CMS/ImportKey 吞吐与延迟。

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
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
use cryptooffload::v1::sign_service_client::SignServiceClient;
use cryptooffload::v1::{
    BuildCmsRequest, HashAlgorithm, ImportKeyRequest, KeyFormat, KeyKind, KeyLifetime,
    ParseCmsRequest, SignAlgorithm, SignRequest, VerifyCmsRequest, VerifyRequest,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchMode {
    ImportKey,
    Sign,
    Verify,
    SignVerify,
    CmsBuild,
    CmsParse,
    CmsVerify,
    /// CMS 封包 + 解析往返（生产常见：build 响应 / parse 请求）
    CmsBuildParse,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    address: String,
    #[arg(long, value_enum, default_value_t = BenchMode::Sign)]
    mode: BenchMode,
    /// 并发 gRPC 连接数（客户端侧），不是服务端 CPU 核数
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
    /// 运维备注：服务端 cpuset / worker 配置（仅写入报告，不影响压测）
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    print_env_banner(&args);

    let channel = Channel::from_shared(args.address.clone())
        .context("invalid address")?
        .connect()
        .await
        .context("connect grpc")?;

    let payload = vec![0xABu8; args.payload_size.max(1)];
    let keys = prepare_keys(&channel, &args, &payload).await?;

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
            "server_profile: (unset — 请用 --server-profile 标注服务端 cpuset/worker 配置，例如 \"rust-cpuset-4-7,workers=4\")"
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
        }
    }
}

async fn prepare_keys(channel: &Channel, args: &Args, payload: &[u8]) -> Result<BenchKeys> {
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel.clone());
    let mut cms_client = CmsServiceClient::new(channel.clone());

    let (priv_pem, cert_pem) = load_or_generate_key_material(args)?;
    let cert_der = X509::from_pem(&cert_pem)?.to_der()?;

    let t0 = Instant::now();

    let priv_meta = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem.clone(),
            label: "bench-private".into(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .metadata
        .context("import private key")?;

    let pub_meta = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Public as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: extract_public_pem(&priv_pem)?,
            label: "bench-public".into(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .metadata
        .context("import public key")?;

    let cms_meta = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem,
            label: "bench-cms".into(),
            certificate_data: cert_der,
            certificate_format: KeyFormat::Der as i32,
        })
        .await?
        .into_inner()
        .metadata
        .context("import cms key")?;

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

    let import_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "key_import_ms: {:.2} (one-time setup, excluded from qps)",
        import_ms
    );

    let sig = sign_client
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
        sample_signature: sig,
        payload: payload.to_vec(),
        cms_der,
    })
}

fn load_or_generate_key_material(args: &Args) -> Result<(Vec<u8>, Vec<u8>)> {
    match (&args.private_key_pem, &args.certificate_pem) {
        (Some(k), Some(c)) => Ok((std::fs::read(k)?, std::fs::read(c)?)),
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
            let mut c = KeyServiceClient::new(channel.clone());
            let _ = c
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
            let mut c = SignServiceClient::new(channel.clone());
            let _ = c
                .sign(SignRequest {
                    key_id: keys.private_key_id.clone(),
                    data: keys.payload.clone(),
                    hash_algorithm: HashAlgorithm::HashSha256 as i32,
                    sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
                })
                .await?;
        }
        BenchMode::Verify => {
            let mut c = SignServiceClient::new(channel.clone());
            let _ = c
                .verify(VerifyRequest {
                    key_id: keys.public_key_id.clone(),
                    data: keys.payload.clone(),
                    signature: keys.sample_signature.clone(),
                    hash_algorithm: HashAlgorithm::HashSha256 as i32,
                    sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
                })
                .await?;
        }
        BenchMode::SignVerify => {
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
        }
        BenchMode::CmsBuild => {
            let mut c = CmsServiceClient::new(channel.clone());
            let _ = c
                .build(BuildCmsRequest {
                    content: keys.payload.clone(),
                    sign_key_id: keys.cms_key_id.clone(),
                    detached: false,
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsParse => {
            let mut c = CmsServiceClient::new(channel.clone());
            let _ = c
                .parse(ParseCmsRequest {
                    cms_der: keys.cms_der.clone(),
                    ..Default::default()
                })
                .await?;
        }
        BenchMode::CmsVerify => {
            let mut c = CmsServiceClient::new(channel.clone());
            let _ = c
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
    }
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
    let cert_pem = cert.to_pem()?;

    Ok((priv_pem, cert_pem))
}
