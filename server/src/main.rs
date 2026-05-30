use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use crypto_offload_server::{default_crypto_max_inflight, run_server_with_config, ServerConfig};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,
    /// Tokio worker 线程数；0 = 运行时默认（通常 = 逻辑核数）。
    #[arg(long, default_value_t = 0)]
    worker_threads: usize,
    /// Tokio blocking 线程池上限；0 = 运行时默认。建议与 cpuset 核数或 `--crypto-max-inflight` 同量级。
    #[arg(long, default_value_t = 0)]
    crypto_blocking_threads: usize,
    /// 同时进行 OpenSSL 运算的最大 in-flight 数；0 = 可见 CPU 核数。
    #[arg(long, default_value_t = 0)]
    crypto_max_inflight: usize,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if args.worker_threads > 0 {
        builder.worker_threads(args.worker_threads);
    }
    if args.crypto_blocking_threads > 0 {
        builder.max_blocking_threads(args.crypto_blocking_threads);
    }
    let runtime = builder
        .build()
        .context("failed to build tokio runtime")?;

    let crypto_max_inflight = if args.crypto_max_inflight > 0 {
        args.crypto_max_inflight
    } else {
        default_crypto_max_inflight()
    };

    if args.worker_threads > 0 {
        tracing::info!(worker_threads = args.worker_threads, "tokio worker threads");
    }
    if args.crypto_blocking_threads > 0 {
        tracing::info!(
            crypto_blocking_threads = args.crypto_blocking_threads,
            "tokio max blocking threads"
        );
    }
    tracing::info!(crypto_max_inflight, "crypto concurrency limit");

    let addr: SocketAddr = args.listen.parse()?;
    runtime.block_on(run_server_with_config(ServerConfig {
        listen: addr,
        crypto_max_inflight,
    }))
}
