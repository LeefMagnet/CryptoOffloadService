use std::net::SocketAddr;

use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,
    #[arg(long, default_value_t = 0)]
    worker_threads: usize,
    #[arg(long, default_value_t = 0)]
    crypto_blocking_threads: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    if args.worker_threads > 0 {
        tracing::info!(worker_threads = args.worker_threads, "worker thread hint");
    }
    if args.crypto_blocking_threads > 0 {
        tracing::info!(
            crypto_blocking_threads = args.crypto_blocking_threads,
            "crypto blocking thread hint"
        );
    }

    let addr: SocketAddr = args.listen.parse()?;
    tracing::info!(%addr, "crypto-offload-server listening");
    crypto_offload_server::run_server(addr).await
}
