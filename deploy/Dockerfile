FROM rust:1.83-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制 workspace 全部成员
COPY Cargo.toml rust-toolchain.toml ./
COPY server ./server
COPY proto ./proto
COPY sdk/rust ./sdk/rust

# 单元测试 + 集成测试（集成测试自启临时 server，无需外部依赖）
RUN cargo test -p crypto-offload-server --release -- --nocapture

# 构建服务端与压测客户端
RUN cargo build --release -p crypto-offload-server --bin crypto-offload-server --bin crypto-offload-benchmark

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/crypto-offload-server /usr/local/bin/

EXPOSE 50051
ENTRYPOINT ["crypto-offload-server"]
CMD ["--listen", "0.0.0.0:50051"]

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS test-runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 openssl bash \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/crypto-offload-benchmark /usr/local/bin/
COPY deploy/smoke_test.sh /usr/local/bin/smoke_test.sh
RUN chmod +x /usr/local/bin/smoke_test.sh

ENV CRYPTO_OFFLOAD_ADDR=crypto-offload:50051

ENTRYPOINT ["/usr/local/bin/smoke_test.sh"]
