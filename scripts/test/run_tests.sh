#!/usr/bin/env bash
# 在 WSL 中构建、启动服务并运行全部测试
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="$HOME/.cargo/bin:$PATH"

echo "==> toolchain"
command -v cargo >/dev/null || { echo "ERROR: cargo not found. Install Rust: curl -sSf https://sh.rustup.rs | sh -s -- -y"; exit 1; }
cargo --version
openssl version

echo "==> build workspace"
cargo build --workspace 2>&1

echo "==> unit + integration tests"
cargo test -p crypto-offload-server -- --nocapture 2>&1

echo "==> start server on random port for smoke test"
TEST_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")
TEST_ADDR="127.0.0.1:${TEST_PORT}"
echo "test server addr=${TEST_ADDR}"

cargo run --release -p crypto-offload-server -- --listen "${TEST_ADDR}" &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true' EXIT

for i in $(seq 1 50); do
  if (echo >/dev/tcp/127.0.0.1/${TEST_PORT}) >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "==> benchmark smoke (sign mode, small sample)"
cargo run --release -p crypto-offload-server --bin crypto-offload-benchmark -- \
  --address "http://${TEST_ADDR}" \
  --mode sign \
  --clients 2 \
  --total-requests 100 \
  --warmup-seconds 1 \
  --payload-size 256

echo ""
echo "==> ALL TESTS PASSED"
