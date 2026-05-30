#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
LOG="$ROOT/build_output.log"

export PATH="/home/ubuntu/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin:${PATH:-}"

{
  echo "=== $(date -Iseconds) ==="
  echo "user=$(id)"
  cargo --version
  rustc --version
  openssl version

  echo "=== cargo build ==="
  cargo build --workspace

  echo "=== cargo test ==="
  cargo test -p crypto-offload-server -- --nocapture

  echo "=== smoke: start server + benchmark ==="
  TEST_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")
  TEST_ADDR="127.0.0.1:${TEST_PORT}"
  echo "test_addr=${TEST_ADDR}"

  cargo run --release -p crypto-offload-server -- --listen "${TEST_ADDR}" &
  SERVER_PID=$!
  cleanup() { kill "${SERVER_PID}" 2>/dev/null || true; }
  trap cleanup EXIT

  for _ in $(seq 1 50); do
    if (echo >/dev/tcp/127.0.0.1/${TEST_PORT}) >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done

  cargo run --release -p crypto-offload-server --bin crypto-offload-benchmark -- \
    --address "http://${TEST_ADDR}" \
    --mode sign \
    --clients 2 \
    --total-requests 50 \
    --warmup-seconds 1

  echo "=== ALL PASSED ==="
} 2>&1 | tee "$LOG"
