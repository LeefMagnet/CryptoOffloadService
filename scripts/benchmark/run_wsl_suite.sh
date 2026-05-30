#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

pkill -f crypto-offload-server 2>/dev/null || true
sleep 1

./target/release/crypto-offload-server --listen 127.0.0.1:50051 > /tmp/cos-bench-server.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "SERVER FAILED TO START"
  cat /tmp/cos-bench-server.log
  exit 1
fi

CPU="$(nproc)"
export SERVER_PROFILE="wsl-unbound,cpu_logical=${CPU}"
export CLIENTS="${CLIENTS:-4}"
export TOTAL="${TOTAL:-5000}"
export WARMUP="${WARMUP:-2}"
export OUT="${OUT:-benchmark_report.txt}"

bash scripts/benchmark/run_suite.sh
