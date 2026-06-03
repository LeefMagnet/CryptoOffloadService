#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

SERVER_CPUSET="${SERVER_CPUSET:-0-1}"
SERVER_CPUS="${SERVER_CPUS:-2}"

pkill -f crypto-offload-server 2>/dev/null || true
sleep 1

taskset -c "${SERVER_CPUSET}" \
  ./target/release/crypto-offload-server --listen 127.0.0.1:50051 \
  > /tmp/cos-bench-server-3cpu.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "SERVER FAILED TO START"
  cat /tmp/cos-bench-server-3cpu.log
  exit 1
fi

echo "server_pid=${SERVER_PID}"
if [[ -r "/proc/${SERVER_PID}/status" ]]; then
  grep -E '^(Name|Cpus_allowed_list):' "/proc/${SERVER_PID}/status" || true
fi

export SERVER_PROFILE="wsl-cpuset-${SERVER_CPUSET},server_cpus=${SERVER_CPUS}"
export CLIENTS="${CLIENTS:-4}"
export TOTAL="${TOTAL:-5000}"
export WARMUP="${WARMUP:-2}"
export OUT="${OUT:-benchmark_report_3cpu.txt}"

bash scripts/benchmark/run_suite.sh
