#!/usr/bin/env bash
# CMP 专项压测：服务端绑定 3 核（默认 cpuset 0-2），与 run_wsl_suite_3cpu.sh 对齐。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/benchmark/bench_defaults.sh
source "${ROOT}/scripts/benchmark/bench_defaults.sh"

export PATH="${HOME}/.cargo/bin:/usr/bin:/bin:${PATH:-}}"

if [[ -z "${OPENSSL_DIR:-}" && -d /opt/openssl35x/lib ]]; then
  # shellcheck source=/dev/null
  source "${ROOT}/scripts/benchmark/env_openssl.sh" 35
fi

SERVER_CPUSET="${SERVER_CPUSET:-0-2}"
SERVER_CPUS="${SERVER_CPUS:-3}"
ADDR="${ADDR:-127.0.0.1:50051}"
CLIENTS="${CLIENTS:-$(bench_default_clients "${SERVER_CPUS}")}"
TOTAL="${TOTAL:-10000}"
WARMUP="${WARMUP:-3}"
OUT="${OUT:-benchmark_cmp_report_3cpu.txt}"

SRV="$ROOT/target/release/crypto-offload-server"
BIN="$ROOT/target/release/crypto-offload-benchmark"

if [[ ! -x "$SRV" ]] || [[ ! -x "$BIN" ]]; then
  cargo build --release -p crypto-offload-server \
    --bin crypto-offload-server --bin crypto-offload-benchmark
fi

pkill -f "target/release/crypto-offload-server" 2>/dev/null || true
sleep 0.5

echo "==> starting server on ${ADDR} with taskset -c ${SERVER_CPUSET} (max-inflight=${SERVER_CPUS})"
taskset -c "${SERVER_CPUSET}" \
  "$SRV" --listen "${ADDR}" \
  --worker-threads "${SERVER_CPUS}" \
  --crypto-blocking-threads "${SERVER_CPUS}" \
  --crypto-max-inflight "${SERVER_CPUS}" \
  --crypto-overload-watermark "${SERVER_CPUS}" \
  > /tmp/crypto-offload-bench-server-3cpu.log 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if (echo >/dev/tcp/"${ADDR%:*}"/"${ADDR#*:}") 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
  echo "SERVER FAILED TO START"
  cat /tmp/crypto-offload-bench-server-3cpu.log
  exit 1
fi
if [[ -r "/proc/${SERVER_PID}/status" ]]; then
  grep -E '^(Name|Cms_allowed_list|Cpus_allowed_list):' "/proc/${SERVER_PID}/status" 2>/dev/null \
    || grep -E '^(Name|Cpus_allowed_list):' "/proc/${SERVER_PID}/status" || true
fi

export START_SERVER=0
export CLIENTS
export TOTAL
export WARMUP
export SERVER_PROFILE="wsl-cpuset-${SERVER_CPUSET},server_cpus=${SERVER_CPUS},openssl35x-rfc"
export OUT
bash "${ROOT}/scripts/benchmark/run_cmp_suite.sh"
