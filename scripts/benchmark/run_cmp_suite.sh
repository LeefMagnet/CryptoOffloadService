#!/usr/bin/env bash
# CMP 专项压测：parse / verify / parse-verify / build
# 推荐先: source scripts/benchmark/env_openssl.sh 35 && ./scripts/benchmark/run_cmp_suite.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/benchmark/bench_defaults.sh
source "${ROOT}/scripts/benchmark/bench_defaults.sh"

export PATH="${HOME}/.cargo/bin:/usr/bin:/bin:${PATH:-}"

# 若未 source env_openssl.sh，默认尝试 /opt/openssl35x
if [[ -z "${OPENSSL_DIR:-}" && -d /opt/openssl35x/lib ]]; then
  # shellcheck source=/dev/null
  source "${ROOT}/scripts/benchmark/env_openssl.sh" 35
fi

ADDR="${ADDR:-127.0.0.1:50051}"
SERVER_CPUS="${SERVER_CPUS:-0}"
if [[ "${SERVER_CPUS}" -eq 0 && "${START_SERVER:-1}" == "1" ]]; then
  SERVER_CPUS="$(bench_logical_cpus)"
fi
CLIENTS="${CLIENTS:-$(bench_default_clients "${SERVER_CPUS}")}"
TOTAL="${TOTAL:-10000}"
WARMUP="${WARMUP:-3}"
SERVER_PROFILE="${SERVER_PROFILE:-wsl-unbound}"
OUT="${OUT:-benchmark_cmp_report.txt}"

BIN="$ROOT/target/release/crypto-offload-benchmark"
SRV="$ROOT/target/release/crypto-offload-server"
START_SERVER="${START_SERVER:-1}"

if [[ ! -x "$BIN" ]] || [[ ! -x "$SRV" ]]; then
  echo "==> building server + benchmark (OPENSSL_DIR=${OPENSSL_DIR:-system})..."
  cargo build --release -p crypto-offload-server --bin crypto-offload-server --bin crypto-offload-benchmark
fi

if [[ "${START_SERVER}" == "1" ]]; then
  pkill -f "target/release/crypto-offload-server" 2>/dev/null || true
  sleep 0.5
  echo "==> starting server on ${ADDR} (crypto-max-inflight=${SERVER_CPUS}) ..."
  nohup "$SRV" --listen "${ADDR}" \
    --crypto-max-inflight "${SERVER_CPUS}" \
    --crypto-overload-watermark "${SERVER_CPUS}" \
    > /tmp/crypto-offload-bench-server.log 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 30); do
    if (echo >/dev/tcp/"${ADDR%:*}"/"${ADDR#*:}") 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  trap 'kill "${SERVER_PID}" 2>/dev/null || true' EXIT
fi

run_mode() {
  local mode="$1"
  echo "######## mode=${mode} ########"
  if ! "$BIN" \
    --address "http://${ADDR}" \
    --mode "${mode}" \
    --clients "${CLIENTS}" \
    --total-requests "${TOTAL}" \
    --warmup-seconds "${WARMUP}" \
    --server-profile "${SERVER_PROFILE}"; then
    echo "WARN: mode=${mode} failed (CMP may be unsupported on this OpenSSL build)"
  fi
  echo
}

{
  echo "=== CryptoOffload CMP benchmark ==="
  echo "date: $(date -Iseconds)"
  echo "addr: ${ADDR}"
  echo "clients: ${CLIENTS}"
  echo "total_per_mode: ${TOTAL}"
  echo "server_profile: ${SERVER_PROFILE}"
  echo "server_cpus: ${SERVER_CPUS}"
  echo "cpu_logical: $(nproc 2>/dev/null || echo unknown)"
  if command -v lscpu >/dev/null; then
    echo "cpu_model: $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
  fi
  echo

  for mode in cmp-parse cmp-verify cmp-parse-verify cmp-build; do
    run_mode "${mode}"
  done
} 2>&1 | tee "${OUT}"

echo "==> report saved to ${OUT}"
