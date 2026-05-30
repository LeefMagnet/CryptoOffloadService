#!/usr/bin/env bash
# 全模式压测套件：Sign/Verify/CMS/SCEP/国密 全部 mode。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.cargo/bin:/usr/bin:/bin:${PATH:-}}"

ADDR="${ADDR:-127.0.0.1:50051}"
CLIENTS="${CLIENTS:-4}"
TOTAL="${TOTAL:-5000}"
WARMUP="${WARMUP:-2}"
PAYLOAD="${PAYLOAD:-256}"
SERVER_PROFILE="${SERVER_PROFILE:-unset}"
OUT="${OUT:-benchmark_report.txt}"

BIN="$ROOT/target/release/crypto-offload-benchmark"
if [[ ! -x "$BIN" ]]; then
  echo "==> building benchmark..."
  cargo build --release -p crypto-offload-server --bin crypto-offload-benchmark
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
    --payload-size "${PAYLOAD}" \
    --server-profile "${SERVER_PROFILE}"; then
    echo "WARN: mode=${mode} failed (may be unsupported on this OpenSSL build)"
  fi
  echo
}

{
  echo "=== CryptoOffload benchmark suite ==="
  echo "date: $(date -Iseconds)"
  echo "addr: ${ADDR}"
  echo "clients: ${CLIENTS}"
  echo "total_per_mode: ${TOTAL}"
  echo "payload_bytes: ${PAYLOAD}"
  echo "server_profile: ${SERVER_PROFILE}"
  echo "cpu_logical: $(nproc 2>/dev/null || echo unknown)"
  if command -v lscpu >/dev/null; then
    echo "cpu_model: $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
    echo "cpu_socket_cores: $(lscpu | awk -F: '/Core\\(s\\) per socket/{print $2}' | xargs)"
    echo "cpu_threads_per_core: $(lscpu | awk -F: '/Thread\\(s\\) per core/{print $2}' | xargs)"
  fi
  if [[ -r /sys/fs/cgroup/cpuset.cpus.effective ]]; then
    echo "process_cpuset: $(cat /sys/fs/cgroup/cpuset.cpus.effective)"
  fi
  echo

  MODES=(
    sign verify sign-verify
    sign-rsa-pss sign-verify-rsa-pss
    sign-sm2 sign-verify-sm2
    sign-ed25519 sign-verify-ed25519
    cms-build cms-parse cms-verify cms-build-parse
    scep-certrep-success scep-certrep-failure
    scep-parse-request scep-certrep-verify scep-parse-build-success
    import-key
  )
  for mode in "${MODES[@]}"; do
    run_mode "${mode}"
  done
} 2>&1 | tee "${OUT}"

echo "==> report saved to ${OUT}"
