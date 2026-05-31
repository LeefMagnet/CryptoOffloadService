#!/usr/bin/env bash
# WSL 原生冒烟：单元/集成测试 + 全模式 benchmark 采样。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="/home/ubuntu/.cargo/bin:/usr/bin:/bin:${PATH:-}"

echo "==> host environment"
echo "hostname: $(hostname)"
echo "cpu_logical: $(nproc)"
if command -v lscpu >/dev/null; then
  lscpu | awk -F: '/Model name|CPU\\(s\\)|Thread|Core|Socket/{gsub(/^ +/,"",$2); printf "%s: %s\n",$1,$2}'
fi
echo "note: 服务端默认未绑核，与生产 sidecar cpuset 不同；生产请用 taskset + run_suite.sh"
echo

echo "==> cargo test (unit + integration)"
cargo test -p crypto-offload-server -- --nocapture

echo "==> cargo build --release"
cargo build --release -p crypto-offload-server --bin crypto-offload-server --bin crypto-offload-benchmark

TEST_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")
TEST_ADDR="127.0.0.1:${TEST_PORT}"
PROFILE="wsl-smoke,server-unbound,cpu_logical=$(nproc)"

echo "==> start server on ${TEST_ADDR} (no cpuset)"
./target/release/crypto-offload-server --listen "${TEST_ADDR}" &
SERVER_PID=$!
cleanup() { kill "${SERVER_PID}" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 50); do
  if (echo >/dev/tcp/127.0.0.1/${TEST_PORT}) >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

BENCH="./target/release/crypto-offload-benchmark"
run() {
  local mode="$1" total="${2:-100}"
  echo ""
  echo "==> benchmark mode=${mode}"
  "$BENCH" \
    --address "http://${TEST_ADDR}" \
    --mode "${mode}" \
    --clients 4 \
    --total-requests "${total}" \
    --warmup-seconds 1 \
    --server-profile "${PROFILE}"
}

run sign 100
run verify 100
run sign-verify 50
run sign-rsa-pss 100
run sign-ed25519 100
run sign-verify-ed25519 50
run sign-sm2 100
run sign-verify-sm2 50
run cms-build 100
run cms-parse 100
run cms-verify 100
run cms-build-parse 50
run scep-certrep-success 100
run scep-certrep-failure 100
run scep-certrep-pending 100
run scep-parse-request 100
run scep-certrep-verify 100
run scep-parse-build-success 50

echo ""
echo "==> ALL WSL SMOKE TESTS PASSED"
echo "完整压测请: SERVER_PROFILE='your-cpuset' CLIENTS=4 bash scripts/benchmark/run_suite.sh"
