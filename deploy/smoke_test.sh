#!/usr/bin/env bash
# 在 test-runner 容器内执行：全模式 E2E 压测。
set -euo pipefail

ADDR="${CRYPTO_OFFLOAD_ADDR:-crypto-offload:50051}"
URL="http://${ADDR}"
PROFILE="${SERVER_PROFILE:-docker-compose-test,server-cpu-limit-4}"

echo "==> smoke test target: ${URL}"
echo "==> server_profile: ${PROFILE}"

wait_for_server() {
  local host="${ADDR%%:*}"
  local port="${ADDR##*:}"
  echo "==> waiting for ${host}:${port} ..."
  for i in $(seq 1 60); do
    if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      echo "==> server port open (attempt ${i})"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: server not reachable at ${ADDR}" >&2
  exit 1
}

wait_for_server

run_bench() {
  local mode="$1"
  local total="${2:-100}"
  echo ""
  echo "==> benchmark mode=${mode} total=${total}"
  crypto-offload-benchmark \
    --address "${URL}" \
    --mode "${mode}" \
    --clients 4 \
    --total-requests "${total}" \
    --warmup-seconds 2 \
    --payload-size 256 \
    --server-profile "${PROFILE}"
}

run_bench sign 200
run_bench verify 200
run_bench sign-verify 100
run_bench sign-rsa-pss 200
run_bench sign-ed25519 200
run_bench sign-sm2 200
run_bench cms-build 200
run_bench cms-parse 200
run_bench cms-verify 200
run_bench cms-build-parse 100
run_bench scep-certrep-success 200
run_bench scep-certrep-failure 200
run_bench scep-parse-request 200
run_bench scep-certrep-verify 200
run_bench scep-parse-build-success 100

echo ""
echo "==> ALL SMOKE TESTS PASSED"
