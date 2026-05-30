#!/usr/bin/env bash
# CryptoOffload 压测一键脚本（Linux / WSL / macOS）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ADDR="${ADDR:-127.0.0.1:50051}"
MODE="${MODE:-sign}"
CLIENTS="${CLIENTS:-8}"
TOTAL="${TOTAL:-20000}"
WARMUP="${WARMUP:-3}"
PAYLOAD="${PAYLOAD:-256}"

echo "==> building benchmark..."
cargo build --release -p crypto-offload-server --bin crypto-offload-benchmark

BIN="$ROOT/target/release/crypto-offload-benchmark"
if [[ ! -x "$BIN" ]]; then
  BIN="$ROOT/target/release/crypto_offload_benchmark"
fi

SERVER_PROFILE="${SERVER_PROFILE:-unset}"

echo "==> CPU logical cores: $(nproc 2>/dev/null || echo unknown)"
echo "==> benchmark addr=$ADDR mode=$MODE clients=$CLIENTS total=$TOTAL server_profile=$SERVER_PROFILE"
"$BIN" \
  --address "http://${ADDR}" \
  --mode "$MODE" \
  --clients "$CLIENTS" \
  --total-requests "$TOTAL" \
  --warmup-seconds "$WARMUP" \
  --payload-size "$PAYLOAD" \
  --server-profile "$SERVER_PROFILE" \
  ${PRIVATE_KEY_PEM:+--private-key-pem "$PRIVATE_KEY_PEM"} \
  ${CERTIFICATE_PEM:+--certificate-pem "$CERTIFICATE_PEM"}

echo ""
echo "==> 完整调参说明见 docs/BENCHMARK_AND_TUNING.md"
