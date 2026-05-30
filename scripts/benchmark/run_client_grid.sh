#!/usr/bin/env bash
# Server 核数 × client 并发网格压测（默认 sign 模式）。
# 用法:
#   bash scripts/benchmark/run_client_grid.sh
#   MODE=sign-verify SERVER_GRID="2:0-1:4,6,8;3:0-2:6,8,12" bash scripts/benchmark/run_client_grid.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.cargo/bin:/usr/bin:/bin:${PATH:-}}"

ADDR="${ADDR:-127.0.0.1:50051}"
MODE="${MODE:-sign}"
TOTAL="${TOTAL:-5000}"
WARMUP="${WARMUP:-2}"
PAYLOAD="${PAYLOAD:-256}"
OUT="${OUT:-benchmark_client_grid.txt}"
# 格式: "cpus:cpuset:clients,clients;..."
SERVER_GRID="${SERVER_GRID:-2:0-1:4,6,8;3:0-2:6,8,12}"

BIN="$ROOT/target/release/crypto-offload-benchmark"
SERVER_BIN="$ROOT/target/release/crypto-offload-server"

if [[ ! -x "$BIN" ]]; then
  echo "==> building..."
  cargo build --release -p crypto-offload-server --bin crypto-offload-server --bin crypto-offload-benchmark
fi

kill_server() {
  pkill -f 'crypto-offload-server --listen' 2>/dev/null || true
  sleep 1
}

start_server() {
  local cpus="$1"
  local cpuset="$2"
  kill_server
  taskset -c "${cpuset}" \
    "$SERVER_BIN" \
    --listen "${ADDR}" \
    --worker-threads "${cpus}" \
    --crypto-blocking-threads "$((cpus * 2))" \
    --crypto-max-inflight "${cpus}" \
    > /tmp/cos-grid-server.log 2>&1 &
  SERVER_PID=$!
  sleep 2
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "SERVER FAILED (cpus=${cpus} cpuset=${cpuset})"
    cat /tmp/cos-grid-server.log
    exit 1
  fi
}

run_one() {
  local cpus="$1"
  local cpuset="$2"
  local clients="$3"
  local profile="grid,server_cpus=${cpus},cpuset=${cpuset},clients=${clients}"

  {
    echo "######## server_cpus=${cpus} cpuset=${cpuset} clients=${clients} mode=${MODE} ########"

    if ! "$BIN" \
      --address "http://${ADDR}" \
      --mode "${MODE}" \
      --clients "${clients}" \
      --total-requests "${TOTAL}" \
      --warmup-seconds "${WARMUP}" \
      --payload-size "${PAYLOAD}" \
      --server-profile "${profile}"; then
      echo "WARN: failed server_cpus=${cpus} clients=${clients}"
      return 1
    fi
    echo
  } | tee -a "${OUT}"
}

parse_and_summarize() {
  python3 - "$OUT" <<'PY'
import re, sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
blocks = re.split(r"######## server_cpus=", text)
rows = []
for block in blocks[1:]:
    header = re.match(r"(\d+) cpuset=([0-9,-]+) clients=(\d+) mode=(\S+) ########", block)
    if not header:
        continue
    cpus, cpuset, clients, mode = header.groups()
    qps_m = re.search(r"^qps: ([0-9.]+)", block, re.M)
    p50_m = re.search(r"latency_us: p50=(\d+)", block)
    p99_m = re.search(r"latency_us: p50=\d+ p95=\d+ p99=(\d+)", block)
    if not qps_m:
        continue
    rows.append({
        "cpus": int(cpus),
        "cpuset": cpuset,
        "clients": int(clients),
        "mode": mode,
        "qps": float(qps_m.group(1)),
        "p50_us": int(p50_m.group(1)) if p50_m else 0,
        "p99_us": int(p99_m.group(1)) if p99_m else 0,
    })

if not rows:
    print("（无有效结果可汇总）")
    sys.exit(0)

print("\n=== 汇总表 ===")
print(f"{'server_cpus':>11} | {'clients':>7} | {'QPS':>8} | {'P50 µs':>8} | {'P99 µs':>8} | {'QPS/核':>8}")
print("-" * 65)
for r in rows:
    per_core = r["qps"] / r["cpus"]
    print(f"{r['cpus']:>11} | {r['clients']:>7} | {r['qps']:>8.0f} | {r['p50_us']:>8} | {r['p99_us']:>8} | {per_core:>8.0f}")

print("\n=== 推荐 clients（按 server_cpus 分组）===")
by_cpu = {}
for r in rows:
    by_cpu.setdefault(r["cpus"], []).append(r)

for cpus in sorted(by_cpu):
    group = sorted(by_cpu[cpus], key=lambda x: x["clients"])
    best_qps = max(group, key=lambda x: x["qps"])
    # 效率：QPS 达到峰值 98% 以上且 P99 未超过最佳 QPS 配置的 1.5 倍
    threshold = best_qps["qps"] * 0.98
    candidates = [g for g in group if g["qps"] >= threshold]
    best_p99 = min(candidates, key=lambda x: x["p99_us"])
    balanced = min(group, key=lambda x: (-x["qps"] / cpus, x["p99_us"]))
    print(f"\nserver_cpus={cpus}:")
    print(f"  最高 QPS     : clients={best_qps['clients']} → {best_qps['qps']:.0f} QPS (P99={best_qps['p99_us']} µs)")
    print(f"  推荐（均衡） : clients={best_p99['clients']} → {best_p99['qps']:.0f} QPS (P99={best_p99['p99_us']} µs, ≥98% peak QPS)")
    print(f"  经验规则     : clients ≈ {cpus}×2 = {cpus*2} 时 QPS={next((g['qps'] for g in group if g['clients']==cpus*2), 0):.0f}" if any(g['clients']==cpus*2 for g in group) else f"  经验规则     : clients ≈ {cpus}×2（未测）")
    for g in group:
        tag = []
        if g is best_qps:
            tag.append("peak-QPS")
        if g is best_p99:
            tag.append("推荐")
        note = f" [{', '.join(tag)}]" if tag else ""
        print(f"    clients={g['clients']:>2}: {g['qps']:>7.0f} QPS  P99={g['p99_us']:>6} µs{note}")
PY
}

kill_server
: > "${OUT}"

{
  echo "=== Client grid benchmark ==="
  echo "date: $(date -Iseconds)"
  echo "mode: ${MODE}"
  echo "total_per_run: ${TOTAL}"
  echo "warmup_s: ${WARMUP}"
  echo "payload_bytes: ${PAYLOAD}"
  echo "server_grid: ${SERVER_GRID}"
  if command -v lscpu >/dev/null; then
    echo "cpu_model: $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
  fi
  echo "cpu_logical_host: $(nproc 2>/dev/null || echo unknown)"
  echo
} | tee "${OUT}"

IFS=';' read -ra GRID_ENTRIES <<< "${SERVER_GRID}"
for entry in "${GRID_ENTRIES[@]}"; do
  cpus="${entry%%:*}"
  rest="${entry#*:}"
  cpuset="${rest%%:*}"
  clients_csv="${rest#*:}"
  IFS=',' read -ra CLIENT_LIST <<< "${clients_csv}"
  start_server "${cpus}" "${cpuset}"
  for clients in "${CLIENT_LIST[@]}"; do
    run_one "${cpus}" "${cpuset}" "${clients}" || true
  done
done

kill_server

{
  echo
  parse_and_summarize
} | tee -a "${OUT}"

echo "==> report: ${OUT}"
