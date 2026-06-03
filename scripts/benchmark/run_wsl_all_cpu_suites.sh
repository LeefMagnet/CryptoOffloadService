#!/usr/bin/env bash
# 顺序跑 1/2/3 核全模式压测并生成 benchmark_cpu_summary.txt
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/benchmark/env_openssl.sh
source "${ROOT}/scripts/benchmark/env_openssl.sh" 35

LOG="${LOG:-/tmp/cos-bench-all.log}"
{
  echo "=== START $(date -Iseconds) ==="
  for s in 1 2 3; do
    echo "=== suite ${s}cpu $(date -Iseconds) ==="
    bash "scripts/benchmark/run_wsl_suite_${s}cpu.sh"
  done
  bash scripts/benchmark/summarize_cpu_reports.sh
  echo "=== DONE $(date -Iseconds) ==="
} 2>&1 | tee -a "${LOG}"
