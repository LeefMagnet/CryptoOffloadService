#!/usr/bin/env bash
# 从 run_suite 报告生成 1/2/3 核热路径 QPS 汇总表（不含 KeyService 低频 RPC）
#
# 用法:
#   bash scripts/benchmark/summarize_cpu_reports.sh
#   OUT=benchmark_cpu_summary.txt bash scripts/benchmark/summarize_cpu_reports.sh \
#     benchmark_report_1cpu.txt benchmark_report_2cpu.txt benchmark_report_3cpu.txt

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT="${OUT:-benchmark_cpu_summary.txt}"
REPORTS=("$@")
if [[ ${#REPORTS[@]} -eq 0 ]]; then
  REPORTS=(
    benchmark_report_1cpu.txt
    benchmark_report_2cpu.txt
    benchmark_report_3cpu.txt
  )
fi

MODES=(
  sign verify sign-verify
  sign-rsa-pss sign-verify-rsa-pss
  sign-sm2 sign-verify-sm2
  sign-ed25519 sign-verify-ed25519
  cms-build cms-parse cms-verify cms-build-parse
  scep-certrep-success scep-certrep-failure scep-certrep-pending
  scep-parse-request scep-certrep-verify scep-parse-build-success
  cmp-parse cmp-verify cmp-parse-verify cmp-build
)

parse_report() {
  local file="$1"
  local cpus="" clients="" profile="" cpu_model="" date=""
  if [[ ! -f "${file}" ]]; then
    echo "SKIP:${file}"
    return 0
  fi
  cpus="$(grep -m1 '^server_profile:' "${file}" | sed -n 's/.*server_cpus=\([0-9]*\).*/\1/p')"
  profile="$(grep -m1 '^server_profile:' "${file}" | sed -n 's/server_profile: //p')"
  clients="$(grep -m1 '^clients:' "${file}" | awk '{print $2}')"
  cpu_model="$(grep -m1 '^cpu_model:' "${file}" | sed -n 's/cpu_model: //p')"
  date="$(grep -m1 '^date:' "${file}" | sed -n 's/date: //p')"

  echo "FILE:${file}"
  echo "CPUS:${cpus}"
  echo "CLIENTS:${clients}"
  echo "PROFILE:${profile}"
  echo "CPU_MODEL:${cpu_model}"
  echo "DATE:${date}"

  local mode="" qps="" p50="" p99="" failed=0
  while IFS= read -r line; do
    if [[ "${line}" =~ ^########\ mode=([^[:space:]]+)\ ######## ]]; then
      if [[ -n "${mode}" ]]; then
        if [[ "${failed}" -eq 1 ]]; then
          echo "MODE:${mode}:FAIL"
        else
          echo "MODE:${mode}:${qps}:${p50}:${p99}"
        fi
      fi
      mode="${BASH_REMATCH[1]}"
      qps="" p50="" p99=""
      failed=0
      continue
    fi
    if [[ "${line}" =~ ^WARN:\ mode=${mode}\ failed ]]; then
      failed=1
      continue
    fi
    if [[ "${line}" =~ ^qps:\ ([0-9.]+) ]]; then
      qps="${BASH_REMATCH[1]}"
    fi
    if [[ "${line}" =~ ^latency_us:\ p50=([0-9]+)\ .*p99=([0-9]+) ]]; then
      p50="${BASH_REMATCH[1]}"
      p99="${BASH_REMATCH[2]}"
    fi
  done < "${file}"
  if [[ -n "${mode}" ]]; then
    if [[ "${failed}" -eq 1 ]]; then
      echo "MODE:${mode}:FAIL"
    else
      echo "MODE:${mode}:${qps}:${p50}:${p99}"
    fi
  fi
}

# 收集解析结果到临时目录
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

for f in "${REPORTS[@]}"; do
  base="$(basename "${f}" .txt)"
  parse_report "${f}" > "${TMP}/${base}.parsed" 2>/dev/null || true
done

{
  echo "=== CryptoOffload 全模式压测 — 1/2/3 核汇总 ==="
  echo "generated: $(date -Iseconds 2>/dev/null || date)"
  echo "source: ${REPORTS[*]}"
  echo "clients: 与 server_cpus 1:1（见各报告 clients 行）"
  echo "total_per_mode: 5000 | warmup: 2s | payload: 256B"
  echo

  for f in "${REPORTS[@]}"; do
    base="$(basename "${f}" .txt)"
    p="${TMP}/${base}.parsed"
    [[ -f "${p}" ]] || continue
    cpus="$(grep '^CPUS:' "${p}" | cut -d: -f2)"
    clients="$(grep '^CLIENTS:' "${p}" | cut -d: -f2)"
    profile="$(grep '^PROFILE:' "${p}" | cut -d: -f2-)"
    cpu_model="$(grep '^CPU_MODEL:' "${p}" | cut -d: -f2-)"
    date="$(grep '^DATE:' "${p}" | cut -d: -f2-)"
    echo "--- ${cpus} 核 | clients=${clients} | ${profile} ---"
    echo "    file: ${f}"
    echo "    date: ${date}"
    echo "    cpu:  ${cpu_model}"
    echo
  done

  echo "=== 汇总表（QPS，clients = 核数）==="
  printf "%-22s" "mode"
  for f in "${REPORTS[@]}"; do
    base="$(basename "${f}" .txt)"
    p="${TMP}/${base}.parsed"
    if [[ -f "${p}" ]]; then
      cpus="$(grep '^CPUS:' "${p}" | cut -d: -f2)"
      printf " | %5s核 QPS" "${cpus}"
    fi
  done
  printf " | %8s\n" "QPS/核¹"
  echo "--------------------------------------------------------------------------------"

  for m in "${MODES[@]}"; do
    printf "%-22s" "${m}"
    sum_qps=0
    sum_qps_per_cpu=0
    cnt=0
    cnt_per_cpu=0
    for f in "${REPORTS[@]}"; do
      base="$(basename "${f}" .txt)"
      p="${TMP}/${base}.parsed"
      if [[ ! -f "${p}" ]]; then
        printf " | %9s" "—"
        continue
      fi
      cpus="$(grep '^CPUS:' "${p}" | cut -d: -f2)"
      row="$(grep "^MODE:${m}:" "${p}" || true)"
      if [[ -z "${row}" ]]; then
        printf " | %9s" "—"
        continue
      fi
      if [[ "${row}" == *:FAIL ]]; then
        printf " | %9s" "FAIL"
        continue
      fi
      qps="$(echo "${row}" | cut -d: -f3)"
      printf " | %9.0f" "${qps}"
      sum_qps=$((sum_qps + $(printf "%.0f" "${qps}")))
      cnt=$((cnt + 1))
      if [[ "${cpus}" -gt 0 ]]; then
        sum_qps_per_cpu=$((sum_qps_per_cpu + $(printf "%.0f" "$(echo "scale=0; ${qps} / ${cpus}" | bc 2>/dev/null || echo 0)")))
        cnt_per_cpu=$((cnt_per_cpu + 1))
      fi
    done
    if [[ ${cnt_per_cpu} -ge 1 ]]; then
      avg_per_cpu="$(echo "scale=0; ${sum_qps_per_cpu} / ${cnt_per_cpu}" | bc 2>/dev/null || echo "—")"
      printf " | %8s\n" "${avg_per_cpu}"
    else
      printf " | %8s\n" "—"
    fi
  done
  echo
  echo "¹ QPS/核 列 = 各跑次 (QPS ÷ server_cpus) 的算术平均，便于横向对比模式强度。"
  echo

  echo "=== 分核明细（QPS | P50 µs | P99 µs）==="
  for f in "${REPORTS[@]}"; do
    base="$(basename "${f}" .txt)"
    p="${TMP}/${base}.parsed"
    [[ -f "${p}" ]] || { echo "（缺失 ${f}）"; continue; }
    cpus="$(grep '^CPUS:' "${p}" | cut -d: -f2)"
    clients="$(grep '^CLIENTS:' "${p}" | cut -d: -f2)"
    echo
    echo "#### ${cpus} 核 (clients=${clients})"
    printf "%-26s %10s %10s %10s %10s\n" "mode" "QPS" "P50µs" "P99µs" "QPS/核"
    echo "------------------------------------------------------------------------"
    for m in "${MODES[@]}"; do
      row="$(grep "^MODE:${m}:" "${p}" || true)"
      if [[ -z "${row}" ]]; then
        continue
      fi
      if [[ "${row}" == *:FAIL ]]; then
        printf "%-26s %10s\n" "${m}" "FAIL"
        continue
      fi
      qps="$(echo "${row}" | cut -d: -f3)"
      p50="$(echo "${row}" | cut -d: -f4)"
      p99="$(echo "${row}" | cut -d: -f5)"
      per_cpu="$(echo "scale=0; ${qps} / ${cpus}" | bc 2>/dev/null || echo "?")"
      printf "%-26s %10.0f %10s %10s %10s\n" "${m}" "${qps}" "${p50}" "${p99}" "${per_cpu}"
    done
  done

  echo
  echo "=== 复现 ==="
  echo "  bash scripts/benchmark/run_wsl_suite_1cpu.sh   # OUT=benchmark_report_1cpu.txt"
  echo "  bash scripts/benchmark/run_wsl_suite_2cpu.sh   # OUT=benchmark_report_2cpu.txt"
  echo "  bash scripts/benchmark/run_wsl_suite_3cpu.sh   # OUT=benchmark_report_3cpu.txt"
  echo "  source scripts/benchmark/env_openssl.sh 35   # CMP + SM2 需 OpenSSL 3.x"
  echo "  bash scripts/benchmark/summarize_cpu_reports.sh"
} > "${OUT}"

echo "==> wrote ${OUT}"
