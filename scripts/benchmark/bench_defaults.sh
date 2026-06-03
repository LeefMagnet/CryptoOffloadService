#!/usr/bin/env bash
# 压测默认：clients 与服务端可见 CPU / max-inflight 对齐（1:1）。
# 在 overload 水位 = max-inflight 时，clients > 核数会触发 RESOURCE_EXHAUSTED。
#
# 用法: source scripts/benchmark/bench_defaults.sh
#       CLIENTS="${CLIENTS:-$(bench_default_clients "${SERVER_CPUS:-3}")}"

bench_logical_cpus() {
  nproc 2>/dev/null || echo 4
}

# 推荐 clients = server_cpus（1:1）；未指定 server_cpus 时用逻辑核数。
bench_default_clients() {
  local server_cpus="${1:-0}"
  if [[ "${server_cpus}" -gt 0 ]]; then
    echo "${server_cpus}"
  else
    bench_logical_cpus
  fi
}
