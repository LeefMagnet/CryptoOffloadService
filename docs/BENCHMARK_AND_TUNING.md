# 压测与容器资源配置指南

> 面向运维：如何根据业务 QPS 配置 CryptoOffload 容器 CPU、客户端连接池与服务端参数。

---

## 1. 压测工具

### 1.1 Rust 压测客户端（推荐）

```bash
# 编译
cargo build --release -p crypto-offload-server --bin crypto-offload-benchmark

# 终端1：按目标核数启动服务端（示例绑定 4 核）
taskset -c 4-7 ./target/release/crypto-offload-server --listen 127.0.0.1:50051

# 终端2：签名压测（默认 RSA-2048，自动生成测试密钥）
./target/release/crypto-offload-benchmark \
  --address http://127.0.0.1:50051 \
  --mode sign \
  --clients 4 \
  --total-requests 20000 \
  --warmup-seconds 3 \
  --server-profile "rust-cpuset-4-7,workers=default"
```

**压测启动时会打印环境摘要**（hostname、CPU 型号、逻辑/物理核、进程 cpuset、`clients`、可选 `--server-profile`），便于对照配置解读 QPS。

**输出示例**

```
=== benchmark environment ===
hostname: dev-wsl
cpu_model: Intel(R) Core(TM) i7-12700
cpu_physical_cores: 1
cpu_logical_cores: 16
process_cpuset: (not restricted / unavailable)
benchmark_clients: 4
server_profile: rust-cpuset-4-7,workers=4
note: clients=4 是客户端并发连接数；QPS 受服务端可见 CPU 核数、cpuset、OpenSSL 线程竞争影响

=== benchmark result ===
mode: Sign
total_requests: 20000
clients: 4
payload_bytes: 256
elapsed_ms: 9650.12
qps: 2072.51
latency_us: p50=3800 p95=5200 p99=6800
```

> **重要**：`clients` 是**客户端并发 gRPC 连接数**，不是 CPU 核数。文档中的 QPS 必须同时标注 **服务端 cpuset / Docker cpus 限制** 和 **clients**，否则无法横向对比。

### 1.2 全模式套件（推荐运维使用）

```bash
# 终端1
taskset -c 4-7 ./target/release/crypto-offload-server --listen 127.0.0.1:50051

# 终端2：Sign / Verify / CMS 全部模式 + 环境报告
SERVER_PROFILE="rust-cpuset-4-7" CLIENTS=4 TOTAL=5000 \
  bash scripts/benchmark/run_suite.sh
```

报告写入 `benchmark_report.txt`，包含 CPU 型号、`nproc`、各 mode 的 QPS/P99。

### 1.3 单模式脚本

```bash
# Linux / WSL
MODE=sign CLIENTS=4 SERVER_PROFILE="wsl-unbound" ./scripts/benchmark/run_benchmark.sh
```

环境变量：

| 变量 | 默认 | 说明 |
|------|------|------|
| `ADDR` | `127.0.0.1:50051` | 服务地址 |
| `MODE` | `sign` | 见下表 |
| `CLIENTS` | `8` | **客户端**并发连接数 |
| `TOTAL` | `20000` | 总请求数 |
| `WARMUP` | `3` | 预热秒数 |
| `SERVER_PROFILE` | `unset` | 运维标注：如 `rust-cpuset-4-7,docker-cpus=4` |

### 1.4 Python 压测（可选）

```bash
pip install grpcio protobuf
make proto
python scripts/benchmark/bench_python.py --mode sign --clients 8
```

---

## 2. 压测模式说明

| mode | 测量内容 | 密钥 ImportKey |
|------|----------|----------------|
| `import-key` | 仅 ImportKey QPS | 每次请求都 import |
| `sign` | Sign QPS | 压测前 import 一次，**不计入** QPS |
| `verify` | Verify QPS | 压测前 import 公钥 + 预生成签名 |
| `sign-verify` | 签名+验签往返 | 各 import 一次 |
| `cms-build` | CMS 封包 QPS | 压测前 import 私钥+证书 |
| `cms-parse` | CMS 解析 QPS | 压测前预生成一份 CMS DER |
| `cms-verify` | CMS 验签 QPS | 同上 |
| `cms-build-parse` | CMS 封包→解析往返 | 同上 |

> **Sign/Verify/CMS 压测反映的是「已有 key_id 后的运算性能」**，与生产路径一致（ImportKey 只在启动或轮换时调用）。

---

## 3. 参考性能（必须标注环境）

下列数值来自 **WSL 冒烟**（`wsl_smoke_test.sh`），环境特征：

| 项 | 值 |
|----|-----|
| 服务端 cpuset | **未绑核**（与 benchmark 同机争用全部逻辑核） |
| `clients` | 4 |
| 算法 | RSA-2048 + SHA-256 |
| payload | 256 B |
| 样本量 | 100 请求/模式（非正式压测） |

| mode | clients | QPS | P50 (µs) | P99 (µs) |
|------|---------|-----|----------|----------|
| sign | 4 | ~4083 | ~889 | ~1941 |
| sign-verify | 4 | ~2392 | ~1458 | ~1865 |
| cms-build | 4 | *待 run_suite 更新* | | |
| cms-parse | 4 | *待 run_suite 更新* | | |
| cms-verify | 4 | *待 run_suite 更新* | | |

**正式压测请按目标生产配置填写**，例如：

```bash
# 8 核机器：Rust 独占 4 核
taskset -c 4-7 ./target/release/crypto-offload-server --listen 127.0.0.1:50051
SERVER_PROFILE="8c-host,rust-cpuset-4-7" CLIENTS=4 bash scripts/benchmark/run_suite.sh
```

线性缩放经验（参考 ScepAccelerator）：

- RSA 签名 CPU 密集，QPS 约与 **Rust 独占核数** 成正比
- 客户端 `clients` 宜 ≈ 服务端 CPU 核数 ~ 2×核数，过大只会排队

---

## 4. 容器资源配置

### 4.1 8 核机器推荐拆分（Sidecar 模式）

```
┌─────────────────────────────────────────────┐
│ 业务进程 (Go/Java)     cpuset 0-3  (4核)    │
│ CryptoOffload (Rust)   cpuset 4-7  (4核)    │
└─────────────────────────────────────────────┘
```

**docker-compose 示例**

```yaml
services:
  crypto-offload:
    image: crypto-offload-server:latest
    cpuset: "4-7"
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: 512M
    command:
      - --listen
      - "0.0.0.0:50051"
      - --worker-threads
      - "4"
      - --crypto-blocking-threads
      - "4"
```

压测时在 test-runner 侧设置：

```bash
SERVER_PROFILE="docker-cpuset-4-7,cpus-limit=4" CLIENTS=4 bash deploy/smoke_test.sh
```

### 4.2 参数对照表

| 参数 | 位置 | 建议 | 说明 |
|------|------|------|------|
| `cpuset` / `cpus` | Docker | = Rust 核数 | 与业务进程错开 |
| `--worker-threads` | 服务端 | = Rust 核数 | Tokio worker |
| `--crypto-blocking-threads` | 服务端 | = Rust 核数 | OpenSSL 阻塞任务 |
| `MaxOpen` | 客户端连接池 | = 核数 ~ 2×核数 | 见 SDK pool 配置 |
| `MinIdle` | 客户端连接池 | 2 ~ 4 | 减少冷启动延迟 |
| `--server-profile` | 压测客户端 | 必填（运维） | 记录上述配置，写入报告 |

### 4.3 按目标 QPS 粗算

设单机 RSA-2048 Sign 压测 QPS = `Q`（4 核），目标业务 QPS = `T`：

| 条件 | 配置 |
|------|------|
| `T ≤ Q` | Rust 4 核足够 |
| `T ≤ 2Q` | Rust 8 核，或水平扩容 2 实例 + 负载均衡 |
| `T > 2Q` | 多实例 + 客户端连接池分散到各实例 |

P99 延迟要求：

- P99 < 10ms：clients ≤ QPS × 0.01，避免排队
- 若 P99 随 clients 线性恶化 → 减小 `MaxOpen` 或增加 Rust 核数

---

## 5. 生产检查清单

- [ ] 压测 **全部相关 mode**（sign / cms-build / cms-parse 等）达到业务目标 QPS 的 **1.5×** 余量
- [ ] 报告含 **CPU 型号、逻辑核、服务端 cpuset、clients**
- [ ] 业务与 Rust **cpuset 不重叠**
- [ ] 永久密钥在启动时 ImportKey，**不在热路径重复 import**
- [ ] 客户端 `MaxOpen` ≤ 服务端 `--crypto-blocking-threads` × 2
- [ ] 监控 gRPC 延迟 P95/P99 与 CPU 使用率

---

## 6. 与 ScepAccelerator 的对比

| 项目 | ScepAccelerator | CryptoOffloadService |
|------|-----------------|----------------------|
| 协议 | UDS 二进制帧 | gRPC Protobuf |
| 压测工具 | `benchmark --mode parse/build` | `crypto-offload-benchmark --mode cms-parse/cms-build` |
| 密钥 | 启动时读 DER 文件 | ImportKey → 内存 `PKey` |
| 绑核 | Go 0-3 / Rust 4-7 | 同样适用 |

SCEP 场景可将 `parse+build` 对标为 `cms-build-parse` + 业务 RA 调用。
