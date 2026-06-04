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

### 1.1.1 推荐 `clients` 与核数对齐（1:1，非 2×）

自 v0.2.4 起服务端默认启用 **`--crypto-max-inflight` / `--crypto-overload-watermark`**（与可见 CPU 核数或 cpuset 一致）。在此配置下：

| 规则 | 说明 |
|------|------|
| **推荐** | `clients`（或 SDK `MaxOpen`）**= 服务端 CPU 核数**（1:1） |
| **禁止** | `clients` **> max-inflight** → 大量 `RESOURCE_EXHAUSTED`（overload 直接拒绝），压测结果失真 |
| **历史** | 旧文档「2× 核数」适用于**无 overload 水位**或水位显著高于 inflight 的场景；与当前默认保护策略不再匹配 |

`scripts/benchmark/bench_defaults.sh` 与各套件脚本已按 **1:1** 设置默认 `CLIENTS`（未绑核时用 `nproc`）。

### 1.2 全模式套件（推荐运维使用）

```bash
# 终端1
taskset -c 4-7 ./target/release/crypto-offload-server --listen 127.0.0.1:50051

# 终端2：Sign / Verify / CMS 全部模式 + 环境报告
SERVER_PROFILE="rust-cpuset-4-7" SERVER_CPUS=4 CLIENTS=4 TOTAL=5000 \
  bash scripts/benchmark/run_suite.sh
```

报告写入 `benchmark_report.txt`，包含 CPU 型号、`nproc`、各 mode 的 QPS/P99。

### 1.3 Client 并发网格压测（推荐调优 clients）

自动扫描 **server 核数 × clients** 组合，找出连接池 `MaxOpen` 的推荐值：

```bash
# 终端1：脚本内按 cpuset 启动 server（含 --crypto-max-inflight = 核数）
# 默认 grid: 2 核 clients=2,3,4；3 核 clients=3,4,6（以 1×核数为中心）
bash scripts/benchmark/run_client_grid.sh

# 自定义
MODE=sign SERVER_GRID="2:0-1:2,3,4;3:0-2:3,4,6" TOTAL=5000 \
  bash scripts/benchmark/run_client_grid.sh
```

报告写入 `benchmark_client_grid.txt`。详见 **§3.2** 参考数据与推荐组合。

### 1.4 CMP 专项压测（需 OpenSSL 3.x CMP 符号）

自编译 OpenSSL（如 `/opt/openssl30x`、`/opt/openssl35x`）时，**构建与运行**须使用同一套库：

```bash
source scripts/benchmark/env_openssl.sh 35   # 或 30
cargo build --release -p crypto-offload-server \
  --bin crypto-offload-server --bin crypto-offload-benchmark

# 一键：自动起服 + 4 个 CMP mode（clients 默认 = 逻辑核数，报告 benchmark_cmp_report.txt）
./scripts/benchmark/run_cmp_suite.sh

# 3 核服务端（taskset 0-2，clients=3）
bash scripts/benchmark/run_cmp_suite_3cpu.sh

# 单模式（clients 建议 = 服务端核数）
./target/release/crypto-offload-benchmark \
  --address http://127.0.0.1:50051 \
  --mode cmp-parse-verify \
  --clients 3 --total-requests 10000
```

| mode | 测量内容 |
|------|----------|
| `cmp-parse` | ParsePkiMessage |
| `cmp-verify` | VerifyPkiMessageProtection |
| `cmp-parse-verify` | ParseAndVerifyPkiMessage（推荐主路径） |
| `cmp-build` | BuildProtectedPkiMessage |

### 1.5 单模式脚本

```bash
# Linux / WSL
MODE=sign CLIENTS=4 SERVER_PROFILE="wsl-unbound" ./scripts/benchmark/run_benchmark.sh
```

环境变量：

| 变量 | 默认 | 说明 |
|------|------|------|
| `ADDR` | `127.0.0.1:50051` | 服务地址 |
| `MODE` | `sign` | 见下表 |
| `CLIENTS` | `= SERVER_CPUS` 或逻辑核数 | **客户端**并发连接数（见 §1.1.1，宜 1:1） |
| `SERVER_CPUS` | `0`（自动） | 标注/推导推荐 clients；绑核脚本会设为 cpuset 核数 |
| `TOTAL` | `20000` | 总请求数 |
| `WARMUP` | `3` | 预热秒数 |
| `SERVER_PROFILE` | `unset` | 运维标注：如 `rust-cpuset-4-7,docker-cpus=4` |

> **压测客户端**：仅维护 Rust 二进制 `crypto-offload-benchmark`（`cargo build --release`），不提供 Python 压测脚本。

---

## 2. 压测模式说明

**不在 `run_suite.sh` 中的操作**（启动/轮换级低频，非热路径）：

| RPC | 说明 |
|-----|------|
| `ImportKey` | 启动或密钥轮换时调用；压测客户端仅在各 mode **预热前** import 一次（见输出 `key_import_ms`，**不计入 QPS**） |
| `DeleteKey` / `GetKeyInfo` / `ListKeys` | 管理类查询，不做吞吐压测 |

| mode | 测量内容 | 密钥 ImportKey |
|------|----------|----------------|
| `sign` | Sign QPS | 压测前 import 一次，**不计入** QPS |
| `verify` | Verify QPS | 压测前 import 公钥 + 预生成签名 |
| `sign-verify` | 签名+验签往返 | 各 import 一次 |
| `cms-build` | CMS 封包 QPS | 压测前 import 私钥+证书 |
| `cms-parse` | CMS 解析 QPS | 压测前预生成一份 CMS DER |
| `cms-verify` | CMS 验签 QPS | 同上 |
| `cms-build-parse` | CMS 封包→解析往返 | 同上 |
| `sign-rsa-pss` / `sign-verify-rsa-pss` | RSA-PSS 签名/往返 | RSA 私钥 |
| `sign-ed25519` / `sign-verify-ed25519` | Ed25519 签名/往返 | Ed25519 |
| `sign-sm2` / `sign-verify-sm2` | SM2 签名/往返（需 OpenSSL 国密） | SM2 |
| `scep-parse-request` | SCEP PKIO 解析：验签外层 + 解密 → `csr_der` + `wrapper_cert_der` | CA 私钥 + 启动时生成 PKIO fixture |
| `scep-certrep-success` | SUCCESS CertRep 构建（默认：UNSPECIFIED→AES-128-CBC） | CA + issued + wrapper |
| `scep-certrep-success-aes128-cbc` | SUCCESS CertRep 构建（AES-128-CBC，RFC 8894） | 同上 |
| `scep-certrep-success-aes256-cbc` | SUCCESS CertRep 构建（AES-256-CBC，step-ca） | 同上 |
| `scep-certrep-failure` | FAILURE CertRep 构建 | CA |
| `scep-certrep-pending` | PENDING CertRep 构建（pkiStatus=3） | CA |
| `scep-certrep-verify` | SUCCESS CertRep CMS 验签 | 预构建 CertRep + CA 证书 |
| `scep-parse-build-success` | ParseRequest → BuildSuccessCertRep 往返 | 同上 |
| `cmp-parse` | CMP PKIMessage 解析（ParsePkiMessage） | 启动时 Build 一份样本 DER |
| `cmp-verify` | CMP protection 验签 | 同上 + 带证书的 verify_key_id |
| `cmp-parse-verify` | CMP 解析 + 验签（推荐主路径） | 同上 |
| `cmp-build` | CMP 构建带 protection 的 PKIMessage | 压测前 import 私钥+证书 |

> **Sign/Verify/CMS/SCEP/CMP 压测反映的是「已有 key_id 后的运算性能」**，与生产路径一致（ImportKey 只在启动或轮换时调用）。SCEP Parse 的 PKIO 样本在压测启动时本地生成（3DES Envelop + wrapper 签名），不计入 QPS。

---

## 3. 参考性能（必须标注环境）

### 3.1 全模式压测（3 核 server · clients=3）

下列来自 WSL **`taskset -c 0-2`** + `--crypto-max-inflight 3`，**`clients=3`（= 核数）**，`total=5000/mode`，`payload=256B`：

| 环境 | AMD Ryzen 7 5800X3D · server cpuset `0-2` · clients=3 |
|------|------------------------------------------------------|

| mode | QPS | P50 (µs) | P99 (µs) | 说明 |
|------|-----|----------|----------|------|
| sign | 3435 | 1086 | 2226 | RSA PKCS#1 CPU 密集 |
| verify | 7669 | 497 | 978 | 轻量，CPU 占用率低 |
| sign-verify | 2333 | 1631 | 3017 | |
| sign-rsa-pss | 3181 | 1154 | 2566 | |
| sign-ed25519 | 7639 | 502 | 916 | |
| cms-build | 3150 | 1158 | 2611 | |
| cms-parse | 6981 | 551 | 994 | |
| cms-verify | 7228 | 528 | 984 | |
| scep-parse-request | 3334 | 1704 | 3345 | PKIO 解析 + 外层验签 + 解密 CSR |
| scep-certrep-success | 2608 | 1416 | 3209 | 默认 Envelop（UNSPECIFIED→AES-128-CBC） |
| scep-certrep-success-aes128-cbc | — | — | — | AES-128-CBC（RFC 8894）；待实测 |
| scep-certrep-success-aes256-cbc | — | — | — | AES-256-CBC（step-ca）；待实测 |
| scep-certrep-failure | 3086 | 1189 | 2818 | 无 Envelop，比 success 快 |
| scep-certrep-verify | 8644 | 648 | 1350 | CMS 验签 CertRep（轻量） |
| scep-parse-build-success | 1536 | 3786 | 6441 | Parse → Build 往返 |

> 16 核未绑核（`run_wsl_suite.sh`）Sign 约 **4326 QPS**；3 核约为 **79%** 线性比例，RSA 签名与核数大致成正比。

复现：

```bash
bash scripts/benchmark/run_wsl_suite_3cpu.sh
# 或 SERVER_CPUSET=0-2 SERVER_CPUS=3 bash scripts/benchmark/run_wsl_suite_3cpu.sh
```

### 3.2 Client 网格压测（Sign · 2 核 / 3 核）

**目的**：在 **overload 水位 = max-inflight** 下验证 `clients` 与核数关系。默认网格以 **1×核数** 为中心（2 核：2,3,4；3 核：3,4,6）。

| 环境 | Sign · RSA PKCS#1 · `total=5000` · `max-inflight = watermark = server_cpus` |
|------|-------------------------------------------------------------------------------|

**历史数据（2× 核数网格，无 overload 或水位较高）** 仍可作为「高并发排队」参考，见 git 历史版 §3.2；**当前默认服务端会拒绝 clients > inflight**。

**推荐组合（与 §1.1.1 一致）**

| server 核数 | 推荐 clients / MaxOpen | 说明 |
|------------|------------------------|------|
| 2 | **2** | = 核数；`clients=3~4` 可能偶发 overload 拒绝 |
| 3 | **3** | = 核数；`clients=6` 在 watermark=3 时压测失败 |
| 4 | **4** | = 核数 |

| 场景 | 调整 |
|------|------|
| 压测 / 对标 QPS | 保持 **clients = 核数**，并标注 cpuset |
| 刻意压满排队（测延迟退化） | 提高 `--crypto-overload-watermark` 或关闭 overload，再扫大 clients |
| SDK 连接池 | `MaxOpen` 与 **clients** 同义，生产默认 **1:1** |

复现：

```bash
bash scripts/benchmark/run_client_grid.sh
```

### 3.4 冒烟采样（未绑核 · 仅供参考）

下列数值来自 **WSL 冒烟**（`wsl_smoke_test.sh`），**未绑核**，`clients=4`，100 请求/模式，**不可与 §3.1/§3.2 直接对比**：

| mode | QPS（约） |
|------|-----------|
| sign | ~4083 |
| sign-verify | ~2392 |

**正式压测请按目标生产配置执行 §3.1 或 §3.2**，例如：

```bash
taskset -c 0-2 ./target/release/crypto-offload-server \
  --listen 127.0.0.1:50051 \
  --crypto-max-inflight 3 --worker-threads 3 --crypto-blocking-threads 6

SERVER_PROFILE="wsl-cpuset-0-2,server_cpus=3" CLIENTS=3 \
  bash scripts/benchmark/run_suite.sh
```

### 3.3 CMP 压测（OpenSSL 3.5 · RFC PKIMessage）

| 环境 | 8845H · OpenSSL 3.5.6 · `total=10000/mode` |
|------|---------------------------------------------|

**未绑核**（16 逻辑核，`max-inflight≈16`，`clients=16` 由 `run_cmp_suite.sh` 默认）

| mode | QPS | P50 (µs) |
|------|-----|----------|
| cmp-parse | 4013 | 1871 |
| cmp-verify | 4214 | 1752 |
| cmp-parse-verify | 3825 | 1961 |
| cmp-build | 3624 | 2071 |

**3 核**（`taskset 0-2`，`inflight=3`，**`clients=3`**）

| mode | QPS | P50 (µs) |
|------|-----|----------|
| cmp-parse | 3133 | 896 |
| cmp-verify | 3236 | 859 |
| cmp-parse-verify | 2791 | 989 |
| cmp-build | 1972 | 1389 |

复现：`bash scripts/benchmark/run_cmp_suite_3cpu.sh`（报告 `benchmark_cmp_report_3cpu.txt`）。

线性缩放经验：

- RSA / SCEP success / CMS build / **cmp-build**：**CPU 密集**，QPS ≈ 与 Rust 独占核数成正比
- Verify / CMS parse / **cmp-parse**：相对轻量
- 客户端 **`clients` = server 核数**（§1.1.1）；`clients > max-inflight` 只会触发 overload 拒绝，无法反映真实吞吐

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
| `--crypto-blocking-threads` | 服务端 | ≈ Rust 核数 ~ 2×核数 | `spawn_blocking` 池上限 |
| `--crypto-max-inflight` | 服务端 | = Rust 核数（默认自动） | OpenSSL 并发 Semaphore，见 [STABILITY.md](./STABILITY.md) |
| `MaxOpen` | 客户端连接池 | **= server 核数**（§1.1.1） | 2 核→2，3 核→3，4 核→4 |
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

- [ ] 运行 **§3.2 Client 网格** 或 `run_client_grid.sh` 确认 `MaxOpen` 与核数匹配
- [ ] 压测 **全部相关 mode**（sign / cms / scep-* 等）达到业务目标 QPS 的 **1.5×** 余量
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
