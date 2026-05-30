# 服务端稳定性与加固说明

> 面向运维与后续维护：已实施的防崩溃措施、启动参数，以及**暂未实现**的可选优化（遇问题时再评估）。

---

## 1. 设计目标

CryptoOffload 作为 sidecar 长期运行，应避免：

- 单次坏请求或 Rust panic 导致**整进程退出** → Docker `restart: unless-stopped` 循环
- 突发高并发导致 **unbounded `spawn_blocking`** → 内存/线程堆积 → OOM kill

密码运算在 Rust + OpenSSL 内完成；gRPC + Protobuf 已提供帧边界与字段大小约束（单字段 ≤ 1 MiB，见 [API.md](./API.md)）。

---

## 2. 已实施（当前版本）

### 2.1 KeyStore 锁 poison 不再 panic

`RwLock` 若因 panic 变为 poison，原先 `.expect()` 会**拖死整个进程**。

现改为返回 `Result`，gRPC 映射为 **`UNAVAILABLE`**（message 含 `lock poisoned`），其它 KeyStore 错误仍为 `INVALID_ARGUMENT`。

### 2.2 全局 crypto 并发 Semaphore

所有 Sign / CMS / SCEP 的 OpenSSL 路径在 `spawn_blocking` 前 **`acquire` 全局 Semaphore**：

- 默认 permits = **可见 CPU 逻辑核数**（与 cpuset / `taskset` 一致）
- 可通过 `--crypto-max-inflight N` 显式覆盖
- 超过上限的请求在 async 层等待 permit，**不**无限堆积 blocking 任务

正常负载下（in-flight ≈ 核数）几乎无排队；异常洪峰时优先**排队/超时**，而非 OOM。

### 2.3 Tokio runtime 参数接线

`crypto-offload-server` 支持：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--worker-threads` | 0（Tokio 默认） | gRPC async worker |
| `--crypto-blocking-threads` | 0（Tokio 默认） | `spawn_blocking` 池上限 |
| `--crypto-max-inflight` | 0（= 可见核数） | OpenSSL 并发 Semaphore |

**Docker / cpuset 示例（4 核 sidecar）：**

```bash
crypto-offload-server \
  --listen 0.0.0.0:50051 \
  --worker-threads 4 \
  --crypto-blocking-threads 8 \
  --crypto-max-inflight 4
```

启动日志会打印 `crypto_max_inflight`。

### 2.4 与 ScepAccelerator 二进制版的差异（为何未移植 EnginePool）

| 项 | ScepAccelerator UDS | CryptoOffload gRPC |
|----|---------------------|-------------------|
| 协议 | 自定义帧 + 16MiB 上限 | gRPC / Protobuf + 1MiB 字段 |
| OpenSSL 状态 | 可变 `ScepEngine` 需独占池 | 每次 RPC 新建 `Signer` / `Pkcs7`，共享只读 `PKey` |
| 密钥模型 | 固定 CA 文件 | 按 `key_id` 引用 |

因此**未**移植 per-engine 池；并发由 Semaphore + blocking 池控制即可。

---

## 3. 暂未实现（可选，遇问题再优化）

以下在讨论中评估过，**当前代码未做**；若生产出现对应症状，再按需引入。

### 3.1 `catch_unwind` 包裹 crypto 入口

- **目的**：Rust panic 在 blocking 任务内变为 RPC `INTERNAL`，避免 poison KeyStore
- **代价**：每次 RPC 一层 unwind 探测；**防不了 OpenSSL `abort()`**
- **触发条件**：监控到 `crypto task join error` 或进程仍偶发退出且排除 OOM

### 3.2 per-`key_id` 引擎池 / 互斥

- **目的**：若将来引入**带可变状态的 per-key 上下文**（类似 ScepEngine）
- **注意**：对同一 `ca_key_id` 做 **Mutex 串行** 会严重降低 SCEP QPS，不推荐
- **触发条件**： profiling 证明同一 `PKey` 并发有问题（当前每次新建 Signer，理论上不需要）

### 3.3 KeyStore 无锁化（DashMap / `Arc` 热路径）

- **目的**：高频率 Import/List 时减少全局 `RwLock` 争用
- **触发条件**：密钥种类极多且 Import/List QPS 成为瓶颈（一般 sidecar 不会）

### 3.4 ImportKey 也走 `spawn_blocking`

- **目的**：避免大 PEM 解析阻塞 async worker
- **触发条件**：启动阶段批量 Import 导致 gRPC 延迟尖刺

### 3.5 运维层：内存 limit + liveness

- Docker `deploy.resources.limits.memory` + HTTP/gRPC health check
- OOM 时仍会重启，但可告警、与业务进程隔离；见 [BENCHMARK_AND_TUNING.md](./BENCHMARK_AND_TUNING.md) 部署章节

### 3.6 OpenSSL 版本与 abort

- 畸形 ASN.1 多数返回 `Err`；极低概率 OpenSSL 内部 abort
- 依赖发行版/OpenSSL 升级；业务侧尽量只送已校验 DER

---

## 4. 客户端侧建议

- 连接池 `MaxOpen` 与服务端 `--crypto-max-inflight` **同量级**（不必相等，但避免客户端 100 连接打 4 核 server）
- 收到 `UNAVAILABLE`（含 lock poisoned / semaphore closed）→ 短暂退避后重试；**不要**对 `INVALID_ARGUMENT` 盲重试
- 服务重启后 **重新 ImportKey**（密钥仅进程内存）

---

## 5. 相关文档

- [API.md](./API.md) — RPC、错误码、§7 排错清单
- [BENCHMARK_AND_TUNING.md](./BENCHMARK_AND_TUNING.md) — cpuset、压测、容器 CPU
