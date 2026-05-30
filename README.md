# CryptoOffloadService

通用密码运算 offload 服务：基于 **gRPC + Protobuf**，Rust/OpenSSL 执行重 CPU 密码运算，业务进程通过 **连接池 SDK** 按 `key_id` 调用。

设计参考 [ScepAccelerator](../ScepAccelerator) 的 sidecar 思路，但协议完全 protobuf 化，支持多语言接入。

## 架构

```
┌──────────────┐     gRPC (Protobuf)      ┌─────────────────────────────┐
│ Go / Python  │  ◄──── 连接池 SDK ────►  │ crypto-offload-server (Rust)│
│ Java / Rust  │                          │  • KeyService  (KMS 式 key_id)│
└──────────────┘                          │  • SignService (签名/验签)     │
                                          │  • CmsService  (CMS 解析/封装)│
                                          └─────────────────────────────┘
```

## 核心能力

| 服务 | RPC | 说明 |
|------|-----|------|
| **KeyService** | `ImportKey` | 导入公钥/私钥/证书，返回 `key_id` |
| | `DeleteKey` / `GetKeyInfo` / `ListKeys` | 密钥生命周期管理 |
| **SignService** | `Sign` / `Verify` | 通过 `key_id` 签名/验签，可选摘要算法 |
| **CmsService** | `Parse` / `Build` / `Verify` | CMS/PKCS#7 解析、封装、验签 |

### 密钥管理（类 KMS）

- **永久密钥** (`KEY_LIFETIME_PERMANENT`)：服务运行期间一直有效，可重复使用
- **临时密钥** (`KEY_LIFETIME_TEMPORARY`)：首次用于密码运算后自动销毁（单次有效）
- 后续 CMS / 签名 / 验签均通过 **`key_id`** 引用，不再传输密钥材料

### 摘要与签名算法

签名时可指定：

- `HashAlgorithm`：`SHA256` / `SHA384` / `SHA512` / `SHA1`
- `SignAlgorithm`：`RSA_PKCS1_V15` / `RSA_PSS` / `ECDSA`（未指定时按密钥类型推断）

> 不提供独立的「纯摘要 offload」RPC；摘要作为签名流程的一部分在服务端完成。面向**小包**场景，单字段上限 1 MiB。

## 文档

| 文档 | 说明 |
|------|------|
| [docs/API.md](docs/API.md) | **Protobuf API 完整参考**（字段、枚举、错误码） |
| [docs/BENCHMARK_AND_TUNING.md](docs/BENCHMARK_AND_TUNING.md) | **压测与容器资源配置指南** |
| [docs/STABILITY.md](docs/STABILITY.md) | **服务端稳定性加固与可选优化** |

## 各语言 Demo

| 语言 | 运行方式 |
|------|----------|
| Go | `make proto && go run ./examples/go/demo` |
| Python | `make proto && pip install -e sdk/python && python examples/python/demo.py` |
| Rust | `cargo run --example demo --manifest-path examples/rust/Cargo.toml` |
| Java | `cd sdk/java && mvn compile` 后运行 `examples/java/Demo.java` |

## 压测

```bash
# Rust 压测客户端（推荐）
./scripts/benchmark/run_benchmark.sh

# 或
make benchmark
```

详见 [docs/BENCHMARK_AND_TUNING.md](docs/BENCHMARK_AND_TUNING.md)。

## 密钥导入与缓存（重要）

`ImportKey` 时服务端**一次性**将 PEM/DER 解析为 OpenSSL `PKey`/`X509` 并保存在**进程内存**中；后续 `Sign`/`Verify`/`CMS` 仅通过 `key_id` 引用，**不会**重复 PEM Base64 解码或 ASN.1 解析。

- **不是磁盘持久化**：服务重启后需重新 ImportKey
- **永久密钥**：启动或轮换时 import 一次，热路径只传 `key_id`
- **临时密钥**：首次运算后自动销毁

详见 [docs/API.md §1.3](docs/API.md#13-密钥存储模型重要)。

## 测试验证

### WSL 原生（推荐，不依赖 Docker Hub）

```bash
# 单元 + 集成测试 + release 冒烟压测
bash scripts/test/wsl_smoke_test.sh
```

### Docker 内（server + test-runner 同网络）

> 需能拉取 `rust:1.83-bookworm` / `debian:bookworm-slim` 镜像。

```bash
bash scripts/test/docker_test.sh
# 或
make docker-test
```

Docker 构建阶段会自动执行 `cargo test`；`test-runner` 容器对 `crypto-offload` 服务跑 sign/verify/sign-verify 压测。

## 快速开始

### 1. 生成 Protobuf 代码

```bash
# 需要安装 buf: https://buf.build/docs/installation
make proto
```

Rust 服务端/客户端在 `cargo build` 时通过 `tonic-build` 自动生成，无需 buf。

### 2. 启动服务

```bash
cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
```

或 Docker：

```bash
docker compose -f deploy/docker-compose.yml up --build
```

### 3. Go SDK 示例

```go
ctx := context.Background()
cli, err := client.New(ctx, client.Config{
    Config: pool.Config{
        Address:        "127.0.0.1:50051",
        MinIdle:        2,
        MaxOpen:        8,
        MaxLifetime:    30 * time.Minute,
        IdleTimeout:    5 * time.Minute,
    },
})
if err != nil { panic(err) }
defer cli.Close()

importResp, err := cli.ImportKey(ctx, &pb.ImportKeyRequest{
    Kind:     pb.KeyKind_KEY_KIND_PRIVATE,
    Lifetime: pb.KeyLifetime_KEY_LIFETIME_PERMANENT,
    Format:   pb.KeyFormat_KEY_FORMAT_PEM,
    KeyData:  privateKeyPEM,
    Label:    "my-signing-key",
})

signResp, err := cli.Sign(ctx, &pb.SignRequest{
    KeyId:          importResp.Metadata.KeyId,
    Data:           []byte("payload"),
    HashAlgorithm:  pb.HashAlgorithm_HASH_SHA256,
    SignAlgorithm:  pb.SignAlgorithm_SIGN_RSA_PKCS1_V15,
})
```

### 4. Python SDK 示例

```python
from cryptooffload import Client, PoolConfig
from cryptooffload.client import KeyKind, KeyLifetime, KeyFormat, HashAlgorithm

client = Client.connect(PoolConfig(address="127.0.0.1:50051"))
meta = client.import_key(
    kind=KeyKind.KEY_KIND_PRIVATE,
    lifetime=KeyLifetime.KEY_LIFETIME_TEMPORARY,
    format=KeyFormat.KEY_FORMAT_PEM,
    key_data=private_pem,
)
sig = client.sign(
    key_id=meta.metadata.key_id,
    data=b"payload",
    hash_algorithm=HashAlgorithm.HASH_SHA256,
)
```

### 5. Rust SDK 示例

```rust
use cryptooffload_sdk::{Client, PoolConfig};
use cryptooffload_sdk::pb::v1::*;

let client = Client::connect(PoolConfig::default()).await?;
let imported = client.import_key(ImportKeyRequest {
    kind: KeyKind::Private as i32,
    lifetime: KeyLifetime::Permanent as i32,
    format: KeyFormat::Pem as i32,
    key_data: pem_bytes,
    ..Default::default()
}).await?;
```

## 连接池设计

各语言 SDK 的连接池语义对齐 **database/sql** 与 **Redis 连接池**：

| 参数 | 含义 |
|------|------|
| `MinIdle` | 最小空闲连接，启动时预热 |
| `MaxOpen` | 最大并发连接（含使用中 + 空闲） |
| `MaxLifetime` | 连接最大存活时间，归还时淘汰 |
| `IdleTimeout` | 空闲超时回收 |
| `AcquireTimeout` | 池耗尽时等待上限 |

gRPC 虽支持单连接多路复用，但连接池用于**限制并发连接数**、**隔离负载**、**统一超时与淘汰策略**，与 SCEP 侧 UDS 连接池思路一致。

## 目录结构

```
proto/                  # Protobuf 定义
server/                 # Rust gRPC 服务端
sdk/
  go/                   # Go SDK（pool + client）
  python/               # Python SDK
  rust/                 # Rust SDK
  java/                 # Java SDK
deploy/                 # Docker / Compose
```

## Proto 包

- `cryptooffload/v1/common.proto` — 枚举与公共类型
- `cryptooffload/v1/key_service.proto` — 密钥管理
- `cryptooffload/v1/sign_service.proto` — 签名/验签
- `cryptooffload/v1/cms_service.proto` — CMS 操作

## 与 ScepAccelerator 的关系

ScepAccelerator 使用自定义 UDS 二进制帧 + SCEP 专用 opcode。本项目是**全新通用服务**：

- 仅 Protobuf/gRPC，不兼容旧 UDS 协议
- SCEP 可作为上层业务：导入 CA 私钥 → `Parse`/`Build` CMS → 返回 PKCS#7
- 可复用 ScepAccelerator 的 OpenSSL 实现经验（引擎池、cpuset、legacy provider）

## 构建要求

- Rust 1.75+（推荐 1.83）
- OpenSSL 3.x（含 legacy provider，CMS 3DES 解密需要）
- buf（生成 Go/Python stub）
- Go 1.22+ / Python 3.10+ / JDK 17+（按 SDK 选用）
