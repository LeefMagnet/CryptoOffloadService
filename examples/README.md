# 各语言 Demo 说明

运行前请先启动服务：

```bash
cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
```

## Go

```bash
make proto
cd sdk/go && go mod tidy
go run ../../examples/go/demo
```

## Python

```bash
make proto
pip install -e sdk/python cryptography
PYTHONPATH=sdk/python python examples/python/demo.py
```

## Rust

```bash
cargo run --example demo --manifest-path examples/rust/Cargo.toml
```

## Java

```bash
cd sdk/java && mvn compile
# 将 examples/java 加入 classpath 后运行 Demo
```

## SCEP 正向用例（Go / Java / Rust 共用）

三个示例都补充了与 `server/tests/scep_tests.rs` 对齐的正向链路：

1. `ParseEnrollPkio`（支持 `challenge_password`）
2. `BuildScepSuccessCertRep`（`challenge_password` 非空时走 PasswordRecipientInfo）

通过环境变量注入样本，避免把业务密钥写入仓库：

```bash
export SCEP_ENROLL_PKIO_B64="<base64 DER>"
export SCEP_CA_KEY_ID="<ca private key id>"
export SCEP_CHALLENGE_PASSWORD="<optional>"
export SCEP_ISSUED_CERT_DER_B64="<optional base64 DER>"
```

说明：
- `SCEP_CA_KEY_ID` 必须是该 PKIO 对应 CA 私钥（不是终端私钥）。
- 不设置 `SCEP_ENROLL_PKIO_B64` 时会跳过 SCEP 段，仅运行基础 Sign/CMS 演示。
- 不设置 `SCEP_ISSUED_CERT_DER_B64` 时只演示 Parse，不演示 BuildSuccessCertRep。

完整 API 说明见 [docs/API.md](../docs/API.md)。
