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

## CMP ParseAndVerify（Go / Java / Rust 共用）

三个示例都补充了 CMP 的单次 RPC 路径：

1. `ParseAndVerifyCmpPkiMessage`（单次 RPC 完成 parse + verify）

通过环境变量注入样本：

```bash
export CMP_PKI_MESSAGE_DER_B64="<base64 DER>"
export CMP_VERIFY_KEY_ID="<optional verify key id>"
```

说明：
- `CMP_PKI_MESSAGE_DER_B64` 未设置时，示例会自动跳过 CMP 段。
- `CMP_VERIFY_KEY_ID` 未设置时，会 fallback 到示例中已导入的 key_id（仅用于演示）。
- 若要验证真实生产报文，建议使用证书导入得到的 key_id 作为 `CMP_VERIFY_KEY_ID`。
- SM2 验签依赖运行时 OpenSSL 的国密能力（可用时 `ParseAndVerify` 支持 SM2 证书验签）。

完整 API 说明见 [docs/API.md](../docs/API.md)。
