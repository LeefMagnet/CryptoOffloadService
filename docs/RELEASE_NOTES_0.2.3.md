# CryptoOffloadService 0.2.3 Release Notes

版本代号：`v0.2.3`

## 主题

SCEP **challengePassword / PasswordRecipientInfo**（RFC 8894 §3.1）支持：终端仅有 ECDSA 等签名钥、无 RSA 加密钥时，可用与 PKCS#10 一致的共享口令保护 EnvelopedData，无需 SMS 二次下发 wrapper 加密证书。

## 关键改动

### Protobuf / gRPC

- `ScepService.ParseRequest`、`BuildSuccessCertRep`、`BuildGmSuccessCertRep` 增加可选字段 `challenge_password`。
- `ScepExtService.ParseGetCertPkio`、`ParseEnrollPkio` 同步增加 `challenge_password`。

### 服务端

- 新模块 `scep_password_envelope.rs`：基于 OpenSSL CMS `PasswordRecipientInfo`（与 `openssl cms -pwri_password` 一致：`CMS_PARTIAL` → `CMS_add0_recipient_password` → `CMS_final`）。
- `scep_pkio` / `scep_certrep`：自动识别内层 pwri 与 RSA KeyTrans；口令模式下 `wrapper_cert_der` 可省略。
- 校验：`service_validators` 对口令长度与 NUL 字节做边界检查。

### 测试与文档

- 单元测试：`scep_password_envelope_roundtrip`、`scep_parse_request_password_pkio`、`scep_build_success_certrep_password_envelope`。
- `docs/API.md`、`docs/TESTING.md` 补充字段说明与用例表。

## 兼容性

- **向后兼容**：`challenge_password` 为空时行为与 0.2.2 相同（RSA KeyTrans + `wrapper_cert_der`）。
- **OpenSSL**：已在 OpenSSL 1.1.1f 验证；pwri 使用 `CMS_add0_recipient_password`（非 OpenSSL 3.0 专属的 `CMS_add1_*`）。

## 升级提示

1. 重新 `make proto` / `mvn compile` 以生成含新字段的 SDK stub。
2. 若终端 Enroll 使用 `challengePassword` 且 wrapper 为 ECDSA，Parse/Build 时传入相同 `challenge_password`。

## 验证

```bash
cargo test -p crypto-offload-server
```
