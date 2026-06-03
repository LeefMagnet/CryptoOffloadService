# CryptoOffloadService 0.2.4 Release Notes

版本代号：`v0.2.4`

## 主题

CMP（RFC 9810/9811）密码运算卸载：基于 OpenSSL 3.x 原生 CMP API 的 PKIMessage 解析、保护验签与受保护响应构建；外层 DER 由 C shim + OpenSSL ASN.1 编码，无 Rust TLV 组包。

## 关键改动

### Protobuf / gRPC（`CmpService`）

- `ParseCmpPkiMessage`：解析 PKIMessage（header/body 类型、nonce 等）。
- `VerifyCmpPkiMessageProtection`：基于导入证书的信任链验证消息保护。
- `ParseAndVerifyCmpPkiMessage`：单 RPC 合并解析与验签（推荐）。
- `BuildCmpProtectedPkiMessage`：对业务侧组好的 `pki_header_der` + `pki_body_der` 签名并封装完整 PKIMessage。

### 服务端

- `crypto_cmp.rs`：运行时加载 OpenSSL 3.x CMP 符号；不支持时返回 `CMP_OPENSSL_UNSUPPORTED`。
- `cmp_shim.c`：C shim 构建 ProtectedPart / PKIMessage；细粒度错误码并映射为 gRPC 状态（含 `INVALID_ARGUMENT`、`RESOURCE_EXHAUSTED`）。
- `key_store::verifying_cert`：CMP 验签需证书或带证书的公钥导入。

### SDK 与示例

- Go / Rust / Java SDK 增加 CmpService 客户端封装。
- `examples` 增加 `ParseAndVerifyCmpPkiMessage` 演示（环境变量触发）。

### 文档与测试

- `docs/API.md`：CMP 接入、RPC 次数、BC fallback 判定表。
- `docs/TESTING.md`：CmpService 集成用例表。
- 集成测试：`grpc_cmp_build_*`、`grpc_cmp_parse_and_verify_*`。

## 兼容性

- **OpenSSL**：CMP 路径要求 OpenSSL 3.x 且导出 CMP 符号；否则 `FAILED_PRECONDITION`，业务侧回退 Java BC。
- **向后兼容**：既有 Sign/CMS/SCEP 接口无破坏性变更。

## 升级提示

1. 重新生成 proto stub（`make proto` / `cargo build -p cryptooffload-sdk` / `mvn compile`）。
2. 入站 CMP：优先 `ParseAndVerifyCmpPkiMessage`；出站：BC 组 header/body 后调用 `BuildCmpProtectedPkiMessage`。
3. `verify_key_id` 建议 `KEY_KIND_CERTIFICATE` 或公钥 + `certificate_data`。

## 验证

```bash
cargo test -p crypto-offload-server
```
