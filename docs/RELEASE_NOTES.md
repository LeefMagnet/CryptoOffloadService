# CryptoOffloadService Release Notes

> 版本发布总索引（时间线）。  
> 后续发版时只需要在本文末尾**追加一个新章节**，并可按需链接到独立详情文档。

---

## 时间线索引

| 版本 | 说明 | 详情 |
|------|------|------|
| `0.2.4` | CMP offload（RFC 9810/9811，OpenSSL 3.x + C shim） | [RELEASE_NOTES_0.2.4.md](./RELEASE_NOTES_0.2.4.md) |
| `0.2.3` | SCEP challengePassword / PasswordRecipientInfo（RFC 8894 §3.1） | [RELEASE_NOTES_0.2.3.md](./RELEASE_NOTES_0.2.3.md) |
| `0.2.2` | 架构美学重构（服务层解耦 + FFI 边界收口）与版本升级 | [RELEASE_NOTES_0.2.2.md](./RELEASE_NOTES_0.2.2.md) |
| `0.2.1` | CMS 验签语义收紧、SCEP DER 边界加固与回归测试补全 | 见下方摘要 |
| `0.2.0` | ScepExtService 引入，SCEP 扩展能力进入稳定分支 | 见下方摘要 |

---

## 0.2.4

- 主题：CMP PKIMessage 解析/验签/受保护构建卸载，协议层与密码运算分离。
- 关键改动：新增 `CmpService`；C shim ASN.1 组包；`ParseAndVerify` 单 RPC；细粒度 shim 错误映射。
- 详情：[RELEASE_NOTES_0.2.4.md](./RELEASE_NOTES_0.2.4.md)。

## 0.2.3

- 主题：SCEP 口令信封（PasswordRecipientInfo），适配仅 ECDSA wrapper、无 RSA 加密钥的 Enroll/CertRep。
- 关键改动：Proto 增加 `challenge_password`；服务端 pwri 加解密；口令模式下可省略 `wrapper_cert_der`。
- 测试：`cargo test -p crypto-offload-server` 全量通过（含 3 个 pwri 专项用例）。
- 详情：[RELEASE_NOTES_0.2.3.md](./RELEASE_NOTES_0.2.3.md)。

## 0.2.2

- 主题：软件工程“美学”与可维护性优化。
- 关键改动：
  - 拆分 `services.rs` 职责，引入 `service_validators` 与 `service_errors`。
  - 收敛 `scep_certrep` 中重复 `unsafe` 初始化路径，降低 FFI 认知复杂度。
  - 统一版本元信息升级到 `0.2.2`。
- 测试：`cargo test -p crypto-offload-server` 全量通过。  
- 详情：`docs/RELEASE_NOTES_0.2.2.md`。

## 0.2.1

- 主题：高性价比稳定性修复与语义澄清。
- 关键改动：
  - 修复 `scep_cert_alias` 对畸形 DER 的长度边界处理，避免 panic 风险。
  - `CmsService.Verify` 明确并落实“`verify_key_id` 必须匹配签名证书公钥”。
  - `BuildCmsRequest.content_type` 对不支持值显式返回 `INVALID_ARGUMENT`。
  - 补齐恶意输入 / 错误 key / 不支持 content_type 回归测试。

## 0.2.0

- 主题：SCEP 扩展能力落地。
- 关键改动：
  - 增加 `ScepExtService`（扩展 SCEP 协议字段与解析能力）。
  - 引入 `ParseEnrollPkio` 等扩展接口，强化 SCEP offload 覆盖面。
  - 建立 `feature/scep-ext-v0.2` 版本线，形成 `0.2.x` 演进基础。

---

## 追加模板（后续版本沿用）

```md
## X.Y.Z

- 主题：
- 关键改动：
  - 
  - 
- 兼容性：
- 测试：
- 详情：（可选，链接到 RELEASE_NOTES_X.Y.Z.md）
```
