# CryptoOffloadService 0.2.2 Release Notes

发布日期：2026-05-31  
版本代号：`v0.2.2`（本地已完成提交）

## 一句话摘要

`0.2.2` 聚焦“软件工程美学”与可维护性：在不改变核心能力的前提下，完成服务层职责拆分、SCEP FFI 边界收口，并统一版本元数据。

## 亮点

### 1) 服务层结构更清晰（`services.rs` 解耦）

- 新增 `server/src/service_validators.rs`：集中请求校验逻辑（大小限制、必填字段、SCEP/CMS 约束）。
- 新增 `server/src/service_errors.rs`：集中错误映射策略，减少散落式 `Status` 转换。
- `server/src/services.rs` 仅保留“服务编排 + 调用流程”，降低认知负担。

### 2) SCEP CertRep 的 `unsafe` 边界更小、更可读

- 在 `server/src/scep_certrep.rs` 中提取共享 helper：`new_signed_data_with_signer(...)`。
- SUCCESS / GM SUCCESS / FAILURE / PENDING 四条路径复用同一初始化流程。
- 减少重复 FFI 样板，集中空指针检查与生命周期语义。

### 3) 版本升级到 0.2.2

以下元数据已同步更新：

- `Cargo.toml`
- `Cargo.lock`
- `sdk/java/pom.xml`
- `sdk/python/pyproject.toml`
- `examples/rust/Cargo.toml`
- `docs/OVERVIEW.md`

## 质量与验证

- 已执行：`cargo test -p crypto-offload-server`
- 结果：全部通过（包含 integration/scep/sign/key_store/scep_ext 测试组）
- 说明：存在少量既有 warning（如 `ossl300` cfg 提示），不影响本次发布功能正确性。

## 兼容性说明

- 对外 API/协议无破坏性变更。
- 本次主要是内部结构优化与工程质量提升，可直接替换同系列版本。

## 推荐升级动作

1. 升级服务端与 SDK 到 `0.2.2`。
2. 按现有压测脚本做一次环境回归（尤其是 SCEP 与 CMS 核心路径）。
3. 观察错误码监控面板中 `NOT_FOUND / FAILED_PRECONDITION / INVALID_ARGUMENT / INTERNAL` 的分布变化，用于后续告警策略细化。
