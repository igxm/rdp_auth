# rdp_auth Agent Checklist

本文件是后续 Codex/协作者的低 token 入口。完整规范见 [docs/development.md](E:/Developers/rdp_auth/docs/development.md)；如有冲突，以原文为准。

## 1. 开始前

- 先阅读本文件和 `docs/development.md`
- 开始前执行 `git status --short`
- 如需突破现有边界，先在设计或任务清单写明原因、风险和回滚方式

## 2. Git

- 每次有效代码、文档、配置变更都提交 git
- 不回滚或覆盖用户已有的无关改动
- 提交信息使用短前缀：`docs:`、`feat:`、`fix:`、`test:`

## 3. 中文注释

- 新增代码必须有必要中文注释
- 注释解释维护难点，不复述代码表面含义
- 优先解释：
  - Windows COM 生命周期
  - Credential Provider / LogonUI 边界
  - 凭证序列化
  - 命名管道
  - 安全边界
  - fail closed 原因

## 4. 核心边界

- CP 只做：COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC、MFA 成功后的凭证打包
- helper 只做：命名管道服务、请求路由、session 状态、配置聚合、API 调用、审计、Windows session notification
- `auth_core` 只放纯逻辑
- `auth_config` 只放配置引导、加密配置、schema、默认值、迁移
- `auth_ipc` 只放协议类型和 JSON 编解码
- `auth_api` 只封装真实服务端 API
- `register_tool` 只做安装、卸载、health、配置导入导出
- Tauri/GUI 只能是独立管理界面，不能成为 CP 或核心 helper 的运行依赖

## 5. CP 文件职责

- `dll.rs`：DLL 导出
- `class_factory.rs`：COM 类工厂
- `provider.rs`：`ICredentialProvider`
- `credential.rs`：单个 Tile 交互与 `GetSerialization`
- `fields.rs`：字段定义和顺序
- `serialization.rs`：RDP/NLA 解包与重打包
- `filter.rs`：Filter / `UpdateRemoteCredential`
- `session.rs`：RDS session 查询与断开
- `timeout.rs`：MFA / missing-serialization 超时
- `diagnostics.rs`：CP 轻量脱敏日志
- `state.rs`：共享轻量内存状态

## 6. 安全要求

- 默认 fail closed
- CP 不发网络请求，不读取复杂配置，不长期保存敏感状态
- IPC 只允许非敏感字段
- 以下内容不得进入日志、错误、IPC 响应、策略快照或配置快照：
  - 完整手机号
  - 用户名
  - 密码
  - 验证码
  - token / challenge_token
  - serialization
- 真实手机号只允许在 helper 内短暂存在，用于发短信

## 7. 依赖方向

- 允许：
  - `credential_provider -> auth_core / auth_config / auth_ipc / auth_logging`
  - `remote_auth -> auth_core / auth_config / auth_ipc / auth_api / auth_logging`
  - `register_tool -> auth_config / auth_logging`
- 禁止：
  - `credential_provider -> auth_api`
  - `auth_config -> credential_provider / remote_auth / auth_api`
  - `auth_ipc -> 命名管道实现 / helper 状态实现`
  - Tauri GUI 成为 `credential_provider` 或核心 helper 的运行依赖

## 8. 文档与测试

- 新增功能至少有对应单元测试
- 需要 VM/手工验证的，补测试文档或任务清单
- Credential Provider / Filter 相关必须在 Windows VM 验证
- 未确认恢复流程前，不要在主力机器隐藏系统默认 Provider
- 行为、配置、安装、架构、恢复流程或限制变化时同步更新 docs
- 若无需更新文档，在收尾说明“已检查文档，无需变更”

## 9. 提交前检查

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo test --workspace`
- 可选：`powershell -ExecutionPolicy Bypass -File scripts/check.ps1`
