# Development Summary

本文件是给后续 agent 的低 token 执行摘要；如与 [docs/development.md](E:/Developers/rdp_auth/docs/development.md) 冲突，以原文为准。

## 1. 基本规则

- 有效改动必须提交 git；提交前先看 `git status --short`
- 提交前执行：
  - `cargo fmt --all -- --check`
  - `cargo check --workspace`
  - `cargo test --workspace`
- 新增代码必须写有价值的中文注释，解释维护难点，不复述代码表面含义

## 2. 分层原则

- 单文件单职责；长期概念混在一起就拆模块
- 敏感数据只留在必要层，不进日志、错误、IPC 响应、策略快照
- 低层逻辑应可单测；不要让 UI、IO、策略、API 混成一个大函数

## 3. Crate 边界

- `auth_core`：纯逻辑；不依赖 Windows / 文件 / 网络 / IPC / 配置
- `auth_config`：注册表最小引导、加密配置、schema、默认值、迁移；不做网络、不持有 helper 状态
- `auth_ipc`：协议类型 + JSON 编解码 + 非敏感 payload；不做命名管道 IO
- `auth_logging`：统一日志目录、格式、脱敏和 tracing 初始化
- `credential_provider`：COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC、凭证打包；不做网络、不读复杂配置
- `remote_auth`：helper 能力，含命名管道、路由、session、配置聚合、API、审计、session notification；不承载 GUI
- `auth_api`：真实服务端 API 封装；不读 CP 状态或注册表
- `register_tool`：安装、卸载、health、配置导入导出；不参与登录时业务判断

## 4. CP 内部分层

- `dll.rs`：DLL 导出
- `class_factory.rs`：COM 类工厂
- `provider.rs`：`ICredentialProvider`
- `credential.rs`：单个 Tile 交互与 `GetSerialization`
- `fields.rs`：字段 ID / 描述符 / 顺序
- `serialization.rs`：RDP/NLA 解包与重打包
- `filter.rs`：Filter / `UpdateRemoteCredential`
- `session.rs`：RDS session 查询与断开
- `timeout.rs`：MFA / missing-serialization 超时
- `diagnostics.rs`：CP 轻量脱敏日志
- `state.rs`：共享轻量内存状态

## 5. Helper 内部分层

- 命名管道层只处理单次请求收发
- 路由层只分发 `auth_ipc::IpcRequest`
- session 状态只保存 `session_id`、状态、时间戳、TTL、最近事件
- 策略快照只输出 CP 可渲染的脱敏数据
- 真实手机号只在 helper 内短暂存在，用于发短信
- 审计日志只记脱敏上下文和结果码

## 6. 安全边界

- 注册表只保存 Windows 集成必需的最小引导项
- 业务配置统一进入加密配置文件；运行期不读长期明文 TOML
- CP 只能通过短超时 IPC 调 helper；helper 异常或超时必须 fail closed
- IPC / 日志 / 错误 / 策略快照中不得出现：
  - 完整手机号
  - 密码
  - 验证码
  - token
  - 用户名
  - RDP serialization

## 7. 依赖方向

- 允许：
  - `credential_provider -> auth_core / auth_config / auth_ipc / auth_logging`
  - `remote_auth -> auth_core / auth_config / auth_ipc / auth_api / auth_logging`
  - `register_tool -> auth_config / auth_logging`
- 禁止：
  - `credential_provider -> auth_api`
  - `auth_ipc -> 命名管道实现 / helper 状态`
  - `auth_config -> credential_provider / remote_auth / auth_api`
  - Tauri GUI 成为 `credential_provider` 或核心 helper 的运行依赖

## 8. 文档与测试

- 功能、配置、安装、架构、恢复流程变化时同步更新 docs
- 无需文档变更时，在收尾说明“已检查文档，无需变更”
- CP / Filter 相关必须在 Windows VM 验证
- 未确认恢复流程前，不要在主力机器隐藏系统默认 Provider
