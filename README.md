# rdp_auth

`rdp_auth` 是一个面向 Windows RDP 场景的二次认证项目。它的目标不是替代 Windows 一次登录凭证输入，而是在 RDP/NLA 已经把基础凭证送到目标机后，在 LogonUI 里增加一层 MFA 校验，再把原始登录凭证安全地重新打包交还给 Windows。

当前实现重点是把链路拆清楚并收紧安全边界：

- `credential_provider` 只负责 COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC、MFA 成功后的凭证打包
- `remote_auth` 只负责 helper 侧的 session、配置聚合、API 调用、审计和 Windows session notification
- `auth_api` 只封装真实服务端 API
- 敏感数据不进入日志、错误、IPC 响应、策略快照或配置快照
- 所有异常默认 fail closed

## 当前状态

项目已经完成了本地主链路和大部分 helper / IPC 基础设施：

- RDP pass-through 主链路已打通
- MFA 成功后才允许 `GetSerialization`
- helper 命名管道 IPC 已稳定
- 多手机号选择已收敛为“CP 只见脱敏号码 + `phone_choice_id`”
- 短信 challenge 方案已落地为 `send_sms -> challenge_token -> verify_sms`
- `auth_api` 已完成真实 HTTP 代码和 mock 服务测试
- helper 审计上下文已带：
  - RDP 客户端 IP
  - 本机公网 IP
  - 本机内网 IP
  - `audit.ip_logging = full|masked|off`

当前还没有完成的重点主要是：

- 真实后端联调
- 远程配置拉取 / 缓存 / 完整性校验
- VM 场景验证

## 仓库结构

```text
crates/
  auth_core            纯逻辑
  auth_config          配置、加密配置、schema、默认值、迁移
  auth_ipc             IPC 协议类型和 JSON 编解码
  auth_logging         tracing 初始化与统一脱敏
  auth_api             真实服务端 API 封装
  credential_provider  登录链路、UI、serialization、短超时 IPC
  remote_auth          helper、session、审计、API 编排
  register_tool        安装、卸载、health、配置导入导出

docs/
  development.md               完整开发规范
  development-summary.md       低 token 版开发摘要
  architecture.md              架构说明
  configuration.md             配置说明
  install.md                   安装与部署说明
  helper-ipc-test.md           helper / IPC 测试说明
  rdp-client-ip-vm-test.md     RDP 客户端 IP 的 VM 手工测试
  tasks.md                     当前任务清单
```

## 核心设计

### 1. 分层边界

- CP 不发网络请求
- CP 不读取复杂配置
- CP 不保存手机号、验证码、密码、token、serialization
- helper 才能读取配置、持有 session 状态、调用 API
- `auth_api` 不知道 CP 状态，不碰注册表或 helper 内存状态

### 2. 多手机号策略

- 完整手机号只存在于 helper 内存
- CP 只收到脱敏手机号和非敏感 `phone_choice_id`
- `send_sms` / `verify_sms` 只传 `phone_choice_id`
- helper 自己把 `phone_choice_id` 映射回完整手机号

### 3. 短信 challenge

- `send_sms` 成功后由服务端返回 `challenge_token`
- `challenge_token` 只允许存在于 helper 内存
- `verify_sms` 固定走 `challenge_token + code`
- `challenge_token` 不得进入日志、错误、IPC、CP 状态或落盘

### 4. 审计上下文

当前 helper 已统一生成并复用审计上下文，供 `send_sms`、`verify_sms` 和 `post_login_log` 使用。它目前包含：

- `request_id`
- `session_id`
- `client_ip`
- `host_public_ip`
- `host_private_ips`
- `host_uuid`

其中 IP 输出受 `audit.ip_logging` 控制。

## 快速开始

### 1. 构建

```powershell
cargo build --workspace
```

### 2. 全量检查

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

### 3. 先读哪些文档

如果你是第一次进入这个仓库，建议顺序是：

1. [AGENTS.md](E:/Developers/rdp_auth/AGENTS.md)
2. [docs/development-summary.md](E:/Developers/rdp_auth/docs/development-summary.md)
3. [docs/architecture.md](E:/Developers/rdp_auth/docs/architecture.md)
4. [docs/tasks.md](E:/Developers/rdp_auth/docs/tasks.md)

需要精确边界或裁决时，再看：

- [docs/development.md](E:/Developers/rdp_auth/docs/development.md)

## 测试

### 自动测试

```powershell
cargo test --workspace
```

当前自动测试已经覆盖：

- 配置 schema 与归一化
- IPC 请求 / 响应编解码
- CP 本地状态与字段行为
- helper session 状态
- challenge 状态机
- `auth_api` 的 mock HTTP 测试
- helper 审计上下文与公网 / 内网 / 客户端 IP 逻辑

### 手工 / VM 测试

当前推荐文档：

- [docs/helper-ipc-test.md](E:/Developers/rdp_auth/docs/helper-ipc-test.md)
- [docs/rdp-client-ip-vm-test.md](E:/Developers/rdp_auth/docs/rdp-client-ip-vm-test.md)

## 开发约束

这个项目对边界要求比较严格，最重要的几条是：

- 不允许 `credential_provider -> auth_api`
- 不允许 CP 发网络请求
- 不允许在日志 / IPC / 错误里输出完整手机号、用户名、密码、验证码、token、serialization
- 没有 inbound serialization 时必须 fail closed
- `GetSerialization` 只在 MFA 成功后返回
- 新增代码需要有有价值的中文注释

完整规则见：

- [docs/development.md](E:/Developers/rdp_auth/docs/development.md)
- [AGENTS.md](E:/Developers/rdp_auth/AGENTS.md)

## 当前最值得继续的方向

- 真实短信 / 二次密码 / 审计后端联调
- 远程配置拉取与完整性校验
- VM 验证当前 RDP 客户端 IP 与超时 / 断开行为

## 说明

这是一个强 Windows / LogonUI / Credential Provider 语境的项目。很多行为只有在真实 RDP 会话、Windows VM 和 LogonUI 环境里才能完全验证，所以“单元测试通过”不等于“登录链路完全闭环”。
