# RDP 二次认证任务清单

本清单只保留当前开发决策、近期任务和未完成验证项，用于减少上下文噪音。项目级硬约束仍以 [docs/development.md](E:/Developers/rdp_auth/docs/development.md) 和仓库根目录 `AGENTS.md` 为准。

## 1. 固定约束

- CP 只负责 COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC、MFA 成功后的凭证打包。
- helper 负责 session 状态、配置聚合、API 调用、审计、Windows session notification。
- CP 不发网络请求，不读取复杂配置，不保存手机号/验证码/token/serialization。
- IPC 只走 `auth_ipc`，只传非敏感字段；手机号只能传 `phone_choice_id` 和 `phone_choices_version`。
- 所有异常默认 fail closed。
- 所有有效改动必须提交 git；提交前执行：
  - `cargo fmt --all -- --check`
  - `cargo check --workspace`
  - `cargo test --workspace`

## 2. 当前阶段

当前主线是先稳定 helper / IPC / session，再继续真实 API：

- [x] helper 内存态 `SessionAuthState`
- [x] helper session notification
- [x] `has_authenticated_session` / `clear_session_state`
- [x] `get_policy_snapshot`
- [x] 多手机号脱敏选择框
- [x] `phone_choice_id`
- [x] `phone_choices_version`
- [x] helper 内存态短信 challenge
- [ ] 真实短信 API challenge 接入（真实后端待联调，当前已完成 HTTP 逻辑和 mock 服务验证）
- [ ] 二次密码真实 API 接入（真实后端待联调，当前已完成 HTTP 逻辑、helper 接入和 mock 服务验证）
- [ ] 审计上报真实 API 接入（真实后端待联调，当前已完成 HTTP 逻辑、helper 接入和 mock 服务验证）

## 3. 近期待办

### P0：真实短信 challenge 链路

- [x] helper `send_sms` 已接入 `AuthApiClient::send_sms_code` 形状，使用真实手机号换取 `SmsChallenge`
- [x] helper challenge 状态已支持从 mock token 切换为真实 `challenge_token`
- [x] `verify_sms` 优先走 `challenge_token + code`
- [x] `auth_api` 已完成真实 HTTP 请求代码，并通过 mock 服务验证 `send_sms` / `verify_sms`
- [ ] challenge 过期、手机号切换、快照版本变化时 fail closed
- [ ] `challenge_token` 不进入 IPC、CP 状态、日志、错误文本、策略快照或落盘

### P1：helper 审计上下文补齐

- [ ] 采集 RDP 客户端 IP，失败时填 `unknown`
- [ ] 获取本机公网 IP，失败时按策略返回 `unknown` 或 fail closed
- [ ] `send_sms` / `verify_sms` / `post_login_log` 带审计上下文
- [ ] IP 记录是否完整输出受配置控制

### P2：真实业务能力

- [x] 二次密码已改为 helper -> `auth_api`，默认占位配置继续保留 mock fallback
- [x] 登录日志上报已改为 helper -> `auth_api`，默认占位配置继续保留本地 success fallback
- [ ] 远程配置拉取、缓存、完整性校验
- [ ] 远程配置缓存 `.enc` 落盘

### P2：`auth_api` 结构整理

- [x] 将 `ApiError` 和稳定错误映射拆到 `error.rs`
- [x] 将 `SmsChallenge`、通用响应 envelope 等稳定模型拆到 `models.rs`
- [x] 将 `AuthApiClient` 基础配置、placeholder 判断、超时 getter 收敛到 `client.rs`
- [x] 将 `post_json`、`reqwest` 错误映射等 HTTP transport 细节拆到 `transport.rs`
- [x] 将短信 challenge 相关请求/响应和实现拆到 `sms.rs`
- [x] 将二次密码请求/响应和实现拆到 `second_password.rs`
- [x] 将 mock HTTP server 和请求捕获工具拆到 `test_support.rs`
- [x] `lib.rs` 只保留模块声明和必要 `pub use`
- [x] 拆分后保持 crate 边界不变：`auth_api` 只封装真实服务端 API，不读 CP 状态、注册表或 helper 内存状态

### P3：安装与运维

- [ ] `register_tool health` 补充 helper / 配置 / 日志 / 缓存状态
- [ ] helper 路径、配置路径、缓存路径异常场景回归
- [ ] 视需要补 Tauri 管理 GUI，但不进入登录链路

## 4. 未完成测试

### 单元测试

- [ ] 公网 IP 获取失败时按策略返回 `unknown` 或 fail closed
- [ ] MFA timeout generation 与 missing-serialization generation 的独立性边界
- [x] `auth_api` mock 服务下的真实 HTTP `send_sms` / `verify_sms`
- [x] `auth_api` mock 服务下的真实 HTTP `verify_second_password`
- [x] `auth_api` mock 服务下的真实 HTTP `post_login_log`
- [ ] `auth_api` 模块拆分后保持现有 mock HTTP 测试覆盖不回退
- [ ] helper 接真实后端联调下的 `send_sms` / `verify_sms`
- [ ] helper 接真实后端联调下的 `verify_second_password`
- [ ] helper 接真实后端联调下的 `post_login_log`

### 集成测试

- [ ] helper 不可用或 IPC 超时时 CP fail closed，且不长时间阻塞 LogonUI
- [ ] helper 已认证 session 命中与未命中时，缺失 serialization 走不同等待策略
- [ ] `send_sms` 会携带公网 IP，并在公网 IP 不可用时按策略降级
- [ ] 远程配置拉取、缓存、刷新、失败回退
- [ ] tracing 文件日志按预期写入和轮转

### VM / 手工测试

- [ ] 首次 RDP 登录时，即使 `GetCredentialCount` / `GetCredentialAt` 早于 `SetSerialization`，也不会被误断
- [ ] 无 inbound serialization 的孤立 MFA 入口会断开，不会停留
- [ ] 锁屏 / 注销返回 LogonUI 时，无新 serialization 按策略断开
- [ ] 短信发送后 300 秒等待窗口生效，短信延迟到达时不会提前断开
- [ ] 多手机号选择框只显示脱敏号码，切换号码后发送链路正确
- [ ] helper 重启后旧 `phone_choice_id` + 旧 `phone_choices_version` 不会误发到新号码
- [ ] Filter、默认 Provider 隐藏、恢复流程继续在 VM 验证

## 5. 已完成里程碑

### M1：RDP pass-through 主链路

- [x] CP 被 LogonUI 加载
- [x] 收到 `SetSerialization`
- [x] RDP 凭证重打包并完成 pass-through
- [x] MFA 成功后才允许 `GetSerialization`

### M2：本地 MFA / helper 基础链路

- [x] mock 短信验证码
- [x] mock 二次密码
- [x] MFA timeout 断开
- [x] 缺失 serialization 保护
- [x] 首次发短信成功后等待窗口延长到 300 秒
- [x] CP -> helper 命名管道 IPC
- [x] helper session 状态和 clear 流程

### M3：多手机号安全收敛

- [x] 手机号输入框移除，只显示 helper 下发的脱敏值
- [x] 支持 `phone.numbers`
- [x] helper 内部 `phone_choice_id -> 完整手机号`
- [x] `phone_choices` 下发到 CP
- [x] `send_sms` / `verify_sms` 只传 `phone_choice_id`
- [x] `phone_choices_version` 防错配

### M4：challenge 方案落地准备

- [x] helper 内存态 challenge 状态
- [x] `auth_api::SmsChallenge`
- [x] `auth_api` 形状改为 `send_sms -> challenge`、`verify_sms -> challenge_token + code`
- [x] `verify_sms` 已优先走 helper 内存态 `challenge_token + code`

### M5：`auth_api` 分层整理

- [x] `auth_api` 已按 client / transport / sms / second_password / login_log / tests 拆分，`lib.rs` 只保留入口导出

## 6. 暂不处理

- [ ] 不替代 Windows 一次登录凭证输入
- [ ] 不主动调用 `LsaLogonUser`
- [ ] 不在 CP 中做网络请求
- [ ] 不在当前阶段支持 Remote Credential Guard / Restricted Admin 特殊凭证模型
- [ ] 不把 Windows Server 2008 R2 纳入当前目标
- [ ] 不把 Tauri GUI 做成 CP / helper 运行依赖
