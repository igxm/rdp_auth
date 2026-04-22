# helper / IPC 测试说明

## 当前已覆盖

本阶段先验证不依赖 Windows 登录界面的纯逻辑，避免在 LogonUI 链路里调试协议错误。

### 单元测试

执行：

```powershell
cargo test --workspace
```

已覆盖：

- `auth_ipc` 请求/响应 JSON 序列化和反序列化。
- `mark_session_authenticated`、`has_authenticated_session`、`clear_session_state` 等 session 状态请求可以稳定编码。
- `get_policy_snapshot` 响应只包含脱敏手机号，例如 `138****8888`，不包含完整手机号。
- 未知 IPC 请求类型会返回结构化解析错误。
- helper 内存态 `SessionAuthState` 可以标记已认证 session。
- TTL 过期后 session 状态自动失效。
- disconnect、logoff、显式 clear 会清理 session 状态。
- lock、unlock 只更新最近事件，不清理认证状态。
- TTL 剩余时间查询只返回 session id、状态和剩余秒数，不包含用户名、手机号、密码、验证码、token 或 serialization。

## 后续集成测试

命名管道服务端和客户端接入后，新增以下测试：

- 启动 `remote_auth` mock helper 后，CP 客户端可以在短超时内完成一次 JSON request/response。
- `mark_session_authenticated` 后，`has_authenticated_session` 命中同一 session。
- `clear_session_state` 后，`has_authenticated_session` 不再命中。
- helper 返回非法 JSON 时，CP 走 fail closed，不放行。
- helper 不可用、命名管道不存在或 IPC 超时时，CP 不长时间阻塞 LogonUI。
- `get_policy_snapshot` 返回认证方式列表、手机号来源、脱敏手机号、字段可编辑状态和超时配置；响应不得包含完整手机号。

## 后续 VM 测试

Windows session notification 接入后，在 VM 中验证：

- RDP 首次登录成功后，`ReportResult status=0` 触发 helper 标记当前 session 已认证。
- 锁屏后返回 LogonUI，若没有新的 inbound serialization，CP 查询 helper 命中已认证 session 后走短等待/立即断开。
- logoff、disconnect、session end 后 helper 清理 session 状态。
- helper 重启后内存状态丢失时，系统按首次登录等待窗口处理，不得放行孤立 MFA。
- helper 不可用或 IPC 超时时，CP fail closed，不得绕过 MFA。

## 安全边界

- session 状态只保存在 helper 内存中，不写注册表、不写状态文件。
- IPC 响应只返回布尔值、状态码、TTL/时间戳和脱敏策略。
- 不通过 IPC 返回用户名、完整手机号、密码、验证码、token 或 RDP serialization。
- Credential Provider 只做短超时 IPC 调用，不直接读取手机号文件、远程配置缓存或发起网络请求。
