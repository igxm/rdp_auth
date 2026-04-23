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
- Credential Provider 侧 `ReportResult status=0` 使用的 `mark_session_authenticated` 请求只包含当前 Windows session id，不携带用户名、手机号、密码、验证码、token 或 serialization。
- Credential Provider 在 `ReportResult` 非成功或用户取消时，会用短超时 IPC 发送 `clear_session_state`，清理 helper 内存态 session 标记；清理失败只记录脱敏诊断日志，不改变 fail closed 路径。
- helper 命名管道 transport 可以把单条 JSON 请求路由到 session 状态，并拒绝非法请求且不回显敏感字段。
- `get_policy_snapshot` 响应只包含脱敏手机号，例如 `138****8888`，不包含完整手机号。
- 未知 IPC 请求类型会返回结构化解析错误。
- helper 内存态 `SessionAuthState` 可以标记已认证 session。
- TTL 过期后 session 状态自动失效。
- disconnect、logoff、显式 clear 会清理 session 状态。
- lock、unlock 只更新最近事件，不清理认证状态。
- TTL 剩余时间查询只返回 session id、状态和剩余秒数，不包含用户名、手机号、密码、验证码、token 或 serialization。

## 后续集成测试

命名管道服务端和客户端接入后，新增以下测试：

- 启动 `remote_auth` helper 后，CP 客户端可以在短超时内写入一次 JSON 请求；需要响应的后续 CP 请求再读取一条 JSON response。
- RDP 登录成功后，`credential_provider.log` 出现 `ReportResult status=0x00000000`，随后出现 `HelperIpc mark_session_authenticated_ok`；如果 helper 未启动，只允许出现 `HelperIpc mark_session_authenticated_failed`，且不得影响 Windows 登录结果。
- `mark_session_authenticated` 后，`has_authenticated_session` 命中同一 session。
- `clear_session_state` 后，`has_authenticated_session` 不再命中。
- helper 返回非法 JSON 时，CP 走 fail closed，不放行。
- helper 不可用、命名管道不存在或 IPC 超时时，CP 不长时间阻塞 LogonUI。
- `get_policy_snapshot` 返回认证方式列表、手机号来源、脱敏手机号、字段可编辑状态和超时配置；响应不得包含完整手机号。
- Credential Provider 枚举 Tile 前会用短超时读取 `get_policy_snapshot`；helper 不可用时应回退本地安全默认值，不能卡住 LogonUI，也不能放行未通过 MFA 的登录。

## 后续 VM 测试

Windows session notification 接入后，在 VM 中验证：

- RDP 首次登录成功后，`ReportResult status=0` 触发 helper 标记当前 session 已认证。
- 锁屏后返回 LogonUI，若没有新的 inbound serialization，CP 查询 helper 命中已认证 session 后走短等待/立即断开。
- logoff、disconnect、session end 后 helper 清理 session 状态。
- helper 重启后内存状态丢失时，系统按首次登录等待窗口处理，不得放行孤立 MFA。
- helper 不可用或 IPC 超时时，CP fail closed，不得绕过 MFA。

### 当前手工验证步骤

本地命名管道冒烟：

1. 执行 `cargo build -p remote_auth`。
2. 启动 `target\debug\remote_auth.exe`，确认输出 `remote_auth helper 已启动`。
3. 通过 `\\.\pipe\rdp_auth_helper` 写入 `{"type":"mark_session_authenticated","session_id":42}`，确认响应 `ok=true`。
4. 再写入 `{"type":"has_authenticated_session","session_id":42}`，确认响应 payload 中 `authenticated=true` 且 `ttl_remaining_seconds` 不为空。
5. 写入 `{"type":"clear_session_state","session_id":42}`，确认响应 `ok=true`。
6. 再次写入 `{"type":"has_authenticated_session","session_id":42}`，确认 payload 中 `authenticated=false` 且 `ttl_remaining_seconds` 为空。
7. 停止 `remote_auth.exe`，确认进程退出后不会残留测试 helper。

验证 helper 未启动时的失败路径不会拖慢登录链路：

1. 在 VM 快照中安装 `credential_provider.dll` 和 `remote_auth.exe`，但不要启动 helper 管道服务。
2. 通过 RDP + NLA + mock MFA 完成一次登录。
3. 查看 `C:\ProgramData\rdp_auth\logs\credential_provider.log`，确认存在 `ReportResult status=0x00000000`。
4. 确认随后出现 `HelperIpc mark_session_authenticated_failed`，错误内容只包含管道打开失败或 session 查询失败，不包含用户名、手机号、密码、验证码、token 或 serialization。
5. 确认用户仍然进入桌面，说明 helper 通知失败不会回滚 Windows 已完成的登录结果。

命名管道服务端完成后，再补充成功路径：

1. 启动 `remote_auth` 常驻 helper，确认它输出 `remote_auth helper 已启动` 并监听 `\\.\pipe\rdp_auth_helper`。
2. 重复 RDP + NLA + mock MFA 登录。
3. 确认 CP 日志出现 `HelperIpc mark_session_authenticated_ok`。
4. 查询 helper 内存态 session，确认同一 session id 的 `has_authenticated_session` 为 true，TTL 剩余时间不为空。

验证策略快照会影响 CP UI，且不泄漏真实手机号：

1. 在 VM 快照中通过 `register_tool config export` 导出配置，修改为 `phone.source = "config"`，并设置 `phone.number = "13812348888"`。
2. 通过 `register_tool config import` 导入配置；导入完成后删除或妥善保护导出的明文 TOML，因为其中短暂包含完整手机号。
3. 启动 `remote_auth` 常驻 helper，确认它输出 `remote_auth helper 已启动`。
4. 通过 RDP + NLA 进入 Credential Provider Tile，确认手机号字段显示为 `138****8888` 且不可编辑。
5. 检查 CP 和 helper 诊断日志，只允许出现脱敏手机号或长度/布尔状态，不得出现完整手机号、用户名、密码、验证码、token 或 serialization。
6. 停止 helper 后重复进入 Tile，确认 LogonUI 不长时间卡住，CP 使用本地安全默认策略继续显示认证方式，并且未完成 MFA 时仍不会放行。

## 安全边界

- session 状态只保存在 helper 内存中，不写注册表、不写状态文件。
- IPC 响应只返回布尔值、状态码、TTL/时间戳和脱敏策略。
- 不通过 IPC 返回用户名、完整手机号、密码、验证码、token 或 RDP serialization。
- Credential Provider 只做短超时 IPC 调用，不直接读取配置手机号、远程配置缓存或发起网络请求。
