# RDP 客户端 IP VM 测试

## 目标

验证 helper 在真实 RDP 会话里能够采集客户端 IP，并把它带入短信 / 审计上下文；采集失败时仍然安全回退 `unknown`，不影响 fail closed 边界。

## 适用范围

- `remote_auth` 已包含 `WTSClientAddress` 采集逻辑
- `send_sms` / `verify_sms` / `post_login_log` 已复用 helper 审计上下文
- 当前默认允许 mock fallback，因此本测试主要验证“上下文字段是否正确”，不是验证真实后端放行

## 前置条件

1. 一台 Windows VM，已安装当前 `credential_provider.dll`、`remote_auth.exe`
2. 可以从另一台机器通过 RDP + NLA 连接该 VM
3. VM 内可查看：
   - `E:\Developers\rdp_auth\target\debug\remote_auth.exe` 或安装后的 helper
   - `C:\ProgramData\rdp_auth\logs\credential_provider.log`
4. 如需看 helper tracing 日志，确认日志目录已启用

## 建议配置

先导出并导入一份便于观察的配置：

```toml
[audit]
ip_logging = "full"
post_login_log = true

[api]
base_url = "https://example.invalid"
public_ip_endpoint = "https://example.invalid/ip"
require_public_ip_for_sms = false
```

说明：
- `ip_logging = "full"` 便于先确认客户端 IP 是否真的进入上下文
- 默认占位服务地址会保留 mock fallback，避免测试时被真实后端联调阻塞

## 测试步骤

### 用例 1：真实 RDP 会话可采集客户端 IP

1. 在 VM 中启动 `remote_auth.exe`
2. 从另一台机器通过 RDP + NLA 连接该 VM
3. 进入二次认证页面
4. 选择短信方式并点击“发送验证码”
5. 查看 helper tracing 日志，确认相关事件存在：
   - `send_sms_requested`
   - `send_sms_issued_challenge`
6. 在日志中确认：
   - `client_ip` 不是 `unknown`
   - `client_ip` 等于发起 RDP 连接那台机器对 VM 可见的地址
   - 日志中不出现完整手机号、验证码、challenge_token、serialization

预期结果：
- helper 成功记录 RDP 客户端 IP
- 客户端 IP 随短信请求一起进入 helper 审计上下文
- 没有敏感字段泄漏

### 用例 2：登录审计复用同一客户端 IP

1. 延续上一个会话，完成一次 mock MFA 成功路径
2. 触发 `post_login_log`
3. 查看 helper tracing 日志中登录审计相关事件
4. 确认：
   - `client_ip` 与短信请求里的值一致
   - `host_public_ip` / `host_private_ips` 仍按当前配置输出

预期结果：
- `post_login_log` 与 `send_sms` / `verify_sms` 使用同一套客户端 IP 来源

### 用例 3：`ip_logging = "masked"` 时客户端 IP 脱敏

1. 把配置改成：

```toml
[audit]
ip_logging = "masked"
```

2. 重启 helper
3. 再次发起一轮 RDP 登录并点击“发送验证码”
4. 查看 helper tracing 日志

预期结果：
- IPv4 显示为 `A.B.C.*`
- IPv6 显示为前四段加 `*:*:*:*`
- 不再输出完整客户端 IP

### 用例 4：采集失败时安全回退 `unknown`

可任选一种方式制造失败场景：

- 使用本地控制台而不是 RDP 进入登录页面
- 在非 RDP 场景触发 helper 审计路径
- 或在调试环境里临时让 `WTSClientAddress` 查询失败

执行：
1. 触发一次短信发送或登录审计
2. 查看 helper tracing 日志

预期结果：
- `client_ip = unknown`
- helper 仍按既有策略处理，不因为客户端 IP 采集失败误放行
- 不出现崩溃、长时间阻塞或异常断开

## 检查项

- [ ] 真实 RDP 会话里 `client_ip` 可见且正确
- [ ] `send_sms` / `verify_sms` / `post_login_log` 看到一致的客户端 IP
- [ ] `ip_logging = masked` 时客户端 IP 正确脱敏
- [ ] 客户端 IP 采集失败时回退 `unknown`
- [ ] 日志中没有完整手机号、验证码、challenge_token、serialization

## 失败时请记录

请把以下信息一起记录下来，方便我继续定位：

1. 测试时间
2. RDP 客户端机器对 VM 的实际地址
3. 使用的 `audit.ip_logging` 配置
4. helper 日志中对应事件前后 20 行
5. `credential_provider.log` 中同一时间段前后 20 行

## 当前结论口径

通过这份 VM 测试后，可以认为：

- helper 的 RDP 客户端 IP 采集逻辑在真实远程会话中可用
- 客户端 IP 已稳定进入当前审计上下文链路
- 后续真实后端联调时，重点就可以转到字段命名、服务端校验和失败策略，而不是本地采集来源
