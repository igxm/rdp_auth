# RDP Pass-through MFA 架构说明

## 目标边界

本项目的 Credential Provider 只负责 RDP 登录后的二次认证，不替代 Windows 一次凭证输入。RDP 客户端或 NLA 阶段已经收集基础 Windows 凭证，目标机 LogonUI 会在合适场景下通过 `SetSerialization` 把远程 authentication buffer 传给 Credential Provider。

Credential Provider 的核心职责是：

1. 接收 `SetSerialization` 传入的远程 authentication buffer，并解包出 Windows 一次凭证。
2. 展示短信验证码、二次密码和后续微信扫码认证界面。
3. 调用本地 helper 完成二次认证。
4. 认证成功后，在 `GetSerialization` 中重新打包成 LogonUI/LSA 可消费的 Negotiate 凭证。
5. 认证失败或未收到原始凭证时，拒绝交出凭证。

## 进程划分

```text
mstsc / RDP Client
  -> NLA / Windows 基础凭证
    -> 目标机 LogonUI
      -> credential_provider.dll
        -> 命名管道
          -> remote_auth.exe
            -> 注册表 / reginfo.ini
            -> 认证服务端 API
            -> 本地脱敏日志
```

`remote_auth.exe` 是无 UI 的核心后台 helper。它负责命名管道 IPC、Windows session
notification、配置解密与聚合、真实认证 API、审计日志和内存态 session 状态。它不得依赖
Tauri、WebView2、前端资源、窗口事件循环或 GUI 自动更新才能启动；后续安装器只能把这个核心
helper 作为登录链路组件登记。

后续 Tauri 管理 GUI 只定位为管理员进入桌面后的配置和运维工具。GUI 可以复用
`register_tool config import/export/status/health`，或通过受控 helper 管理 IPC 查询状态和写入配置；
它不参与 LogonUI、Credential Provider、Winlogon、LSA、RDP 断开决策或 fail closed 判断。GUI
未安装、崩溃、升级失败或 WebView2/runtime 缺失时，核心 helper、CP 和 RDP MFA 登录链路必须继续按
无 GUI 模式工作。

## 为什么 DLL 必须保持轻量

Credential Provider DLL 运行在 LogonUI 相关进程内。网络超时、TLS 初始化、注册表异常、panic 或死锁都会影响 Windows 登录体验。因此 DLL 只做 UI、状态机、IPC 和原始凭证转交，复杂逻辑全部放入 `remote_auth.exe`。

DLL 内允许写入极轻量的本地诊断日志，用于排查 RDP pass-through 链路问题。日志路径为 `C:\ProgramData\rdp_auth\logs\credential_provider.log`，只记录阶段、PID、session、Provider GUID、serialization 长度、认证状态和 Windows `ReportResult` 状态码；不得记录用户名、密码、验证码、token 或 `rgbSerialization` 字节内容。日志写入失败必须被忽略，不能影响 LogonUI 主流程。

## Credential Provider Filter 策略

当前已经实现 `ICredentialProviderFilter`，用于防止 RDP/NLA 场景绕过二次认证。Filter 的策略必须区分 RDP 会话和本地控制台会话：

1. RDP 登录且 `EnableRdpMfa = 1` 时，只保留本项目 Provider，隐藏系统默认入口。
2. 本地登录且 `EnableConsoleMfa = 0` 时，隐藏本项目 Provider，保留系统默认入口。
3. 本地登录且 `EnableConsoleMfa = 1` 时，只保留本项目 Provider。
4. `DisableMfa = 1` 时，隐藏本项目 Provider，保留系统默认入口，用于应急恢复。

`CPUS_LOGON` 同时覆盖本地控制台和部分远程登录阶段，不能单独用它判断来源。RDP/NLA 凭证接管仍以 `UpdateRemoteCredential()` 为核心入口：收到远程凭证序列化后，将 `clsidCredentialProvider` 改写为本项目 Provider CLSID，再让 LogonUI 展示二次认证 Tile。

## 当前 UI 骨架

Credential Provider Tile 已经预留以下二次认证字段：

1. 认证方式组合框：手机验证码、二次密码、微信扫码（预留）。
2. 手机验证码字段：手机号、短信验证码、发送验证码。
3. 二次密码字段：二次密码输入框。
4. 微信扫码字段：当前只显示预留提示，不接入真实逻辑。
5. 登录和取消操作。

认证方式切换后，Credential 会通过 `ICredentialProviderCredentialEvents` 主动通知 LogonUI 更新字段显示状态。发送验证码后，按钮会进入 `重新发送(60)` 的禁用态，防止重复点击；真正的逐秒倒计时和 60 秒后恢复点击，需要结合受控 UI 刷新或 helper 心跳接入，避免在 LogonUI 进程内使用不受控后台线程。

配置手机号模式下，手机号字段只展示 helper 返回的脱敏值。由于 LogonUI 对 `READONLY` 文本框的处理并不总是阻止临时输入，Credential Provider 收到只读手机号字段的写入回调时会立即恢复显示值，状态中仍只保留脱敏号码。

当前 UI 骨架已经通过 helper 接入短信发送、短信校验、二次密码校验和登录日志上报；默认占位服务地址下 helper 会保留 mock fallback 或本地 success fallback，保证在正式后端联调前仍可验证主链路。fail closed 放行策略已经按 helper 响应收敛，后续主要剩真实后端联调和公网 IP / 审计上下文补齐。

## Mock 认证阶段

在 helper 和真实 API 接入前，Credential Provider 内置最小 mock 认证用于验证阻断/放行主链路：

1. 手机验证码认证：手机号非空且验证码为 `123456` 时通过。
2. 二次密码认证：二次密码为 `mock-password` 时通过。
3. 微信扫码认证：仍保持未接入状态，不允许放行。

mock 认证通过后，`GetSerialization` 才返回重新打包后的 Windows 登录凭证；mock 认证失败时返回 `CPGSR_NO_CREDENTIAL_NOT_FINISHED`，LogonUI 会停留在当前 Tile。点击取消会调用 Remote Desktop Services API 断开当前会话，用于结束本次 RDP 登录尝试。

Filter 会临时把 Provider CLSID 改成本项目 CLSID，让 LogonUI 把远程 authentication buffer 交给二次认证 Tile。实机 RDP 链路里 `UpdateRemoteCredential()` 与 Provider `SetSerialization()` 可能不在同一进程内，因此原始 Provider CLSID 同时通过进程内缓存和 `C:\ProgramData\rdp_auth` 下按 session 区分的临时 handoff 文件传递；handoff 文件只保存 Provider GUID，不保存用户名、密码或 serialization 字节，并在读取后删除。当前放行不再原样返回 inbound buffer，因为日志显示 inbound `auth_package=0` 会导致 LSA 返回 `STATUS_LOGON_FAILURE`；Provider 会使用 `CredUnPackAuthenticationBufferW` 解包远程凭证，再用 `CredPackAuthenticationBufferW` 和 `LsaLookupAuthenticationPackage("Negotiate")` 重新生成可登录的凭证 serialization。

排查 mock MFA 通过后仍无法进入桌面时，优先查看 `credential_provider.log` 中是否出现完整链路：`UpdateRemoteCredential route_to_mfa`、`RemoteProviderHandoff write_ok`、`SetSerialization unpacked_remote_credential`、`GetSerialization returning_packed_logon`。如果这些都正常但随后 `ReportResult` 返回 `0xC000006D` 等登录失败状态，说明 Windows 已收到重新打包的凭证但 LSA 拒绝，需要继续检查域名/用户名组合、认证包或 RDP/NLA 凭证模型。

## RDP 注销与无原始凭证策略

当前架构依赖 RDP/NLA 阶段传入的原始凭证序列化数据，本项目不替代 Windows 一次凭证输入，也不保存可重新构造登录的明文用户名密码。用户已经进入桌面后如果执行注销，远程连接可能回到 LogonUI，但此时不一定会再次触发 `UpdateRemoteCredential()` 并提供新的 inbound serialization。

因此在 RDP 场景下，如果没有收到 inbound credential serialization，不允许只显示孤立的 MFA 入口。默认处理策略是断开当前 RDP 连接，让用户重新发起 RDP/NLA 登录；新的连接会重新提供原始 Windows 凭证，然后再进入二次认证流程。只有后续实现完整的一次凭证采集与打包能力时，才应考虑注销后不断开并在同一界面重新登录。

当前实现会在 RDP 会话枚举出本项目 Credential Tile 但短时间内没有收到 `SetSerialization` 时启动缺失凭证保护。该保护会给 LogonUI 一个 1 秒等待窗口；如果窗口内仍没有新的 inbound serialization，就调用 Remote Desktop Services API 断开当前 RDP 会话。这样可以覆盖用户锁屏、注销或返回登录界面后没有新 NLA 凭证的情况，避免用户停留在无法放行的孤立 MFA 界面。

## 认证超时策略

二次认证界面已经接入默认 2 分钟超时断开机制：Credential Provider 收到 RDP inbound serialization 后启动一次性受控定时器，如果到期时二次认证仍未通过，会调用 Remote Desktop Services API 断开当前 RDP 会话，避免远程登录界面长时间停留。首次点击发送短信验证码并收到 helper 成功响应后，当前二次认证页面等待窗口会重置为 5 分钟；后续重发短信只刷新重发倒计时，不再延长 MFA 超时。

为了避免短信延迟到达时被“缺失 inbound serialization 保护”提前断开，首次短信发送成功后会同时把缺失 serialization 的断开等待窗口重置为 300 秒；但这只影响等待时间，不改变放行条件。`GetSerialization` 仍然必须同时满足“二次认证成功”和“存在 inbound serialization”两个条件，否则继续 fail closed。

MFA 超时和缺失 serialization 保护分别维护独立的 timer generation：新的 RDP serialization 只重置对应计时器，首次短信发送成功时同时重置两类等待窗口，旧定时器醒来后会自动退出，避免两条断开路径互相覆盖。

## 认证方式配置策略

手机验证码、二次密码和微信扫码是否启用，适合通过配置文件或注册表中的非敏感策略控制。该配置只决定“哪些认证方式可以展示和提交”，不保存验证码、二次密码、token 等敏感内容。

后续实现时建议增加统一的认证方式策略结构，例如：

1. `EnablePhoneCodeMfa`：控制手机验证码方式。
2. `EnableSecondPasswordMfa`：控制二次密码方式。
3. `EnableWechatMfa`：控制微信扫码方式。

安全默认值建议为：手机验证码启用、二次密码启用、微信扫码在真实逻辑接入前关闭。Credential Provider UI 必须根据策略动态生成认证方式列表；被关闭的方法不应展示，也不能通过手工构造字段值提交。如果配置非法，或配置文件把所有认证方式都关闭，应恢复默认认证方式集合，并记录脱敏诊断信息，避免配置错误导致绕过二次认证。
