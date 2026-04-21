# RDP Pass-through MFA 架构说明

## 目标边界

本项目的 Credential Provider 只负责 RDP 登录后的二次认证，不替代 Windows 一次凭证输入。RDP 客户端或 NLA 阶段已经收集基础 Windows 凭证，目标机 LogonUI 会在合适场景下通过 `SetSerialization` 把原始凭证序列化数据传给 Credential Provider。

Credential Provider 的核心职责是：

1. 缓存 `SetSerialization` 传入的原始凭证。
2. 展示短信验证码、二次密码和后续微信扫码认证界面。
3. 调用本地 helper 完成二次认证。
4. 认证成功后，在 `GetSerialization` 中把原始凭证交回 LogonUI。
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

## 为什么 DLL 必须保持轻量

Credential Provider DLL 运行在 LogonUI 相关进程内。网络超时、TLS 初始化、注册表异常、panic 或死锁都会影响 Windows 登录体验。因此 DLL 只做 UI、状态机、IPC 和原始凭证转交，复杂逻辑全部放入 `remote_auth.exe`。

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

当前 UI 骨架只保存输入状态和显示状态，真实 helper 调用、短信发送、二次密码校验和 fail closed 放行策略将在后续阶段接入。

## Mock 认证阶段

在 helper 和真实 API 接入前，Credential Provider 内置最小 mock 认证用于验证阻断/放行主链路：

1. 手机验证码认证：手机号非空且验证码为 `123456` 时通过。
2. 二次密码认证：二次密码为 `mock-password` 时通过。
3. 微信扫码认证：仍保持未接入状态，不允许放行。

mock 认证通过后，`GetSerialization` 才返回缓存的 RDP 原始凭证；mock 认证失败时返回 `CPGSR_NO_CREDENTIAL_NOT_FINISHED`，LogonUI 会停留在当前 Tile。点击取消会调用 Remote Desktop Services API 断开当前会话，用于结束本次 RDP 登录尝试。

## 认证方式配置策略

手机验证码、二次密码和微信扫码是否启用，适合通过配置文件或注册表中的非敏感策略控制。该配置只决定“哪些认证方式可以展示和提交”，不保存验证码、二次密码、token 等敏感内容。

后续实现时建议增加统一的认证方式策略结构，例如：

1. `EnablePhoneCodeMfa`：控制手机验证码方式。
2. `EnableSecondPasswordMfa`：控制二次密码方式。
3. `EnableWechatMfa`：控制微信扫码方式。

安全默认值建议为：手机验证码启用、二次密码启用、微信扫码在真实逻辑接入前关闭。Credential Provider UI 必须根据策略动态生成认证方式列表；被关闭的方法不应展示，也不能通过手工构造字段值提交。如果配置非法或所有认证方式都被关闭，应 fail closed 并显示明确错误，避免配置错误导致绕过二次认证。
