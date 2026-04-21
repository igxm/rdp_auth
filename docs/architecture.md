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

## 第一阶段不隐藏系统 Provider

在 pass-through 链路没有验证前，不实现过滤默认 Credential Provider。这样即使自定义 Provider 有问题，也能通过系统默认登录入口恢复测试机。等 VM 验证稳定后，再单独实现 `ICredentialProviderFilter` 和应急禁用开关。
