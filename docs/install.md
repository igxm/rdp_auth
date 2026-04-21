# 注册工具使用说明

## 安装 Credential Provider

在管理员 PowerShell 中执行：

```powershell
cargo build -p credential_provider
cargo run -p register_tool -- install --dll .\target\debug\credential_provider.dll
```

安装会写入两个机器级注册表位置：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
- `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`

这里明确写 `HKLM\SOFTWARE\Classes`，而不是用户级注册，原因是 LogonUI/RDP 登录阶段需要机器级 COM 注册。

## 查询状态

```powershell
cargo run -p register_tool -- status
```

## 卸载 Credential Provider

在管理员 PowerShell 中执行：

```powershell
cargo run -p register_tool -- uninstall
```

## 测试提醒

当前阶段还没有实现 Credential Provider Filter，不会隐藏系统默认登录入口。首次测试必须在 VM 快照环境中进行，确认能恢复登录后再继续后续阶段。
