# 注册工具使用说明

## 安装 Credential Provider

在管理员 PowerShell 中执行：

```powershell
cargo build --release -p credential_provider
cargo build --release -p register_tool
.\target\release\register_tool.exe install --dll .\target\release\credential_provider.dll
```

项目已配置静态链接 MSVC 运行库，重新构建后的 `register_tool.exe` 和 `credential_provider.dll` 不应再因为缺少 `VCRUNTIME140.dll` 而无法启动。建议测试 VM 使用 `target\release` 产物；如果 VM 上已经复制了旧构建产物，请重新复制最新的 release 文件。

如果你已经进入 `target\release` 目录，命令应改成：

```powershell
.\register_tool.exe uninstall
.\register_tool.exe install --dll .\credential_provider.dll
.\register_tool.exe status
.\register_tool.exe health
```

不要在 `target\release` 目录下继续写 `.\target\release\credential_provider.dll`，那会变成不存在的嵌套路径。

安装会写入两个机器级注册表位置：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FILTER_CLSID}`
- `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`
- `HKLM\SOFTWARE\Classes\CLSID\{FILTER_CLSID}\InprocServer32`

这里明确写 `HKLM\SOFTWARE\Classes`，而不是用户级注册，原因是 LogonUI/RDP 登录阶段需要机器级 COM 注册。

## 查询状态

```powershell
.\target\release\register_tool.exe status
.\target\release\register_tool.exe health
```

`health` 里应同时看到：

- `LogonUI 枚举入口: 存在`
- `Credential Provider Filter: 存在`
- `DLL 文件: 存在`

如果 Filter 缺失，RDP/NLA 凭证仍可能被系统默认 Password Provider 自动消费，表现就是能看到 `RDP 二次认证` Tile，但不会停留，凭证通过后直接进入桌面。

## 卸载 Credential Provider

在管理员 PowerShell 中执行：

```powershell
.\target\release\register_tool.exe uninstall
```

## 应急禁用和恢复

如果安装后登录界面异常，优先在管理员 PowerShell 中应急禁用枚举入口：

```powershell
.\target\release\register_tool.exe disable
```

`disable` 会删除 LogonUI Provider 和 Filter 的枚举入口，保留 COM 注册信息，方便继续用 `health` 排查 DLL 路径。

确认问题解决后，可以重新启用：

```powershell
.\target\release\register_tool.exe enable
```

如果需要彻底清理，再执行 `uninstall`。

## 测试提醒

当前阶段还没有实现 Credential Provider Filter，不会隐藏系统默认登录入口。首次测试必须在 VM 快照环境中进行，确认能恢复登录后再继续后续阶段。
