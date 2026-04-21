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
- `HKLM\SOFTWARE\rdp_auth\config`

这里明确写 `HKLM\SOFTWARE\Classes`，而不是用户级注册，原因是 LogonUI/RDP 登录阶段需要机器级 COM 注册。

安装时还会初始化登录策略：

- `EnableRdpMfa = 1`：RDP/NLA 登录默认进入二次认证。
- `EnableConsoleMfa = 0`：本地控制台登录默认不进入二次认证，保留系统密码、PIN、Windows Hello 等入口。
- `DisableMfa = 0`：应急禁用开关默认关闭。

`CPUS_LOGON` 同时覆盖本地控制台和部分远程登录阶段，不能单靠它判断登录来源。因此当前方案把 RDP/NLA 凭证接管放在 `UpdateRemoteCredential()`，本地控制台过滤只在显式启用 `EnableConsoleMfa` 时才执行。

## 查询状态

```powershell
.\target\release\register_tool.exe status
.\target\release\register_tool.exe health
```

`health` 里应同时看到：

- `LogonUI 枚举入口: 存在`
- `Credential Provider Filter: 存在`
- `DLL 文件: 存在`
- `RDP 二次认证: 启用`
- `本地控制台二次认证: 关闭`
- `应急禁用开关: 关闭`

如果 Filter 缺失，RDP/NLA 凭证仍可能被系统默认 Password Provider 自动消费，表现就是能看到 `RDP 二次认证` Tile，但不会停留，凭证通过后直接进入桌面。

## 登录策略调整

默认推荐策略是只保护 RDP，不影响本地控制台：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableRdpMfa /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableConsoleMfa /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 0 /f
```

如果后续需要让本地控制台登录也进入二次认证，可以显式开启：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableConsoleMfa /t REG_DWORD /d 1 /f
```

开启本地控制台二次认证前，必须确认 VM 快照和应急登录手段可用。这个开关会让 Filter 在本地 `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION` 阶段隐藏其他 Provider，只保留本项目 Provider。

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

如果只是想临时关闭二次认证策略，但保留 Provider 和 Filter 注册，可以打开应急禁用开关：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 1 /f
```

恢复策略时再关闭：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 0 /f
```

## 测试提醒

当前阶段已经实现 Credential Provider Filter，并且默认采用 RDP / 本地控制台分流：

- RDP/NLA 登录：默认路由到 `RDP 二次认证` Tile。
- 本地控制台登录：默认不隐藏系统登录入口。

建议每次安装新 DLL 后按顺序验证：

1. 本地控制台登录仍能看到系统默认登录方式，并能正常进入桌面。
2. RDP 登录会停留在 `RDP 二次认证` Tile，而不是凭证通过后直接进入桌面。
3. `register_tool.exe health` 中三项策略显示符合预期。

首次测试必须在 VM 快照环境中进行，确认能恢复登录后再继续后续阶段。
