# 测试安装说明

本文用于在测试 VM 中安装、验证和回滚 RDP 二次认证 Credential Provider。首次测试必须在可快照恢复的 VM 中进行，不要直接在生产机器上试装。

## 1. 构建

在管理员 PowerShell 中，从仓库根目录执行：

```powershell
cargo build --release -p credential_provider
cargo build --release -p register_tool
```

项目已配置 MSVC 运行库静态链接。重新构建后的 `register_tool.exe` 和 `credential_provider.dll` 不应再因为缺少 `VCRUNTIME140.dll` 而无法启动。

建议测试 VM 使用 `target\release` 下的最新产物。如果 VM 上已经复制过旧产物，请重新复制最新的 release 文件。

## 2. 安装

如果当前目录是仓库根目录：

```powershell
.\target\release\register_tool.exe install --dll .\target\release\credential_provider.dll
.\target\release\register_tool.exe status
.\target\release\register_tool.exe health
```

如果已经进入 `target\release` 目录：

```powershell
.\register_tool.exe install --dll .\credential_provider.dll
.\register_tool.exe status
.\register_tool.exe health
```

不要在 `target\release` 目录下继续写 `.\target\release\credential_provider.dll`，否则会变成不存在的嵌套路径。

安装会写入以下机器级注册表位置：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FILTER_CLSID}`
- `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`
- `HKLM\SOFTWARE\Classes\CLSID\{FILTER_CLSID}\InprocServer32`
- `HKLM\SOFTWARE\rdp_auth\config`

这里必须写 `HKLM\SOFTWARE\Classes`，不能写用户级注册表，因为 LogonUI/RDP 登录阶段需要机器级 COM 注册。

## 3. 默认策略

安装时会初始化登录策略；如果注册表中已有值，安装不会覆盖已有值。

默认推荐策略是只保护 RDP，不影响本地控制台：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableRdpMfa /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableConsoleMfa /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 0 /f
```

含义：

- `EnableRdpMfa = 1`：RDP/NLA 登录默认进入 `RDP 二次认证`。
- `EnableConsoleMfa = 0`：本地控制台登录默认不进入二次认证，保留系统密码、PIN、Windows Hello 等入口。
- `DisableMfa = 0`：应急禁用开关默认关闭。

当前 Filter 会区分 RDP 会话和本地控制台会话：

- RDP 登录且 `EnableRdpMfa = 1`：隐藏系统默认登录入口，只保留 `RDP 二次认证`。
- 本地登录且 `EnableConsoleMfa = 0`：隐藏 `RDP 二次认证`，只保留系统默认登录入口。
- 本地登录且 `EnableConsoleMfa = 1`：隐藏系统默认入口，只保留 `RDP 二次认证`。
- `DisableMfa = 1`：隐藏 `RDP 二次认证`，保留系统默认入口，用于应急恢复。

## 4. 健康检查

执行：

```powershell
.\target\release\register_tool.exe health
```

如果当前目录是 `target\release`：

```powershell
.\register_tool.exe health
```

`health` 中应看到：

- `LogonUI 枚举入口: 存在`
- `Credential Provider Filter: 存在`
- `DLL 文件: 存在`
- `RDP 二次认证: 启用`
- `本地控制台二次认证: 关闭`
- `应急禁用开关: 关闭`

如果 Filter 缺失，RDP/NLA 凭证仍可能被系统默认 Password Provider 自动消费，表现为能看到 `RDP 二次认证` Tile，但登录不会停留在二次认证流程。

## 5. 登录验证

每次安装新 DLL 后，按下面顺序验证。

1. 先确认 VM 快照可恢复。
2. 在本地控制台登录页验证：默认策略下应看不到 `RDP 二次认证` 入口，应只看到系统默认登录方式，并能正常进入桌面。
3. 从另一台机器发起 RDP 登录：默认策略下应只看到 `RDP 二次认证`，不应同时显示系统默认用户/密码入口。
4. 在 RDP 登录中输入凭证后，应停留在 `RDP 二次认证` Tile，而不是凭证通过后直接进入桌面。
5. 使用 mock 数据验证放行：手机验证码方式输入任意非空手机号和验证码 `123456`，或二次密码方式输入 `mock-password`，点击登录后应继续进入桌面。
6. 使用错误验证码或错误二次密码验证阻断：应停留在当前 Tile，不应进入桌面。
7. 点击取消应断开当前 RDP 连接。
8. 登录后再次执行 `register_tool.exe health`，确认注册表入口、DLL 路径和三项策略仍符合预期。

如果 RDP 登录页同时显示系统默认入口和 `RDP 二次认证`，优先检查：

- `Credential Provider Filter` 是否注册成功。
- `EnableRdpMfa` 是否为 `1`。
- `DisableMfa` 是否为 `0`。
- VM 是否已经部署了最新的 `credential_provider.dll`。

如果本地登录页显示了 `RDP 二次认证`，优先检查：

- `EnableConsoleMfa` 是否被手动改成了 `1`。
- `DisableMfa` 是否为 `0`。
- 是否仍在旧 DLL 上测试。

当前 mock 认证只用于验证 Credential Provider 主链路，真实短信发送、二次密码校验和登录日志上报仍在后续 helper/API 阶段接入。

## 6. 策略调整

如需让本地控制台登录也进入二次认证：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableConsoleMfa /t REG_DWORD /d 1 /f
```

开启前必须确认 VM 快照和应急登录手段可用。该开关会让 Filter 在本地 `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION` 阶段隐藏系统默认 Provider，只保留本项目 Provider。

恢复为只保护 RDP：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableConsoleMfa /t REG_DWORD /d 0 /f
```

临时关闭 RDP 二次认证，但保留 Provider 和 Filter 注册：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableRdpMfa /t REG_DWORD /d 0 /f
```

恢复 RDP 二次认证：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v EnableRdpMfa /t REG_DWORD /d 1 /f
```

## 7. 应急禁用和恢复

如果安装后登录界面异常，优先在管理员 PowerShell 中删除 LogonUI 枚举入口：

```powershell
.\target\release\register_tool.exe disable
```

如果当前目录是 `target\release`：

```powershell
.\register_tool.exe disable
```

`disable` 会删除 Provider 和 Filter 的 LogonUI 枚举入口，保留 COM 注册信息，方便继续用 `health` 排查 DLL 路径。

确认问题解决后重新启用：

```powershell
.\target\release\register_tool.exe enable
```

或在 `target\release` 中：

```powershell
.\register_tool.exe enable
```

如果只是想临时关闭二次认证策略，但保留 Provider 和 Filter 枚举入口，可以打开应急禁用开关：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 1 /f
```

恢复策略时再关闭：

```powershell
reg add "HKLM\SOFTWARE\rdp_auth\config" /v DisableMfa /t REG_DWORD /d 0 /f
```

### 离线恢复

如果无法进入系统桌面，可以使用 VM 快照恢复，或通过 Windows 恢复环境/离线注册表编辑恢复登录入口。离线恢复时优先删除本项目的 LogonUI 枚举入口，保留系统默认 Credential Provider：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FILTER_CLSID}`

也可以离线把 `HKLM\SOFTWARE\rdp_auth\config\DisableMfa` 设置为 `1`。恢复后先确认本地控制台能看到系统默认登录入口，再继续排查 DLL 路径和策略配置。

## 8. 卸载

在管理员 PowerShell 中执行：

```powershell
.\target\release\register_tool.exe uninstall
```

如果当前目录是 `target\release`：

```powershell
.\register_tool.exe uninstall
```

`uninstall` 会删除本项目 Provider、Filter 和 COM 注册项。卸载后建议再次运行：

```powershell
.\target\release\register_tool.exe health
```

此时应显示枚举入口缺失或未安装。
