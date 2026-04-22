# 配置加密测试计划

## 目标

验证所有运行期业务配置都以 AES 加密文件落盘，明文 TOML/JSON 只作为导入/导出的临时交换格式，不作为运行期配置来源。

## 本地自动化测试

在开发机执行：

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

必须覆盖：

- AES 加密后不包含 `serveraddr`、`hostuuid`、手机号、API 地址等明文字段。
- AES 解密后能恢复原始 TOML/JSON bytes。
- 截断密文、错误机器码、认证标签校验失败时返回结构化错误。
- 配置 TOML 解析失败时回退安全默认值，不打印明文配置。
- 机器码由机器信息生成，格式为 64 位十六进制 SHA-256 字符串。

## 安装工具测试

在管理员 PowerShell 中执行：

```powershell
cargo build --workspace
target\debug\register_tool.exe install --dll <credential_provider.dll>
target\debug\register_tool.exe health
target\debug\register_tool.exe status
```

检查点：

- 默认配置路径应为 `C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`。
- `rdp_auth.toml.enc` 存在，文件内容不能包含 `schema_version`、`timeout_seconds` 等明文字段。
- 注册表 `HKLM\SOFTWARE\rdp_auth\config\MachineCode` 存在，且只包含 64 位十六进制机器码。
- `health` / `status` 只显示配置路径、加密状态、AES 算法、密文长度和生效值，不显示完整配置明文或机器码。
- 删除或破坏 `.enc` 文件后，`health` 应显示读取失败并回退安全默认值，不崩溃。

## AES/机器码实机测试

在同一台 Windows 机器上：

1. 使用安装工具生成默认 `.enc` 配置。
2. 重启机器。
3. 再次执行 `register_tool health`，确认仍可解密读取。
4. 修改注册表 `MachineCode` 为另一有效 64 位十六进制值后执行 `health`，预期 AES 解密失败并回退安全默认值；测试后恢复原机器码。
5. 将 `.enc` 文件复制到另一台机器执行 `health`，预期因为机器码不同导致 AES 解密失败并回退安全默认值。

## 明文迁移测试

后续实现 `register_tool config import/export` 后执行：

- `export` 生成的明文 TOML 只能由管理员显式指定路径，不应自动放在运行目录。
- `import` 成功后只保留 `.enc` 作为运行期配置。
- `import` 失败时不能覆盖原有有效 `.enc` 文件。
- 旧版 `reginfo.ini` 迁移成功后应写入统一加密配置，运行期不再读取明文旧文件。

## Windows Server 2008 R2

当前任务目标不考虑 Windows Server 2008 R2 兼容，因此本节不作为当前测试要求。未来如恢复该兼容目标，再在 Windows Server 2008 R2 SP1 64 位 VM 中执行：

1. 记录补丁状态、RDP/NLA 状态和 VC++ 运行时状态。
2. 执行安装工具生成 `.enc` 配置。
3. 执行 `register_tool health`，确认机器码存在且 AES 解密成功。
4. 重启 VM 后再次确认解密成功。
5. 如 AES 加密/解密失败，记录错误码、系统补丁状态、CPU 指令兼容性和依赖运行时状态。
