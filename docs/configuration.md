# 配置读取方案

## 目标

配置读取以单一配置文件为主，注册表只承担 Windows 集成和应急恢复所必需的最小职责。这样可以避免认证方式、API、手机号、审计、远程策略等业务配置散落在注册表里，后续升级、远程下发、人工排查和备份恢复都更简单。

## 推荐格式

本地人工维护配置推荐使用 TOML 作为明文交换格式，但长期落盘文件必须加密：

- 加密落盘路径：`C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`
- 明文导入/导出格式：TOML，仅通过 `register_tool config export/import` 或等效维护命令短暂生成和读取，不作为长期文件保留。
- 优点：TOML 比 JSON 更适合人工编辑，支持注释，层级清晰；比 YAML 解析歧义少，Rust 生态成熟。
- 远程配置缓存可继续使用 JSON 作为解密后的内存格式，但落盘文件也必须加密，例如 `C:\ProgramData\rdp_auth\config\remote_policy.json.enc`。
- 手机号文件、旧版 `reginfo.ini` 迁移结果、远程配置缓存等所有业务配置文件都必须按同一 AES 加密方式落盘；明文旧文件只允许作为迁移输入，迁移成功后不得继续作为运行期配置来源。

## 注册表边界

注册表只保留以下内容：

1. Credential Provider / Filter 的 COM 注册项和 LogonUI 枚举入口。
2. DLL 路径和 helper 路径。
3. 统一配置文件路径，例如 `ConfigPath`。
4. 登录入口级策略：`EnableRdpMfa`、`EnableConsoleMfa`。
5. 应急恢复开关：`DisableMfa`。

认证方式开关、短信/API 地址、手机号来源、超时、审计字段、日志轮转、远程配置刷新周期等业务配置不写注册表。

## 配置文件加密

所有业务配置文件都必须加密落盘，包含本地统一配置、远程配置缓存、手机号文件、从旧版 `reginfo.ini` 迁移出的配置和后续新增的认证方式/API 配置。日志文件不属于配置文件，但日志内容仍必须按脱敏规则处理。

优先方案：

1. 首次安装时根据机器信息生成唯一机器码，写入 `HKLM\SOFTWARE\rdp_auth\config\MachineCode`。
2. 运行期使用注册表机器码派生 AES-256 key，配置文件使用 AES-256-GCM 加密；文件内容为 `nonce + ciphertext`，不再使用 envelope。
3. 注册表保存 `ConfigPath`、`HelperPath`、`MachineCode`、启用策略和应急开关，不保存 API token、手机号、远程配置内容或其它业务配置。
4. `register_tool` 提供导入/导出能力：导出需要管理员显式执行，输出明文 TOML 仅用于人工编辑；导入后立即用 AES 重新加密写回，必要时提示管理员删除临时明文。
5. `auth_config` 只暴露解密后的结构化配置，不把明文内容写日志；解析失败、解密失败、机器码缺失或密文损坏时回退安全默认值或 fail closed。
6. 当前任务目标不考虑 Windows Server 2008 R2 兼容；如未来恢复该目标，再补充机器码生成、注册表写入、AES 加密/解密和重启后继续读取测试。

## 配置优先级

1. 注册表应急开关 `DisableMfa = 1` 最高优先级，直接保留系统默认登录入口。
2. 注册表登录入口策略控制是否在 RDP/本地控制台启用本 Provider。
3. 通过完整性校验的远程配置覆盖本地业务配置，但不得关闭所有认证方式或绕过 MFA。
4. 本地统一加密配置文件提供默认业务配置。
5. 配置缺失、非法或全部认证方式关闭时，回退内置安全默认值。

旧版 `reginfo.ini` 只作为迁移来源或显式 fallback，由 helper 读取并转换为统一加密配置结构；Credential Provider DLL 不直接读取。迁移成功后，运行期不得继续依赖明文 `reginfo.ini`。

## TOML 示例

```toml
schema_version = 1

[auth_methods]
phone_code = true
second_password = true
wechat = false

[mfa]
timeout_seconds = 120
missing_serialization_grace_seconds = 1
sms_resend_seconds = 60
disconnect_when_missing_serialization = true
helper_ipc_timeout_ms = 300
session_state_ttl_seconds = 86400
authenticated_session_short_grace_seconds = 1
initial_login_grace_seconds = 5
fail_closed = true

[phone]
source = "input"
file_path = "C:\\ProgramData\\rdp_auth\\phone.txt"
validation_pattern = "^1[3-9]\\d{9}$"

[api]
base_url = "https://example.invalid"
public_ip_endpoint = "https://example.invalid/ip"
connect_timeout_seconds = 5
request_timeout_seconds = 10
require_public_ip_for_sms = false

[audit]
ip_logging = "masked"
post_login_log = true

[remote_config]
enabled = true
endpoint = "/api/host_instance/config"
cache_path = "C:\\ProgramData\\rdp_auth\\config\\remote_policy.json.enc"
refresh_seconds = 300
ttl_seconds = 900

[logging]
dir = "C:\\ProgramData\\rdp_auth\\logs"
diagnostic_level = "info"
```

## 实现拆分

- `register_tool`：安装时创建配置目录、生成/保存机器码并创建默认 AES 加密 TOML；已有文件不覆盖；注册表只写最小引导项和机器码；提供明文 TOML 的导入/导出维护命令。
- `auth_config`：解析注册表引导项、读取机器码、AES 解密配置文件、解析 TOML、本地默认值和远程缓存，输出结构化配置。
- `remote_auth`：读取完整配置，生成脱敏策略快照，通过 IPC 下发给 Credential Provider。
- `credential_provider`：只消费 helper 下发的策略快照；在 helper 未接入前使用内置安全默认值。

## 校验规则

- 配置文件解密或解析失败时记录脱敏诊断日志，并回退安全默认值。
- `mfa.timeout_seconds` 过小、过大或非法时回退 120 秒。
- 认证方式全部关闭时自动恢复手机验证码和二次密码，不能导致绕过 MFA。
- 文件模式手机号只能由 helper 读取和校验，策略快照只包含脱敏手机号。
- 远程配置必须带版本、更新时间、TTL 和签名或 HMAC；校验失败不得生效。
- 单元测试和 VM 测试必须覆盖 AES 加密文件读取、错误密文、错误机器码、旧版明文迁移和导入/导出；Windows Server 2008 R2 兼容性暂不纳入当前测试目标。
