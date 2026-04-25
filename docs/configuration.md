# 配置读取方案

## 目标

配置读取以单一配置文件为主，注册表只承担 Windows 集成和应急恢复所必需的最小职责。这样可以避免认证方式、API、手机号、审计、远程策略等业务配置散落在注册表里，后续升级、远程下发、人工排查和备份恢复都更简单。

## 推荐格式

本地人工维护配置推荐使用 TOML 作为明文交换格式，但长期落盘文件必须加密：

- 加密落盘路径：`C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`
- 明文导入/导出格式：TOML，仅通过 `register_tool config export/import` 或等效维护命令短暂生成和读取，不作为长期文件保留。
- 优点：TOML 比 JSON 更适合人工编辑，支持注释，层级清晰；比 YAML 解析歧义少，Rust 生态成熟。
- 远程配置缓存可继续使用 JSON 作为解密后的内存格式，但落盘文件也必须加密，例如 `C:\ProgramData\rdp_auth\config\remote_policy.json.enc`。
- 手机号随本地统一配置一起加密落盘；旧版手机号文件、旧版 `reginfo.ini` 迁移结果、远程配置缓存等业务配置材料必须按同一 AES 加密方式落盘。明文旧文件只允许作为迁移输入，迁移成功后不得继续作为运行期配置来源。

## 注册表边界

注册表只保留以下内容：

1. Credential Provider / Filter 的 COM 注册项和 LogonUI 枚举入口。
2. DLL 路径和 helper 路径。
3. 统一配置文件路径，例如 `ConfigPath`。
4. 登录入口级策略：`EnableRdpMfa`、`EnableConsoleMfa`。
5. 应急恢复开关：`DisableMfa`。

认证方式开关、短信/API 地址、手机号来源、超时、审计字段、日志轮转、远程配置刷新周期等业务配置不写注册表。

## 配置文件加密

所有业务配置文件都必须加密落盘，包含本地统一配置、远程配置缓存、从旧版手机号文件或 `reginfo.ini` 迁移出的配置和后续新增的认证方式/API 配置。日志文件不属于配置文件，但日志内容仍必须按脱敏规则处理。

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
source = "config"
number = "13812348888"
numbers = ["13812348888", "13912349999"]
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

当前 `auth_config` 已落地的 schema 包含 `[auth_methods]`、`[mfa]`、`[phone]`、`[api]`、`[audit]`、`[remote_config]`、`[logging]`。真实 API 调用、远程配置拉取、远程缓存加密落盘和完整性校验属于 helper/auth_api 后续任务，Credential Provider 不直接读取这些业务配置字段。

其中与审计上下文直接相关的现状如下：

- `api.public_ip_endpoint` 已由 helper / `auth_api` 用于查询本机公网出口 IP；默认占位地址或查询失败时回退 `unknown`。
- `audit.ip_logging = "full" | "masked" | "off"` 当前已经作用于登录审计里的公网 / 内网 IP 输出：
  - `full`：记录完整 IP
  - `masked`：IPv4 保留前三段、IPv6 保留前四段
  - `off`：不输出 IP 列表，单值字段回退 `unknown`
- `api.require_public_ip_for_sms` 仍保留给短信链路后续接入使用；当前已生效的是登录审计上下文，不会因为公网 IP 查询失败阻断登录日志 mock / fallback 路径。

## 多手机号选择框方案（后续）

后续如果需要在二次认证页面提供多个手机号选择框，安全边界仍保持不变：完整手机号只能由 helper 从加密配置读取并短暂停留在 helper 内存中，不能进入 Credential Provider、IPC payload、诊断日志或错误文本。Credential Provider 只拿到可渲染的脱敏选项和非敏感选择 ID。

配置保持单手机号向后兼容，同时支持多手机号列表：

```toml
[phone]
source = "config"
number = "13812348888"
numbers = ["13812348888", "13912349999"]
validation_pattern = "^1[3-9]\\d{9}$"
```

归一化规则建议如下：

- `number` 保留为兼容字段；`numbers` 存在时优先使用 `numbers`，否则把非空的 `number` 视为单元素列表。
- 每个号码在 helper 侧按统一规则校验、去重和脱敏；无有效号码时短信认证 fail closed，并向 CP 返回可展示错误。
- helper 为每个有效号码生成不包含手机号数字的选择 ID，例如 `phone-0`、`phone-1` 或带配置版本的临时 ID。
- 策略快照只包含 `{ id, masked }`，例如 `{ id = "phone-0", masked = "138****8888" }`。
- `send_sms` / `verify_sms` 请求只携带 `phone_choice_id` 和验证码等必要字段，不携带完整手机号。
- helper 收到 `phone_choice_id` 后在本进程内映射到完整手机号，再调用短信 API；找不到 ID、配置变化或号码非法时必须 fail closed。

Credential Provider UI 可以把手机号字段从普通文本升级为组合框，但组合框项只能显示脱敏手机号。CP 状态中只能保存选中索引、选择 ID 和脱敏展示值，不能保存完整手机号。

## 实现拆分

- `register_tool`：安装时创建配置目录、生成/保存机器码并创建默认 AES 加密 TOML；已有文件不覆盖；注册表只写最小引导项和机器码；提供明文 TOML 的导入/导出维护命令。
- `auth_config`：解析注册表引导项、读取机器码、AES 解密配置文件、解析 TOML、本地默认值和远程缓存，输出结构化配置。
- `remote_auth`：读取完整配置，生成脱敏策略快照，通过 IPC 下发给 Credential Provider。
- `credential_provider`：只消费 helper 下发的策略快照；在 helper 未接入前使用内置安全默认值。

## 校验规则

- 配置文件解密或解析失败时记录脱敏诊断日志，并回退安全默认值。
- `mfa.timeout_seconds` 过小、过大或非法时回退 120 秒；首次点击发送短信验证码并成功后，当前二次认证页面等待窗口会重置为 300 秒，后续重发不再刷新该超时。
- 如果当前 Tile 仍处于缺失 inbound serialization 的等待窗口，首次短信发送成功后会同步把该断开等待窗口也重置为 300 秒，避免短信延迟到达时被提前断开；但没有 inbound serialization 时仍然不能放行登录。
- 认证方式全部关闭时自动恢复手机验证码和二次密码，不能导致绕过 MFA。
- 手机号只能由 helper 从加密配置读取和校验，Credential Provider 不再提供手机号输入框，策略快照只包含脱敏手机号或脱敏手机号选择项；旧配置中的 `phone.source = "input"` 会被归一化为 `config`。明文导出 TOML 会短暂包含完整手机号，必须按敏感文件处理。
- 远程配置必须带版本、更新时间、TTL 和签名或 HMAC；校验失败不得生效。
- 单元测试和 VM 测试必须覆盖 AES 加密文件读取、错误密文、错误机器码、旧版明文迁移和导入/导出；Windows Server 2008 R2 兼容性暂不纳入当前测试目标。


## Challenge Token 方案

当前 `send_sms` / `verify_sms` 已都按真实 HTTP 请求形状落地到 `auth_api`，并用 crate 内 mock 服务完成了请求/响应测试；helper 侧仍保留默认占位配置的 `NotImplemented -> mock fallback` 语义，便于在正式后端联调前继续验证登录主链路。

- `send_sms` 阶段由 helper 在本进程内把 `phone_choice_id` 映射到完整手机号，再向后端发起发送短信请求；当 `auth_api` 返回真实 `SmsChallenge` 时，helper 会把 `challenge_token` 和服务端 TTL 写入内存态 challenge。
- 后端返回 opaque `challenge_token` 后，helper 只在内存中保存 `session_id`、`phone_choice_id`、`challenge_token`、过期时间和 challenge 状态，不落盘。
- `verify_sms` 阶段由 helper 用 `challenge_token + code` 向后端校验；如果当前仍使用默认占位服务地址，`auth_api` 会返回 `NotImplemented`，helper 继续临时回退到 mock 校验，避免在正式后端联调前把现有登录链路全部打断。
- Credential Provider、IPC 响应、策略快照、诊断日志、错误文本均不得包含 `challenge_token` 原值。
- 如需防止旧 `phone_choice_id` 对应到新号码的错配，应在手机号选择快照中增加配置版本、代次或等效 challenge 上下文；helper 发现映射不一致时必须 fail closed，并提示用户重新选择手机号。
