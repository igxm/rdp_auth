# 统一日志规范

本项目所有程序的诊断日志统一通过 `auth_logging` crate 进入 `C:\ProgramData\rdp_auth\logs`，后续接入集中式日志采集时只需要对接这一层的目录、文件名、字段和脱敏规则。

## 日志入口

- `credential_provider`：继续使用轻量同步追加写入，入口是 `credential_provider::diagnostics::log_event()`，底层调用 `auth_logging::append_diagnostic_record()`。该路径运行在 LogonUI 相关进程内，必须吞掉 IO 错误，不能初始化后台线程或阻塞登录主流程。
- `remote_auth`：使用 `auth_logging::init_tracing_file()` 初始化 `tracing` + `tracing-subscriber` + `tracing-appender`，日志按天滚动写入 `remote_auth.log.*`。
- `register_tool`：命令成功或失败时写入 `register_tool.log`，仅记录命令阶段、PID 和脱敏结果，不记录配置明文、密钥、手机号或导入文件内容。

## 统一字段

同步诊断记录使用同一行文本格式：

```text
ts_ms=<unix_ms> component=<component> pid=<pid|unknown> session=<session|unknown> stage=<stage> message=<redacted>
```

- `component` 只允许使用 `auth_logging` 中定义的组件常量。
- `stage` 使用稳定英文标识，例如 `SetSerialization`、`GetSerialization`、`install`、`health`。
- `message` 必须是排障上下文，不得包含用户名、密码、验证码、token、完整手机号、机器码、配置明文或 RDP serialization 字节。
- `session` 对 CP 记录 Windows session id；普通工具没有 session 时写 `unknown`。

## 脱敏规则

所有程序共享 `auth_logging::sanitize_log_value()`：

- `\r`、`\n`、`\t` 会被替换为空格，避免单条日志拆成多行。
- 连续 6 位及以上数字会被替换为 `<redacted-number>`，用于覆盖手机号、验证码和长编号。
- 包含 `password`、`token`、`code`、`serialization` 的 token 会被替换为 `<redacted-secret>`。

新增日志字段前必须先判断字段是否可能携带敏感输入。禁止直接记录 `?struct` 或 `%struct`，除非该结构体的 `Debug` / `Display` 已经明确只输出脱敏字段。

## 健康检查

`register_tool health` 只读取日志目录和最近诊断日志的元数据，包括路径、大小、修改时间，不读取日志内容。可识别的诊断日志文件名统一由 `auth_logging::is_known_diagnostic_log_file()` 判断，当前包括：

- `credential_provider.log`
- `remote_auth.log*`
- `register_tool.log`

## 后续统一日志接入

集中采集器应优先监听 `C:\ProgramData\rdp_auth\logs`，按 `component` 和 `stage` 建索引。CP 的日志写入路径不能被替换为可能阻塞 LogonUI 的网络写入；如果后续需要上传 CP 日志，也应由 helper 或独立采集进程异步读取文件后上传。
