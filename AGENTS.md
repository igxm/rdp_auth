# rdp_auth 开发硬约束 Checklist

本文件是给后续 Codex/协作者的项目级执行清单。完整规范见 `docs/development.md`；如本清单与完整规范冲突，以 `docs/development.md` 为准。

## 任务启动

- [ ] 先阅读本文件和 `docs/development.md`，把规范视为硬约束。
- [ ] 如任务需要突破既有边界，先在设计或任务清单中写明原因、风险和回滚方式。
- [ ] 开始前查看 `git status --short`，区分用户已有改动和本次改动。

## Git

- [ ] 每次有效代码、文档、配置变更都提交到 git。
- [ ] 提交前确认 `git status --short` 没有遗漏本次应提交文件。
- [ ] 提交信息使用短前缀，如 `docs:`、`feat:`、`fix:`、`test:`。
- [ ] 不回滚或覆盖用户已有的无关改动。

## 中文注释

- [ ] 所有新增代码包含必要中文注释。
- [ ] 注释解释维护难点：Windows COM 生命周期、引用计数、凭证序列化、命名管道、安全边界、失败策略。
- [ ] 避免只复述代码表面含义。

## 分层与职责

- [ ] 新代码能用一句话说明所在模块职责。
- [ ] 单个文件只处理一个长期概念；同时承载两个以上长期概念时拆分模块。
- [ ] 抽象服务于可维护性、测试或安全边界，不制造空壳。
- [ ] 依赖方向清楚，敏感数据不跨层乱传，低层逻辑可独立测试。

## Crate 边界

- [ ] `auth_core` 只放纯业务类型和纯函数；不得依赖 Windows、注册表、文件系统、网络、IPC 或配置文件。
- [ ] `auth_config` 只负责最小注册表引导项、加密配置读写、TOML schema、默认值归一化和旧配置迁移；不得发网络请求、读取真实手机号文件或承担 helper 运行状态。
- [ ] `auth_ipc` 只定义 CP/helper 协议类型、JSON 编解码和非敏感 payload；不得实现命名管道 IO、Windows session notification 或业务 API。
- [ ] `auth_logging` 统一日志目录、文件名、诊断格式、tracing 初始化和脱敏函数；新增诊断日志先经过这一层。
- [ ] `credential_provider` 只处理 COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC 客户端和放行凭证打包；不得发网络请求、读取复杂业务文件或长期保存敏感状态。
- [ ] `remote_auth` 只实现 helper 后台能力：命名管道服务、请求路由、session 内存状态、配置聚合、API 调用、审计日志和 Windows session notification；不得承载 Tauri/WebView GUI。
- [ ] `auth_api` 只封装真实服务端 API、请求/响应结构、超时和错误映射；不得读取 CP 状态或注册表。
- [ ] `register_tool` 只做安装、卸载、状态查询、health、应急禁用和管理员配置导入/导出；不得实现登录时业务判断。
- [ ] 后续 Tauri 管理 GUI 必须独立，只通过 `register_tool` 能力或受控 helper 管理 IPC 操作配置和状态，不进入登录链路。

## Credential Provider 分层

- [ ] `dll.rs` 只处理 DLL 导出入口，如 `DllGetClassObject`、`DllCanUnloadNow`。
- [ ] `class_factory.rs` 只处理 COM 类工厂和 CLSID 创建分发。
- [ ] `provider.rs` 只处理 `ICredentialProvider` 生命周期、场景设置、Credential 枚举和 `SetSerialization`。
- [ ] `credential.rs` 只处理单个 Tile 字段值、交互、状态刷新和 `GetSerialization`。
- [ ] `fields.rs` 只处理字段 ID、字段描述符和稳定 UI 字段顺序。
- [ ] `serialization.rs` 只处理 RDP/NLA 解包、Kerberos interactive/unlock packed buffer 构造和敏感字节内存管理。
- [ ] `filter.rs` 只处理 Credential Provider Filter 和 `UpdateRemoteCredential`。
- [ ] `session.rs` 只封装 RDS session 查询和断开。
- [ ] `timeout.rs` 只处理 MFA 超时、缺失 serialization 等待窗口和断开定时器。
- [ ] `diagnostics.rs` 只处理 CP 轻量脱敏诊断日志；写入失败必须吞掉，不能影响 LogonUI。
- [ ] `state.rs` 只保存 Provider/Credential 共享轻量内存状态，不放复杂业务策略或网络结果。

## Helper 分层

- [ ] 命名管道服务只负责监听、读取一条请求、写回一条响应和连接生命周期。
- [ ] 请求路由只分发 `auth_ipc::IpcRequest` 到 handler，不直接做文件解析或 HTTP 细节。
- [ ] session 状态只维护 session id、认证状态、时间戳、TTL 和最近事件；不得保存用户名、手机号、密码、验证码、token 或 serialization。
- [ ] session notification 只把 lock、unlock、disconnect、logoff、session end 转成 session 状态更新。
- [ ] 策略快照聚合配置、手机号来源和超时策略，只输出 CP 可渲染的脱敏快照。
- [ ] 手机号文件只在 helper 内读取，读取后立刻校验和脱敏，真实手机号只短暂用于发送短信。
- [ ] API client 只通过 `auth_api` 调用真实服务端，不把 HTTP 细节泄漏到 CP 或 IPC 外层。
- [ ] 审计日志只记录脱敏上下文和结果码，不记录敏感输入。

## 配置

- [ ] 注册表只保存 Windows 集成必需的最小引导项。
- [ ] 业务配置统一进入加密配置文件，运行期不读取长期明文 TOML。
- [ ] 明文 TOML 只允许通过 `register_tool config export/import` 或后续管理 GUI 显式维护流程短暂出现。
- [ ] `auth_config::schema` 只定义结构、默认值和归一化；不得打开文件、读注册表或发网络请求。
- [ ] 远程配置缓存、手机号文件迁移结果、旧配置迁移结果等业务配置文件必须加密落盘。

## IPC 与敏感数据

- [ ] `auth_ipc` 协议只包含可序列化、可测试、非敏感的请求和响应类型。
- [ ] CP 只能通过短超时 IPC 调用 helper；helper 异常、超时或非法响应必须 fail closed。
- [ ] IPC 响应不得包含完整手机号、密码、验证码、token、用户名或 RDP serialization。
- [ ] 命名管道 transport 只放在 helper/CP 对应 IO 层，不写进协议 crate。
- [ ] 敏感数据不得进入日志、错误文本、IPC 响应或配置快照。

## 依赖方向

- [ ] 允许：`credential_provider -> auth_core / auth_config / auth_ipc / auth_logging`。
- [ ] 允许：`remote_auth -> auth_core / auth_config / auth_ipc / auth_api / auth_logging`。
- [ ] 允许：`register_tool -> auth_config / auth_logging`。
- [ ] 允许：`auth_config -> auth_core`，`auth_ipc -> auth_core`，`auth_api -> auth_core`。
- [ ] 允许：`auth_logging -> 标准库 + tracing 生态`，`auth_core -> 标准库 + serde`。
- [ ] 禁止：`auth_core` 依赖本地系统、网络、配置、IPC 或 Windows crate。
- [ ] 禁止：`auth_config` 依赖 `credential_provider`、`remote_auth` 或 `auth_api`。
- [ ] 禁止：`auth_ipc` 依赖命名管道实现或 helper 状态实现。
- [ ] 禁止：`credential_provider` 依赖 `auth_api` 发起网络请求。
- [ ] 禁止：Tauri 管理 GUI 被 `credential_provider` 或核心 helper 作为运行依赖。

## 测试与文档

- [ ] 新增功能至少有对应单元测试；需要 VM/实机验证的，补测试文档或任务清单。
- [ ] Credential Provider 和 Filter 相关功能必须在 Windows VM 快照环境验证。
- [ ] 未确认卸载和恢复流程前，不允许在主力机器上隐藏系统默认 Credential Provider。
- [ ] 每个任务收尾时判断是否影响 `docs`。
- [ ] 代码行为、安装步骤、测试方法、配置项、注册表路径、架构边界、恢复流程或已知限制变化时，同步更新对应文档。
- [ ] 如果无需文档更新，在收尾说明“已检查文档，无需变更”。

## 提交前本地检查

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --workspace`
- [ ] `cargo test --workspace`
- [ ] 可选运行：`powershell -ExecutionPolicy Bypass -File scripts/check.ps1`
