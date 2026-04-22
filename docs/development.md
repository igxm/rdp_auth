# 开发规范

本规范是后续开发的硬约束。所有新增代码、文档和配置变更都要按这里的边界执行；如果某个任务确实需要突破边界，必须先在设计或任务清单中说明原因、风险和回滚方式。

## Git 要求

- 每次有效代码、文档、配置变更都必须提交到 git。
- 提交前必须确认 `git status --short` 没有遗漏。
- 提交信息使用简短前缀，例如 `docs:`、`feat:`、`fix:`、`test:`。

## 中文注释要求

- 所有新增代码必须包含必要中文注释。
- 注释重点解释维护难点：Windows COM 生命周期、引用计数、凭证序列化、命名管道、安全边界、失败策略。
- 避免只重复代码表面含义，例如“设置变量值”这类注释没有维护价值。

## 代码分层要求

- 代码必须按功能和业务职责分层，不允许把 COM 导出、类工厂、Provider、Credential、字段定义、凭证序列化、IPC、配置读取、API 调用、日志和策略判断长期堆在同一个文件。
- 单个文件只承载一个清晰职责；当文件同时处理两个以上长期概念时，必须拆分模块。
- 新增抽象必须服务于可维护性、测试或安全边界，不为了“看起来分层”制造空壳；但一旦模块职责稳定，就应及时拆文件。
- 分层不是只按文件名拆开，而是要保证依赖方向清楚、敏感数据不跨层乱传、测试可以在低层独立运行。

### Crate 职责边界

- `auth_core`：只放纯业务类型和纯函数，例如认证方式、状态机、手机号校验和脱敏。不得依赖 Windows、注册表、文件系统、网络、IPC 或配置文件。
- `auth_config`：只负责最小注册表引导项、加密配置文件读写、TOML schema、默认值归一化和旧配置迁移。不得发网络请求，不得读取真实手机号文件，不得承担 helper 运行状态。
- `auth_ipc`：只定义 CP 与 helper 的协议类型、JSON 编解码和非敏感 payload。不得实现命名管道 IO、Windows session notification 或业务 API。
- `credential_provider`：只处理 Windows Credential Provider COM 生命周期、LogonUI UI、RDP inbound serialization、短超时 helper IPC 客户端和放行凭证打包。不得发网络请求，不得读取复杂业务文件，不得长期保存敏感状态。
- `remote_auth`：只实现本地 helper 的后台能力，包括命名管道服务、请求路由、session 内存状态、配置聚合、API 调用、审计日志和 Windows session notification。不得承载 Tauri/WebView GUI。
- `auth_api`：只封装真实服务端 API、请求/响应结构、超时和错误映射。不得读取 CP 状态或注册表。
- `register_tool`：只做安装、卸载、状态查询、health、应急禁用和管理员配置导入/导出。不得实现登录时业务判断。
- 后续 Tauri 管理 GUI 必须作为独立应用或独立 crate，只通过 `register_tool` 能力或受控 helper 管理 IPC 操作配置和状态，不得进入登录链路。

### Credential Provider 分层

- `dll.rs`：DLL 导出入口，只处理 `DllGetClassObject`、`DllCanUnloadNow` 之类 COM 边界。
- `class_factory.rs`：COM 类工厂和 CLSID 到对象的创建分发。
- `provider.rs`：`ICredentialProvider` 生命周期、场景设置、Credential 枚举和 `SetSerialization` 接收。
- `credential.rs`：单个 Tile 的字段值、用户交互、状态刷新和 `GetSerialization`。
- `fields.rs`：字段 ID、字段描述符和稳定 UI 字段顺序。
- `serialization.rs`：RDP/NLA inbound buffer 解包、Kerberos interactive/unlock packed buffer 构造、敏感字节内存管理。
- `filter.rs`：Credential Provider Filter 和 `UpdateRemoteCredential` 相关逻辑。
- `session.rs`：RDS session 查询和断开封装。
- `timeout.rs`：MFA 超时、缺失 serialization 等待窗口和断开定时器。
- `diagnostics.rs`：CP 内轻量脱敏诊断日志。写入失败必须被吞掉，不能影响 LogonUI。
- `state.rs`：Provider/Credential 共享的轻量内存状态，不放复杂业务策略和网络结果。

### Helper 分层

- 命名管道服务：只负责监听、读取一条请求、写回一条响应和连接生命周期。
- 请求路由：把 `auth_ipc::IpcRequest` 分发到对应业务 handler，不直接做文件解析或 HTTP 细节。
- session 状态：只维护内存态 session id、认证状态、时间戳、TTL 和最近事件；不得保存用户名、手机号、密码、验证码、token 或 serialization。
- session notification：只把 lock、unlock、disconnect、logoff、session end 转换为 session 状态更新。
- 策略快照：聚合本地加密配置、远程配置、手机号来源和超时策略，输出 CP 可渲染的脱敏快照。
- 手机号文件读取：只在 helper 内完成，读取后立刻校验和脱敏，真实手机号只短暂用于发送短信。
- API client：只通过 `auth_api` 调用真实服务端，不把 HTTP 细节泄漏到 CP 或 IPC 协议外层。
- 审计日志：只记录脱敏上下文和结果码，不记录敏感输入。

### 配置分层

- 注册表只保存 Windows 集成必需的最小引导项：COM/Filter 注册、DLL 路径、helper 路径、配置文件路径、机器码、RDP/本地 MFA 策略和应急禁用开关。
- 业务配置统一进入加密配置文件，运行期不读取长期明文 TOML。
- 明文 TOML 只允许通过 `register_tool config export/import` 或后续管理 GUI 的显式维护流程短暂出现。
- `auth_config::schema` 只定义结构、默认值和归一化；不得打开文件、读注册表或发网络请求。
- 远程配置缓存、手机号文件迁移结果、旧版配置迁移结果等业务配置文件都必须加密落盘。

### IPC 分层

- `auth_ipc` 协议只包含可序列化、可测试、非敏感的请求和响应类型。
- CP 只能通过短超时 IPC 调用 helper，helper 异常、超时或返回非法响应时必须 fail closed。
- IPC 响应不得包含完整手机号、密码、验证码、token、用户名或 RDP serialization。
- 命名管道 transport 只放在 helper/CP 对应 IO 层，不写进协议 crate。

### 依赖方向

允许的主要依赖方向：

```text
credential_provider -> auth_core / auth_config / auth_ipc
remote_auth         -> auth_core / auth_config / auth_ipc / auth_api
register_tool      -> auth_config
auth_config        -> auth_core
auth_ipc           -> auth_core
auth_api           -> auth_core
auth_core          -> 标准库 + serde
```

禁止的依赖方向：

- `auth_core` 依赖任何本地系统、网络、配置、IPC 或 Windows crate。
- `auth_config` 依赖 `credential_provider`、`remote_auth` 或 `auth_api`。
- `auth_ipc` 依赖命名管道实现或 helper 状态实现。
- `credential_provider` 依赖 `auth_api` 发起网络请求。
- Tauri 管理 GUI 被 `credential_provider` 或核心 helper 作为运行依赖。

### 分层检查清单

提交前必须自查：

- 新代码是否能用一句话说明所在模块职责。
- 新文件是否只处理一个长期概念。
- 敏感数据是否只留在必要层，且没有进入日志、错误文本、IPC 响应或配置快照。
- CP 中是否只做短小、可失败、可回退的操作。
- helper 中是否把 IO、路由、业务策略、API、审计分开。
- 配置 schema、文件 IO、注册表读取、加密解密是否没有混在同一个大函数里。
- 新增功能是否至少有对应单元测试；需要 VM/实机的，是否补了测试文档或任务清单。

## 文档同步要求

- 每完成一个任务，都必须判断本次变更是否影响 `docs` 中的对应文档。
- 如果代码行为、安装步骤、测试方法、配置项、注册表路径、架构边界、恢复流程或已知限制发生变化，必须同步更新对应文档。
- 如果没有需要更新的文档，应在任务收尾时明确说明已经检查过文档，无需变更。
- 文档更新应跟随同一个任务提交，不要把代码变更和必要文档长期拆开。

## 本地检查

提交前至少执行：

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

也可以运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

## VM 测试要求

Credential Provider 和 Filter 相关功能必须在 Windows VM 快照环境验证。未确认卸载和恢复流程前，不允许在主力机器上隐藏系统默认 Credential Provider。
