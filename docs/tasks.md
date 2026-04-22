# RDP 登录后二次认证任务清单

## 项目约束

- 所有后续代码、文档、配置变更都必须提交到 git，禁止留下未提交的有效改动。
- 后续开发必须遵守 `docs/development.md`，尤其是功能/业务分层、依赖方向、安全边界和提交前检查清单。
- 所有新增代码必须包含必要的中文注释，重点解释 Windows COM、Credential Provider 生命周期、凭证序列化、IPC、安全边界等后期维护难点。
- 中文注释应解释“为什么这样做”和“此处有什么坑”，避免只重复代码表面含义。
- 代码必须按功能或逻辑分层，不允许把 COM 导出、类工厂、Provider、Credential、字段定义、凭证序列化、IPC、配置读取、API 调用等长期堆在同一个文件。
- Credential Provider DLL 只做 RDP 凭证接收、二次认证 UI、调用本地 helper、认证通过后转交可由 LogonUI/LSA 消费的凭证序列化数据。
- 网络请求、注册表读取、业务审计日志、策略判断都放到本地 helper，避免 LogonUI 进程被阻塞或拖垮；Credential Provider DLL 只允许写入轻量脱敏诊断日志，且日志失败不能影响登录流程。
- 核心 helper 必须保持无 UI、可后台运行、可短超时响应 IPC；后续如引入 Tauri，只作为独立管理员配置 GUI，不作为 Credential Provider 登录链路或 helper 核心进程的运行依赖。
- 第一阶段不隐藏系统默认 Credential Provider，确认 RDP pass-through 链路稳定后再实现过滤器，降低锁死测试机风险。

## 当前优先级

1. 先用 VM 验证现有 RDP pass-through 主链路、缺失 serialization 断开保护、MFA 超时断开和短信倒计时 UI 刷新，确认不会误断首次登录；当前任务目标暂不考虑 Windows Server 2008 R2 兼容。
2. 再把超时、缺失 serialization 等待窗口、短信重新发送时间、helper IPC 超时、session 状态 TTL 等迁移到统一 TOML 配置，并让 `register_tool health` 能显示当前生效值。
3. 然后实现 helper / IPC 的 mock 服务和 helper 内存态 session 跟踪，把 CP 内的 mock 逻辑逐步迁移到 helper，保持 Credential Provider DLL 轻量。
4. 在 helper/IPC 稳定之后接入真实 API、远程配置、手机号文件、审计日志和公网/内网 IP 采集。
5. Tauri 管理 GUI 只在核心 helper、加密配置和 `register_tool` 导入/导出能力稳定后开发，用于管理员查看 health、编辑配置和触发维护命令，不进入登录安全链路。
6. 最后接入微信扫码等扩展认证方式；该阶段不应阻塞 RDP 主链路和锁屏断开问题的收敛。

## 任务可行性分级

- **A级：已完成或只需复测确认。** Workspace 骨架、Credential Provider 加载、RDP inbound serialization 接收、Kerberos interactive/unlock 重新打包、mock MFA、MFA 超时断开、缺失 serialization 快速断开、短信按钮倒计时刷新等已经有实现记录，后续重点是 VM 回归和日志补齐。
- **B级：可直接开发，风险较低。** 统一 TOML 配置、配置默认值、`register_tool health` 展示、`auth_core` 手机号校验、日志/错误处理依赖、配置解析单元测试、文档更新等不依赖 Windows 登录链路，可先在普通进程和单元测试里稳定。
- **C级：依赖 helper/IPC 前置。** Windows session notification、helper 内存态 `SessionAuthState`、锁屏后立即断开策略、真实短信/二次密码 API、手机号文件读取、远程配置、审计上下文、公网/内网 IP 采集都应放在 helper 内完成；在 helper mock 服务可用前，Credential Provider 不应直接承接这些复杂逻辑。Tauri 管理 GUI 也属于该级别的后置任务，必须通过 helper 或 register_tool 管理接口工作，不能反向成为 helper 的前置依赖。
- **D级：高风险，必须 VM 验证后定版。** Credential Provider Filter 隐藏默认 Provider、`CPUS_LOGON` 与 `CPUS_UNLOCK_WORKSTATION` 差异、RDP/NLA serialization 慢到窗口、跨进程 session 状态判断、LogonUI 字段刷新线程模型等都属于系统行为相关任务，不能只靠代码审查判断可行；Windows Server 2008 R2 兼容暂不纳入当前目标。
- **暂缓项。** 真实 API、微信扫码、远程配置自动更新、复杂审计上报、Tauri 管理 GUI 美化和自动更新在 RDP 主链路、helper/IPC 和 VM 兼容矩阵稳定前不作为当前收敛目标，避免把问题定位范围扩大。

## 配置与文件读取边界

- [x] 明确边界：Credential Provider DLL 不直接读取手机号文件、远程配置缓存、`reginfo.ini` 或复杂策略文件，避免 LogonUI 进程被磁盘 IO、权限、杀毒软件或配置解析错误拖垮。
- [x] 明确边界：Credential Provider DLL 只消费 helper 通过 IPC 返回的策略快照，例如可用认证方式、手机号显示值、手机号是否可编辑、超时时间和错误提示。
- [ ] helper 负责读取和校验手机号文件、远程配置缓存、`reginfo.ini`、公网 IP endpoint、认证方式开关和超时策略，并把结果转换为 CP 可直接渲染的脱敏策略。
- [x] helper 下发给 CP 的手机号策略只允许包含脱敏展示值和是否可编辑标记；真实手机号仅在 helper 内存中用于发送短信请求，不回传给 CP 日志。
- [ ] CP 与 helper IPC 增加 `get_policy_snapshot` 或等效请求，CP 初始化和刷新 UI 时通过该请求获取认证方式、手机号来源、脱敏手机号、字段可编辑状态和超时配置。

## 日志与错误处理技术选型

- [x] 调研 Rust 日志库：`tracing` 是结构化、事件驱动诊断框架，`tracing-appender` 支持滚动文件和非阻塞写入；`tklog` 提供轻量同步/异步文件日志和切割能力，但生态集成、span 上下文和 crate 互操作性弱于 `tracing`。
- [x] 确定日志主方案：后续统一采用 `tracing` + `tracing-subscriber` + `tracing-appender`，用于 helper、register_tool、auth_api 等普通进程；如需兼容第三方 `log` 生态，再接入 `tracing-log` 或 `tracing-subscriber` 的 log 兼容层。
- [x] 确定 Credential Provider DLL 日志边界：LogonUI 进程内仍保持当前轻量诊断写入策略，后续如接入 `tracing`，必须保证初始化幂等、写入失败被吞掉、不能启动不可控后台线程阻塞登录，且不得记录用户名、密码、验证码、token 或原始 serialization 字节。
- [x] 调研 Rust 错误处理库：`thiserror` 适合为库 crate 定义可匹配、可测试的结构化错误枚举；`anyhow` 适合二进制入口和任务编排层快速附加上下文并向上返回。
- [x] 确定错误处理主方案：`auth_config`、`auth_ipc`、`auth_api`、`credential_provider` 等库 crate 使用 `thiserror` 定义领域错误；`remote_auth`、`register_tool` 等 bin crate 使用 `anyhow::Result` 汇总错误并补充人类可读上下文。
- [x] 在 workspace 统一增加日志与错误处理依赖：`tracing`、`tracing-subscriber`、`tracing-appender`、`thiserror`、`anyhow`；按 crate 职责选择性引用，避免 Credential Provider DLL 引入不必要运行时负担。
- [x] 新增 helper 统一诊断日志模块：定义日志目录、文件名、按天轮转、非阻塞 guard 生命周期、脱敏字段约定和初始化幂等策略；业务审计日志后续单独实现。
- [ ] 新增统一错误模块：各库 crate 定义 `Error` / `Result<T>` 类型别名，错误枚举必须包含安全的 Display 文案和可记录的诊断上下文，禁止把敏感输入直接放入错误消息。

## 总体目标

实现一个全 Rust 维护的 RDP 登录后二次认证方案：

1. RDP 客户端完成基础 Windows 凭证输入或 NLA 认证。
2. 目标机 LogonUI 加载 Rust Credential Provider。
3. Credential Provider 通过 `SetSerialization` 接收 RDP 传入的原始凭证序列化数据。
4. Credential Provider 展示二次认证界面。
5. 用户完成短信验证码、二次密码或后续微信扫码认证。
6. 二次认证通过后，`GetSerialization` 将 RDP 凭证重新打包成 LogonUI/LSA 可消费的 Negotiate 凭证。
7. Winlogon / LSA 继续完成真正的 Windows 登录。

## RDP 场景判定与断开策略

- [x] 确定判定原则：Credential Provider 不监听“用户按下 Win+L”这类瞬时事件，只处理 LogonUI 请求的认证场景。
- [x] `SetUsageScenario` 只作为场景上下文：同时支持 `CPUS_LOGON` 和 `CPUS_UNLOCK_WORKSTATION`，不能假设锁屏解锁一定只收到 `CPUS_UNLOCK_WORKSTATION`。
- [x] RDP 来源以当前会话协议判断为主：通过 Remote Desktop Services 查询当前 session 是否为 RDP，而不是单独依赖 usage scenario。
- [x] 放行能力以 inbound serialization 为准：只有收到 `SetSerialization` 并解包出一次 Windows 凭证后，MFA 通过才允许重新打包并交给 LogonUI/LSA。
- [x] 无 inbound serialization 的 RDP 孤立 MFA 入口必须断开：当前架构不保存首次登录密码，也不实现一次凭证采集，所以不能让用户停留在无法放行的 MFA Tile。
- [ ] 增加按 session 区分的轻量历史状态标记：`ReportResult status=0` 后记录当前 session 曾成功完成 RDP MFA，用于区分“首次登录 serialization 慢到”和“已登录会话锁屏/注销后返回 LogonUI”。
- [ ] 历史状态标记的目标实现放在 helper 内存中维护，不写注册表、不写状态文件；Credential Provider 只通过短超时 IPC 查询和更新。
- [ ] helper 通过 Windows session notification 监听 session lock、unlock、disconnect、logoff 等事件，维护 session 内存状态并及时清理，Credential Provider 不直接监听 Win+L 事件。
- [ ] 如果 helper 不可用或 IPC 超时，Credential Provider 不得因此放行；回退到现有缺失 serialization 等待窗口和 fail closed 断开策略。
- [ ] 缺失 serialization 保护按上下文使用不同等待窗口：已有成功会话返回 LogonUI 时使用短窗口，疑似首次登录时使用较宽松窗口，避免误断正常 RDP 登录。
- [x] 将缺失 serialization 等待窗口改为统一配置项，例如 `mfa.missing_serialization_grace_seconds`，缺失或非法时使用安全默认值。
- [ ] 日志补齐场景链路：记录 `SetUsageScenario`、`Filter`、`UpdateRemoteCredential`、`GetCredentialCount`、`GetCredentialAt`、`SetSerialization`、`MissingSerialization`、`MfaTimeout`、`GetSerialization`、`ReportResult` 的关键脱敏字段。
- [ ] VM 验证 Windows 10/Server 版本上 `CPUS_LOGON` 与 `CPUS_UNLOCK_WORKSTATION` 的实际调用差异，避免把锁屏逻辑写死到单一 usage scenario。

## Windows Server 2008 R2 兼容方案

当前任务目标不考虑 Windows Server 2008 R2 兼容，也不把 2008 R2 作为当前开发、测试、验收或阻塞项。以下内容仅作为未来如需扩展兼容时的参考，不在当前阶段执行。该系统属于 NT 6.1 时代，Credential Provider、RDP/NLA、RDS 会话 API 基础能力存在，但现代 Rust/MSVC 运行时、Windows API set、TLS/Schannel、依赖 crate 的最低系统版本都可能成为真实阻断点。

- [ ] 定义支持级别：主线优先支持当前开发 VM 和较新的 Windows Server；Windows Server 2008 R2 初始标记为“待验证/实验性兼容”，只有专门 VM 测试全部通过后才能写入安装文档的支持矩阵。
- [ ] 准备 Windows Server 2008 R2 SP1 64 位 VM，记录系统版本、补丁状态、是否启用 RDP/NLA、是否启用 TLS 1.2、是否安装 VC++ 运行时，并建立可回滚快照。
- [ ] 固定兼容构建环境：确认 Rust toolchain、`windows` crate、MSVC/Windows SDK、链接选项和目标三元组对 Windows 7/Server 2008 R2 仍可运行；必要时增加 `legacy_2008r2` feature 或单独构建配置。
- [ ] 检查 DLL/EXE 导入表：使用 `dumpbin /imports`、Dependencies 或同类工具确认 `credential_provider.dll`、`remote_auth.exe`、`register_tool.exe` 没有静态导入 Server 2008 R2 不存在的 API set 或新系统 DLL；发现问题时改为动态加载、降级实现或禁用对应功能。
- [ ] 审计 Credential Provider 相关 API 最低系统要求：`ICredentialProvider`、`ICredentialProviderCredential`、`ICredentialProviderFilter`、`UpdateRemoteCredential`、`CredUnPackAuthenticationBufferW`、`CredPackAuthenticationBufferW`、`LsaLookupAuthenticationPackage`、COM 注册表项和 LogonUI 调用顺序都必须在 2008 R2 VM 中实测。
- [ ] 审计 RDS/session API 最低系统要求：`WTSGetActiveConsoleSessionId`、`WTSQuerySessionInformationW`、`WTSDisconnectSession`、session lock/unlock/logoff/disconnect notification 在 2008 R2 上的可用性和事件时序必须实测；如果 helper 无法稳定收到锁屏事件，则 2008 R2 只能使用缺失 serialization fail closed 兜底策略。
- [ ] 审计网络与 TLS 能力：真实短信、远程配置、公网 IP 查询如果依赖 HTTPS，必须确认 2008 R2 的 Schannel/TLS 1.2 补丁和系统策略；如果不可控，应在 helper 层提供明确错误和安装检查，不让 Credential Provider 直接承担网络失败。
- [ ] 审计运行时部署：优先评估静态链接 CRT 或随安装包部署匹配 VC++ 运行时；安装工具应在 `health` 中显示运行时、配置文件、helper 路径、服务状态和关键 DLL 导入检查结果。
- [ ] 增加兼容降级开关：如 2008 R2 上 `ICredentialProviderFilter` 或 UI 刷新不稳定，允许关闭隐藏默认 Provider、使用更保守的字段刷新、禁用非必要动态 UI；这些开关统一进入 TOML 配置，注册表只保存必要引导信息。
- [ ] 增加 2008 R2 VM 冒烟用例：注册/卸载、LogonUI 正常加载、控制台登录不被锁死、RDP/NLA 首次登录收到 `SetSerialization`、mock MFA 成功进入桌面、验证码错误不会放行、取消/MFA 超时会断开 RDP、锁屏/注销返回 LogonUI 时无 serialization 会快速断开、短信按钮倒计时会刷新。
- [ ] 增加 2008 R2 helper 用例：helper 服务启动、命名管道 IPC、`mark_session_authenticated`、`has_authenticated_session`、`clear_session_state`、session notification、TTL 清理、helper 不可用时 CP fail closed。
- [ ] 明确不支持判定：如果 2008 R2 上无法可靠收到 RDP inbound serialization、`UpdateRemoteCredential`/Filter 链路不稳定且无法降级，或 Kerberos interactive/unlock serialization 无法被 LSA 接受，则该版本不支持当前 RDP pass-through MFA 架构，只保留文档说明，不继续投入真实 API 和微信扫码兼容。

## 阶段 0：仓库基线与工程规范

- [x] 将现有单 crate 项目调整为 workspace 结构。
- [x] 保留 `docs/agent.md` 和 `docs/login.png` 作为需求输入资料。
- [x] 新增架构文档，说明 RDP pass-through MFA 的边界。
- [x] 新增开发规范文档，明确 git 提交、中文注释、安全测试和 VM 测试要求。
- [x] 新增最小 CI 或本地检查脚本，至少执行 `cargo fmt`、`cargo check`、后续单元测试。
- [x] 建立提交规范，例如 `docs: ...`、`feat: ...`、`fix: ...`。

## 阶段 1：Rust Workspace 骨架

- [x] 创建 `crates/credential_provider`，类型为 `cdylib`，用于实现 Windows Credential Provider COM DLL。
- [x] 创建 `crates/remote_auth`，类型为 `bin`，用于本地二次认证 helper。
- [x] 创建 `crates/auth_core`，用于保存认证方式、请求响应、错误码、状态机等纯业务类型。
- [x] 创建 `crates/auth_ipc`，用于定义 Credential Provider 与 helper 之间的命名管道协议。
- [x] 创建 `crates/auth_config`，用于读取注册表和配置文件。
- [x] 创建 `crates/auth_api`，用于封装服务端 API 调用。
- [x] 创建 `crates/register_tool`，用于安装、注册、卸载 Credential Provider。
- [x] 所有 crate 提供中文模块级注释，说明职责边界和维护注意事项。

## 阶段 2：Credential Provider DLL 最小加载

- [x] 在 `credential_provider` 中配置 `crate-type = ["cdylib"]`。
- [x] 导出 `DllGetClassObject`。
- [x] 导出 `DllCanUnloadNow`。
- [x] 实现最小 `IClassFactory`。
- [x] 实现最小 `ICredentialProvider`。
- [x] 支持 `CPUS_LOGON` 和 `CPUS_UNLOCK_WORKSTATION`。
- [x] 暂时拒绝 `CPUS_CHANGE_PASSWORD`、`CPUS_CREDUI`、`CPUS_PLAP`。
- [x] 实现一个最小 Tile，确认 LogonUI 能枚举并显示。（VM 已验证）
- [x] 在代码中用中文注释解释 COM 引用计数、接口查询、对象生命周期。
- [x] 按职责拆分阶段 2 代码，避免 DLL 入口、类工厂、Provider、Credential、字段和内存分配长期堆在同一个文件。

## 阶段 3：RDP 原始凭证接收与重新打包转交

- [x] 实现 `ICredentialProvider::SetSerialization`。
- [x] 深拷贝保存 `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`。
- [x] 保存字段包括 `ulAuthenticationPackage`、`clsidCredentialProvider`、`cbSerialization`、`rgbSerialization`。
- [x] 实现 `ICredentialProviderCredential::GetSerialization`。
- [x] 在早期 pass-through 阶段曾验证原始凭证原样返回链路；当前已改为解包后重新打包。
- [x] 如果没有收到 inbound serialization，显示明确错误并拒绝提交。
- [x] 使用 RDP 测试：mstsc 输入凭证后，目标机 CP 能收到 serialization 并成功继续登录。
- [x] 用中文注释说明为什么不能自己调用 `LsaLogonUser`，以及为什么交给 Winlogon 处理。
- [x] 使用 `CredUnPackAuthenticationBufferW` 从 RDP/NLA inbound authentication buffer 中解出 Windows 一次凭证，只在内存中短暂保存，不写日志。
- [x] 曾验证 `CredPackAuthenticationBufferW` 重新打包路线：API 能成功生成 buffer，但 VM 日志仍返回 `STATUS_LOGON_FAILURE / STATUS_INTERNAL_ERROR`，因此不再作为最终返回格式。
- [x] 对照 `FaceWinUnlock-Tauri/Server` 的 Credential Provider 实现，确认 `CredPackAuthenticationBufferW` + `LsaLookupAuthenticationPackage("Negotiate")` 路线可作为优先验证方案。
- [x] 修正 `Negotiate` authentication package 查询的 `LSA_STRING` 构造，按 Windows API 习惯保留 NUL 结尾容量，并补充查询结果诊断日志。
- [x] 增强 RDP 凭证解包/重打包脱敏日志：记录 LSA 查询状态、CredUnPack/CredPack 返回结果、长度、package id 和用户名形态标记，不记录用户名、密码或 serialization 字节。
- [x] MFA 通过后改为构造 `KERB_INTERACTIVE_UNLOCK_LOGON` packed buffer：`UNICODE_STRING.Buffer` 保存相对结构起点的字节偏移，`CPUS_LOGON` 使用 `KerbInteractiveLogon`，`CPUS_UNLOCK_WORKSTATION` 使用 `KerbWorkstationUnlockLogon`。
- [x] 使用 VM 复测 RDP + NLA + mock MFA，新 Kerberos packed serialization 已进入桌面，日志确认 `ReportResult status=0x00000000 sub_status=0x00000000`。

## 阶段 4：二次认证 UI 状态机

- [x] 设计字段枚举，例如 Logo、认证方式、手机号、验证码、发送短信、二次密码、登录、退出、状态文本。（当前字段为标题、认证方式、手机号、短信验证码、发送验证码、二次密码、微信预留、登录、取消、状态文本）
- [x] 实现手机认证和二次密码认证两个 Tab 或等效切换控件。（当前用组合框切换）
- [x] 微信扫码字段预留，但第一版不接入真实逻辑。
- [x] 根据配置文件中的认证方式开关动态生成认证方式列表，关闭的方法不显示在组合框中。
- [x] 当只启用一种认证方式时，可默认选中该方式，并评估是否隐藏认证方式组合框。
- [x] 当所有认证方式都被关闭时，恢复默认认证方式配置，不能因为配置错误绕过二次认证。
- [x] 实现字段显示 / 隐藏逻辑。
- [x] 认证方式切换后，通过 `ICredentialProviderCredentialEvents` 主动通知 LogonUI 刷新字段，避免手机号/验证码/二次密码 UI 不同步。
- [x] 实现输入框取值和状态文本刷新。
- [x] 实现按钮点击回调。
- [ ] 手机号认证支持两种来源：helper 从配置/文件读取手机号、用户手动输入手机号；来源策略由 helper 统一下发，Credential Provider 只负责展示和轻量校验。
- [ ] helper 读取手机号模式：手机号字段显示 helper 返回的脱敏格式，例如 `138****8888`，并设置为不可编辑；Credential Provider 不接触真实手机号。
- [ ] 手动输入手机号模式：手机号字段允许编辑，点击发送验证码前必须通过手机号正则校验，默认规则为 `^1[3-9]\d{9}$`。
- [ ] 手机号不合法时不允许进入发送短信流程，刷新状态提示为“请输入正确的手机号”或“手机号配置无效，请联系管理员”。
- [x] 删除底部重复状态区域，避免登录按钮下方再出现一块“第二部分”内容。
- [x] 发送验证码后立即把按钮切换为禁用态，并显示 `重新发送(60)`。
- [x] 实现短信验证码重新发送倒计时递减，并在 60 秒后恢复为可点击 `发送验证码`。（当前通过 LogonUI events 只刷新发送短信按钮；后续接入 helper 后可改为 helper 心跳驱动）
- [x] 增加认证超时断开机制：收到 RDP inbound serialization 后启动默认 2 分钟的一次性定时器，超时仍未完成二次认证时自动断开当前 RDP 会话。
- [x] 认证超时断开时间后续改为从统一配置文件读取，缺失时默认 120 秒。
- [x] 设计 `MfaState` 状态机：空闲、发送短信中、等待输入、认证中、成功、失败。
- [x] 使用 mock 数据模拟认证通过情况：手机验证码 `123456`、二次密码 `mock-password`。
- [x] 二次认证未通过时，`GetSerialization` 不返回原始凭证。
- [x] 二次认证通过后，`GetSerialization` 不再返回缓存的 inbound 原始 bytes，而是返回重新打包后的 Negotiate/Kerberos interactive 凭证。
- [x] 修复 mock MFA 通过后仍提示用户名或密码错误：Filter 记录 RDP 原始 Provider CLSID 时同时写入按 session 区分的 handoff 文件，Provider 在 `SetSerialization` 阶段跨进程恢复原始 Provider CLSID；随后解包 RDP inbound buffer 并重新打包为 Kerberos interactive 凭证后放行，VM 日志已验证成功。
- [x] 增加 Credential Provider 脱敏诊断日志：记录 Filter、SetSerialization、mock 验证、GetSerialization、ReportResult 的链路阶段，便于定位 mock MFA 通过后仍无法进入桌面的问题。
- [x] 点击取消按钮时，调用 Remote Desktop Services API 断开当前 RDP 会话。
- [x] 增加 RDP 注销/返回登录界面保护：如果 RDP 场景下没有收到 inbound credential serialization，不允许只显示 MFA 入口，约 1 秒后断开当前 RDP 连接，迫使用户重新发起 RDP/NLA 并重新提供原始凭证。
- [x] 中文注释解释 LogonUI UI 更新机制和状态切换原因。

## 阶段 5：本地 helper 与 IPC

- [ ] 明确 helper 形态：`remote_auth` 是无 UI 的核心后台进程/服务，负责 IPC、session notification、配置解密、API、审计和内存态 session；不得依赖 Tauri、WebView2 或前端资源才能启动。
- [ ] 明确 GUI 边界：后续 Tauri 仅作为独立管理员配置工具，通过 helper 管理 IPC 或 `register_tool` 能力读写配置和查询状态；Credential Provider 永远不直接调用 Tauri GUI。
- [ ] `remote_auth` 启动命名管道服务。
- [ ] 将 `remote_auth` 设计为可常驻的 helper 进程，后续可由安装工具注册启动路径；启动失败不能阻塞 LogonUI。
- [x] helper 内存中维护 `SessionAuthState`，按 Windows session id 记录是否已成功完成 RDP MFA、最后更新时间、最近一次会话事件和诊断状态码，不保存用户名、密码、验证码、token 或 serialization。
- [ ] helper 使用 Windows session notification 订阅会话事件，至少处理 lock、unlock、disconnect、logoff；事件处理只更新内存状态和脱敏诊断日志。
- [ ] helper 在 logoff、session end、状态过期或显式清理请求时移除对应 session 内存状态，避免 session id 复用导致误判。
- [ ] 定义 session 状态 TTL，超过 TTL 的状态视为无效并清理；TTL 后续从统一配置读取。
- [x] `auth_ipc` 定义 JSON 请求响应协议。
- [x] `auth_ipc` 增加 `mark_session_authenticated` 请求：Credential Provider 在 `ReportResult status=0` 后通知 helper 标记当前 session 已完成 RDP MFA。
- [x] `auth_ipc` 增加 `has_authenticated_session` 请求：Credential Provider 在 RDP 会话无 inbound serialization 时查询 helper，命中则直接走短等待/立即断开策略。
- [x] `auth_ipc` 增加 `clear_session_state` 请求：Credential Provider 或 register_tool 可请求清理指定 session 状态，用于断开、卸载或异常恢复。
- [ ] 所有 session 状态 IPC 必须设置极短超时；helper 不可用、超时或返回非法响应时，Credential Provider 回退到 fail closed 策略，不得放行。
- [x] IPC 响应只返回布尔值、状态码、TTL/时间戳等非敏感信息，不返回用户标识、手机号、密码或原始凭证材料。
- [x] 支持 `get_policy_snapshot` 请求：helper 读取本地配置和必要文件后，返回 CP 可渲染的脱敏策略快照，包括认证方式列表、手机号来源、脱敏手机号、手机号字段是否可编辑和超时配置；远程配置和用户可见提示待后续扩展协议字段。
- [x] 支持 `send_sms` 请求。
- [x] `send_sms` 请求携带手机号来源标记；文件读取手机号模式下 CP 不传真实手机号，helper 使用自己读取并校验过的真实手机号；手动输入模式下 CP 只传用户输入手机号。
- [x] helper 对手机号再次执行格式校验，禁止只依赖 Credential Provider UI 校验；手机号非法时返回可展示错误且不调用真实短信 API。
- [x] helper 实现手机号文件读取和校验：读取 `PhoneFilePath`，校验 `^1[3-9]\d{9}$`，只向 CP 返回脱敏手机号和不可编辑标记，日志不得记录完整手机号。
- [ ] helper 为每次 MFA 请求生成审计上下文 `AuditContext`：包含 request_id、session_id、client_ip、host_public_ip、host_private_ips、host_uuid 和认证方式。
- [ ] helper 采集 RDP 连接用户 IP：优先按当前 Windows session 查询客户端地址；采集失败时填充 `unknown`，并记录脱敏诊断原因。
- [ ] helper 采集本机内网 IP 列表：枚举活动网卡，过滤 loopback、link-local、未启用网卡和明显无效地址，支持多网卡多 IP。
- [ ] helper 获取本机公网 IP：优先调用自家服务端公网 IP 查询接口；失败时填充 `unknown`，默认不阻断短信发送，除非远程策略要求 fail closed。
- [x] helper 返回短信发送成功后，驱动 CP 进入 60 秒重新发送倒计时。（helper 已返回成功响应；CP 通过命名管道接入后使用该响应启动倒计时）
- [x] 支持 `verify_sms` 请求。
- [x] 支持 `verify_second_password` 请求。
- [ ] 支持 `post_login_log` 请求。
- [x] 第一版 helper 先返回 mock 结果，用固定验证码验证主链路。
- [ ] Credential Provider 通过命名管道调用 helper。
- [ ] 增加超时处理，避免 LogonUI 长时间无响应。
- [x] helper 使用 `tracing` 输出结构化诊断日志，记录 helper 启动、请求类型、session、结果和 payload 状态；request_id、耗时和认证方式随审计上下文补齐。
- [x] helper 使用 `anyhow` 作为入口层错误返回，IPC 协议错误使用 `thiserror` 定义可匹配类型；业务错误类型后续随真实 API 接入补齐。
- [ ] 中文注释解释为何 CP DLL 不直接发网络请求。
- [ ] 中文注释解释为何核心 helper 不做 Tauri GUI：登录链路需要服务化、短超时和低依赖，GUI 崩溃或 WebView2 缺失不得影响 RDP MFA fail closed 策略。

## 阶段 6：配置读取

- [x] 确定配置集中化方案，详见 `docs/configuration.md`：本地人工维护配置使用 TOML，远程配置缓存可使用 JSON，注册表只保留最小引导项和应急开关。
- [x] 配置采用单一文件为主，运行期推荐加密路径为 `C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`，TOML 只作为导入/导出的明文交换格式；如服务端下发天然是 JSON，可在远程缓存层保留 JSON 内存格式，但远程缓存落盘也必须加密。
- [ ] 所有业务配置文件必须加密落盘：本地统一配置、远程配置缓存、手机号文件、旧版 `reginfo.ini` 迁移结果和后续新增认证/API 配置都不得以明文作为运行期配置文件。
- [x] 将本地配置长期落盘路径调整为 AES 加密文件，例如 `C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`；TOML 仅作为导入/导出的明文交换格式。
- [x] 配置加密方式改为 AES-256-GCM，文件内容保存 `nonce + ciphertext`，不再使用 envelope。
- [x] 首次安装时根据机器信息生成唯一机器码，写入注册表 `MachineCode`，并使用该机器码派生 AES-256 key。
- [ ] Windows Server 2008 R2 兼容验证暂不纳入当前任务目标；如未来恢复兼容目标，再覆盖机器码生成、注册表写入、AES 加密/解密和重启后读取。
- [ ] 注册表只保留 Windows 集成所必需的机器级信息：Provider/Filter COM 注册、LogonUI 枚举入口、DLL 路径、helper 路径、配置文件路径、`MachineCode`、`DisableMfa` 应急开关和必要的 `EnableRdpMfa` / `EnableConsoleMfa` 登录入口策略；认证方式、API、手机号、超时、审计、远程配置等业务配置不得散落写入注册表。
- [ ] `auth_config` 读取注册表 `SOFTWARE\rdp_auth\config` 中的最小引导项，例如 `ConfigPath`、`HelperPath`、`DisableMfa`、`EnableRdpMfa`、`EnableConsoleMfa`，再读取统一配置文件。
- [x] `auth_config` 按职责拆分模块：`login_policy` 只处理注册表最小引导项，`file_config` 只处理配置路径/文件读写/TOML 解析，`schema` 只处理配置结构和默认值归一化，`legacy` 只保留旧配置迁移占位。
- [x] `auth_config::lib` 仅作为对外 API re-export 层，避免注册表读取、配置 schema、文件 IO、旧版迁移和后续 AES 加密继续堆在单个文件。
- [x] `register_tool install` 初始化统一配置文件，若文件已存在则不覆盖人工修改；注册表只写最小引导项和 Windows 必需注册项。
- [ ] 定义统一配置 schema，至少包含 `[auth_methods]`、`[mfa]`、`[phone]`、`[api]`、`[audit]`、`[remote_config]`、`[logging]` 七组配置，并提供版本字段 `schema_version`。
- [x] 定义认证方式开关配置，例如 `auth_methods.phone_code`、`auth_methods.second_password`、`auth_methods.wechat`，默认启用手机验证码和二次密码，微信在真实接入前默认关闭。
- [x] 定义认证超时配置，例如 `mfa.timeout_seconds`，默认 120 秒，设置过小/非法时恢复默认值。
- [x] 定义缺失 RDP 原始凭证保护配置，例如 `mfa.missing_serialization_grace_seconds`，默认先按 VM 结果确定为 1 到 5 秒之间，设置过小/非法时恢复安全默认值。
- [x] 定义短信重新发送配置，例如 `mfa.sms_resend_seconds`，默认 60 秒；helper/API 接入后优先使用服务端返回的限流时间。
- [x] 定义 RDP 断开策略配置，例如 `mfa.disconnect_when_missing_serialization = true`，应急关闭时必须记录脱敏诊断日志并保持 fail closed，不得绕过 MFA。
- [x] 定义 helper session 状态配置，例如 `mfa.session_state_ttl_seconds`、`mfa.authenticated_session_short_grace_seconds`、`mfa.initial_login_grace_seconds`，用于区分已认证会话返回 LogonUI 和首次登录等待 serialization。
- [x] 定义 helper IPC 超时配置，例如 `mfa.helper_ipc_timeout_ms`，默认应足够短，避免 LogonUI 被 helper 卡住。
- [x] 定义手机号来源配置，例如 `phone.source = "file" | "input"`；默认建议为 `input`，避免文件缺失导致测试环境无法收验证码。
- [x] 定义手机号文件路径配置，例如 `phone.file_path = "C:\\ProgramData\\rdp_auth\\phone.txt"`，仅在 `phone.source = "file"` 时由 helper 读取，Credential Provider 不直接打开该文件。
- [x] `auth_core` 提供手机号校验和脱敏函数：合法手机号按 `138****8888` 格式展示，非法手机号不暴露前后缀。
- [x] `auth_config` 只定义手机号来源、路径、优先级和错误类型；真实手机号文件读取、校验和 fail closed 决策由 helper 执行。
- [ ] 定义公网 IP 查询配置，例如 `api.public_ip_endpoint`、`api.public_ip_timeout_seconds`、`api.require_public_ip_for_sms`，默认公网 IP 获取失败不阻断短信。
- [ ] 定义 IP 审计日志策略，例如 `audit.ip_logging = "full" | "masked" | "off"`，区分诊断日志和审计日志对 IP 字段的记录方式。
- [ ] 定义远程配置缓存路径，例如 `remote_config.cache_path = "C:\\ProgramData\\rdp_auth\\config\\remote_policy.json.enc"`，并定义版本号、更新时间、TTL 和完整性校验字段；远程缓存也必须加密落盘。
- [ ] 支持远程配置下发：helper 启动时拉取配置，按 `remote_config.refresh_seconds` 周期刷新；拉取失败时使用最后一次有效配置，从未成功拉取时使用本地安全默认值。
- [ ] 远程配置不得关闭所有认证方式或绕过 MFA；若下发非法策略，自动回退默认认证方式集合并记录审计告警。
- [x] 支持从统一配置文件读取认证方式开关，并明确优先级：应急注册表开关优先级最高，其次是经完整性校验的远程配置，最后是本地统一配置文件和内置安全默认值。（当前已实现本地统一配置和内置安全默认值；远程配置优先级待 helper 接入后补齐）
- [x] 新增 `AuthMethodPolicy` 或等效结构，统一表达哪些认证方式可展示、可提交。
- [x] 配置中关闭的认证方式必须同时影响 UI 展示和提交校验，避免通过手工构造字段值提交已禁用方式。
- [x] 当配置文件把所有认证方式都关闭时，自动回退到默认认证方式集合，并记录脱敏诊断信息。
- [ ] helper 读取 `hostuuid` 并放入策略快照和审计上下文，Credential Provider 不直接读取。
- [ ] helper 读取 `serveraddr` 并用于 API base URL 或远程配置拉取，Credential Provider 不直接读取。
- [ ] `ClientIp` 不再作为静态配置优先来源；helper 应优先从当前 RDP session 动态采集，配置值仅作为采集失败时的显式 fallback。
- [ ] helper 读取 `r_ip_range`、`r_time_range`、`r_region` 等策略配置并在本地或服务端策略判断中使用，CP 只接收最终允许/拒绝或可展示策略。
- [ ] helper 支持兼容读取旧版 `reginfo.ini`，只作为迁移来源或显式 fallback；成功迁移后写入统一加密配置文件，CP 不直接读取 `reginfo.ini`。
- [x] `auth_config` 增加配置解密层：先读取 AES 加密文件并解密为内存中的 TOML/JSON，再解析为结构化配置；明文只允许短暂存在于内存。
- [x] `auth_config` 对机器码缺失、密文损坏、AES 解密失败分别返回结构化错误，并按 fail closed/安全默认值策略处理。
- [x] `register_tool config export` 导出明文 TOML 供管理员编辑，命令输出必须提示明文敏感和删除临时文件；导出操作需要管理员显式执行。
- [x] `register_tool config import` 读取明文 TOML 后立即加密写回 `.enc` 文件，已有加密配置写入前创建加密备份，不保留明文副本。
- [x] `register_tool health` 显示配置文件是否加密、AES 算法、密文长度、解密是否成功、配置来源和最后修改时间；不得显示配置明文内容。
- [x] 编写 helper / IPC 测试文档，详见 `docs/helper-ipc-test.md`。
- [ ] 配置缺失时返回结构化错误。
- [x] 认证方式配置缺失或非法时使用安全默认值；全部关闭时恢复默认认证方式集合。
- [x] helper 启动时输出脱敏诊断日志。
- [x] 中文注释说明最小注册表引导项、统一配置文件字段意义、缺失字段处理策略和向后兼容迁移规则。

## 阶段 7：真实服务端 API

- [ ] `auth_api` 封装 HTTP client。
- [ ] 实现 `POST /api/host_instance/getSSHLoginCode`。
- [ ] 短信发送 API 请求携带 `host_public_ip`，并可携带 `client_ip`、`host_private_ips`、`host_uuid`、`session_id` 等审计上下文；服务端仍应以请求来源 IP 做可信校验。
- [ ] 实现短信验证码校验接口，若路径未确定则先以配置项方式注入。
- [ ] 实现二次密码校验接口，若路径未确定则先以配置项方式注入。
- [ ] 实现 `POST /api/host_instance/postSSHLoginLog`。
- [ ] 登录日志上报接口携带 client_ip、host_public_ip、host_private_ips、host_uuid、认证方式、认证结果和耗时，失败原因使用诊断码而不是敏感原文。
- [ ] 实现远程配置拉取接口，例如 `GET /api/host_instance/config` 或等效路径，响应包含配置版本、TTL、策略内容和签名/校验字段。
- [ ] 定义统一 API 错误码和用户提示文案。
- [ ] 所有请求设置连接超时和总超时。
- [ ] 所有日志脱敏手机号、验证码、密码、token。
- [ ] `auth_api` 使用 `thiserror` 定义 API 错误类型，区分网络错误、HTTP 状态错误、服务端业务错误、响应解析错误和超时错误。
- [ ] API 调用使用 `tracing` 记录脱敏请求上下文、耗时、HTTP 状态码和服务端错误码，禁止记录 token、验证码、密码和原始响应中的敏感字段。
- [ ] 中文注释说明每个 API 的用途、入参来源和失败策略。

## 阶段 8：微信扫码认证

- [ ] 实现二维码 BMP 获取：`wechat_login_oauth_bmp?host_uuid=...`。
- [ ] helper 将二维码保存到安全可控路径。
- [ ] CP 显示二维码图片字段。
- [ ] 实现扫码状态轮询或回调查询。
- [ ] 支持二维码刷新。
- [ ] 支持超时、失败、取消状态。
- [ ] 微信认证通过后复用同一 `MfaState::Success` 放行路径。
- [ ] 中文注释解释二维码文件生命周期和刷新策略。

## 阶段 9：防绕过 Credential Provider Filter

- [x] 创建 `credential_provider_filter` crate。（当前实现为同 DLL 内 `filter` 模块，避免额外 DLL 注册和部署）
- [x] 实现 `ICredentialProviderFilter`。
- [x] 初始版本只记录系统 Provider 枚举情况，不隐藏任何 Provider。（已进入拦截验证阶段：仅在本 Provider 同时存在时隐藏其他 Provider）
- [x] 在测试稳定后，仅在 RDP 场景和策略开启时隐藏默认密码 Provider。（当前限制在 LOGON/UNLOCK，且缺少本 Provider 时不隐藏其他 Provider）
- [x] 将 `Filter()` 调整为默认不隐藏本地控制台登录的系统 Provider，避免影响本地密码、PIN、Windows Hello 等正常登录方式。
- [x] 将 RDP / NLA 场景的强制接管逻辑集中放在 `UpdateRemoteCredential()`：收到远程凭证序列化后，把 `clsidCredentialProvider` 改写为本项目 Provider CLSID，再交给 LogonUI 加载二次认证 Tile。
- [x] 增加登录场景策略配置，默认 `EnableRdpMfa = 1`、`EnableConsoleMfa = 0`，让 RDP 默认启用二次认证，本地控制台默认不启用。
- [x] 为本地控制台登录预留独立策略：当 `EnableConsoleMfa = 1` 时，再允许 Filter 在本地 `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION` 阶段执行隐藏默认 Provider 的逻辑。
- [x] 在 `register_tool install` 中写入默认策略配置，并在 `status` / `health` 中显示 RDP MFA、本地 MFA、应急禁用开关的当前状态。
- [x] 增加策略读取的分层模块，避免把注册表读取、Filter 判断、Provider 状态处理堆在同一个文件。
- [x] 增加注释说明：`CPUS_LOGON` 同时覆盖本地登录和 RDP 登录，不能单靠 usage scenario 判断远程来源；RDP/NLA 更可靠的入口是 `UpdateRemoteCredential()`。
- [x] 增加注册表应急开关，例如 `DisableMfa = 1`。
- [x] 增加安全模式 / 离线恢复文档。
- [x] 中文注释解释过滤条件，避免维护人员误改导致无法登录。

## 阶段 10A：Tauri 管理 GUI（后置运维工具）

- [ ] 明确产品定位：Tauri GUI 是管理员登录桌面后的配置/运维工具，不参与 LogonUI、Credential Provider、Winlogon、LSA 或 RDP 断开决策。
- [ ] 明确进程边界：核心 helper 继续以无 UI 进程/服务运行；Tauri GUI 独立启动、独立崩溃、独立升级，关闭 GUI 不影响 helper、CP 和 fail closed 策略。
- [ ] 明确依赖边界：WebView2、前端资源、Tauri 插件、窗口事件循环和 GUI 自动更新都不得成为 RDP MFA 登录链路的前置依赖。
- [ ] 新增独立 crate 或应用目录，例如 `crates/admin_gui` 或 `apps/admin_gui`，避免把 Tauri 配置、前端代码和后台 helper 主程序混在一起。
- [ ] GUI 只通过受控管理接口操作配置：优先复用 `register_tool config import/export/status/health` 能力，或调用 helper 的管理员管理 IPC；不得直接写业务注册表项。
- [ ] GUI 编辑配置时只生成临时明文 TOML 并立即导入加密 `.enc` 文件；界面和日志不得长期保存明文配置、机器码、API token、手机号、验证码、密码或 serialization。
- [ ] GUI 提供配置页：展示 `[auth_methods]`、`[mfa]`、`[phone]`、`[api]`、`[audit]`、`[remote_config]`、`[logging]` 的可编辑项，并在保存前执行与 `auth_config` 一致的校验。
- [ ] GUI 提供状态页：展示 `register_tool health` 等价信息，包括 CP 注册状态、helper 路径、helper 连通性、配置加密状态、配置最后修改时间、日志目录和远程配置缓存状态。
- [ ] GUI 提供应急页：展示 `DisableMfa`、RDP/本地 MFA 策略和恢复提示；危险操作必须有明确确认，且调用现有工具或管理 IPC 完成。
- [ ] GUI 不展示或导出解密后的敏感字段；需要排查时仅显示脱敏值、错误码、文件路径、版本、时间戳和布尔状态。
- [ ] GUI 打包必须采用 per-machine 安装或与主安装器协同安装，不能把核心 CP/helper 安装到用户私有目录；如随包安装 WebView2 或固定 runtime，必须记录在安装文档和 health 中。
- [ ] GUI 首版不做自动更新；如果未来接入自动更新，必须和 CP/helper 更新解耦，并保留离线安装与回滚方案。
- [ ] GUI 不作为第二里程碑或锁屏断开 bug 的阻塞项；只有核心 helper、IPC、AES 配置、导入/导出和 health 稳定后再启动开发。

## 阶段 10：安装、卸载与恢复

- [x] `register_tool install` 写入 Credential Provider 注册表项。
- [x] `register_tool uninstall` 删除注册表项。
- [ ] 注册 helper 路径。
- [ ] `register_tool install` 注册或记录 helper 启动路径，并确保 helper 可访问统一配置文件和日志目录。
- [ ] `register_tool install` 只把核心 helper 注册为后台进程/服务；Tauri GUI 如需安装，作为独立可选组件登记，不影响 CP/helper 注册成功。
- [ ] `register_tool health` 检查 helper 是否可启动/可连通、命名管道是否可用、session notification 是否初始化成功。
- [ ] `register_tool health` 显示 Tauri 管理 GUI 是否安装、安装路径和 WebView2/runtime 检查结果；GUI 未安装不得视为登录链路故障。
- [x] `register_tool status` / `health` 显示当前启用的认证方式，便于排查配置文件是否生效。
- [x] `register_tool status` / `health` 显示当前 MFA 超时、缺失 serialization 等待窗口、短信重新发送时间和配置来源，便于排查 VM 行为。
- [x] `register_tool status` / `health` 显示 helper session 状态策略：状态 TTL、首次登录等待窗口、已认证会话短等待窗口和 IPC 超时。
- [x] 初始化 `C:\ProgramData\rdp_auth` 目录。
- [x] 初始化日志目录。
- [ ] 初始化远程配置缓存目录，例如 `C:\ProgramData\rdp_auth\config`。
- [ ] `register_tool install` 默认创建加密配置文件，不创建长期明文 TOML；如果发现旧明文配置，提示迁移或自动导入后加密。（当前默认新建 `.enc` 已完成，旧明文发现/迁移待补）
- [ ] `register_tool uninstall` 不默认删除加密配置文件和加密备份，避免误删管理员配置；如新增清理参数，必须明确提示风险。
- [ ] `register_tool uninstall` 区分核心登录组件和 Tauri 管理 GUI：卸载 GUI 不删除 CP/helper，卸载核心组件时默认保留加密配置和备份。
- [x] 提供健康检查命令。
- [x] 提供应急禁用命令。
- [x] 编写 VM 测试和恢复文档。
- [x] `register_tool` CLI 迁移到 `clap`，由 CLI 框架统一处理子命令、必填参数、未知参数和帮助文本，减少手写解析分支。
- [ ] `register_tool` 使用 `anyhow` 为安装、卸载、注册表读写和路径校验错误补充上下文，命令行输出保持中文可读。
- [x] `register_tool health` 增加日志配置检查：显示日志目录是否存在、最近诊断日志路径、日志文件大小和最近修改时间。
- [ ] `register_tool health` 增加审计和配置检查：显示本机内网 IP、公网 IP 查询状态、远程配置版本、最后拉取时间、缓存文件状态和配置完整性校验结果。
- [ ] 中文注释解释每个注册表项的作用和删除风险。

## 阶段 11：测试计划

- [ ] 单元测试：认证状态机。
- [x] 单元测试：认证方式开关配置解析与默认值。
- [x] 单元测试：禁用认证方式不会出现在 UI 方法列表中。
- [x] 单元测试：所有认证方式关闭时恢复默认认证方式集合。
- [x] 单元测试：Credential Provider 内置认证超时默认值为 120 秒，初始 generation 为 0。
- [x] 单元测试：统一配置文件中的认证超时配置解析与默认值。
- [x] 单元测试：统一配置文件中的缺失 serialization 等待窗口和短信重新发送时间解析与默认值。
- [x] 单元测试：统一配置文件中的 helper session 状态 TTL、首次登录等待窗口、已认证会话短等待窗口和 IPC 超时解析与默认值。
- [x] 单元测试：AES 加密后不包含 TOML/JSON 明文字段，例如 `serveraddr`、`hostuuid`、手机号或 API 地址。
- [x] 单元测试：AES 解密成功后能恢复原始 TOML/JSON 并解析为结构化配置。
- [x] 单元测试：错误密文、截断文件和错误机器码时返回结构化错误且不泄漏明文。
- [x] 单元测试：`register_tool config import/export` 覆盖 CLI 解析、明文 TOML 归一化、非法 TOML 拒绝和加密配置备份命名；真实导入/导出仍需在安装环境做集成验证。
- [ ] 单元测试：缺失 serialization 保护 generation 变化后旧定时器不会断开新登录尝试。
- [ ] 单元测试：短信倒计时 generation 变化后旧刷新线程不会覆盖新倒计时。
- [x] 单元测试：helper `SessionAuthState` 标记、查询、TTL 过期和清理逻辑。
- [ ] 单元测试：helper 收到 logoff/disconnect/session end 事件后清理对应 session 状态。
- [x] 单元测试：`mark_session_authenticated`、`has_authenticated_session`、`clear_session_state` IPC 请求响应序列化。
- [x] 单元测试：手机号校验规则，合法手机号满足 `^1[3-9]\d{9}$`，非法手机号被拒绝。
- [x] 单元测试：手机号脱敏规则，`13812348888` 显示为 `138****8888`，非法手机号显示为安全占位文案。
- [ ] 单元测试：helper 文件读取手机号模式会让 CP 禁用手机号输入框，并且 UI 只显示脱敏手机号。
- [x] 单元测试：helper 策略快照在文件手机号模式下只返回脱敏手机号，且手机号字段不可编辑。
- [x] 单元测试：手动输入手机号模式下，手机号不合法时禁止发送验证码并显示错误提示。
- [x] 单元测试：`get_policy_snapshot` 不包含文件模式真实手机号，只包含脱敏手机号、字段可编辑状态和策略来源。
- [ ] 单元测试：本机内网 IP 枚举会过滤 loopback、link-local、未启用网卡，并保留多网卡有效地址。
- [ ] 单元测试：公网 IP 获取失败时按策略返回 `unknown` 或 fail closed。
- [ ] 单元测试：审计日志字段序列化包含 client_ip、host_public_ip、host_private_ips、host_uuid、session_id，且不包含手机号、验证码、密码、token。
- [ ] 单元测试：远程配置版本、TTL、签名/校验字段解析，非法配置不能覆盖本地有效配置。
- [ ] 集成测试：认证超时后自动断开当前 RDP 会话。（代码路径已实现，仍需 VM 验证）
- [x] 单元测试：RDP 原始 Provider CLSID 可通过跨进程 handoff 文件恢复。
- [x] 单元测试：Credential Provider 诊断日志会清理换行符，避免单条日志被拆行。
- [x] 单元测试：RDP 凭证重新打包时正确拼接域用户、保留 UPN 用户名。
- [x] 单元测试：`Negotiate` authentication package 名称按 LSA 调用要求保留 NUL 结尾容量。
- [x] 单元测试：Kerberos interactive packed buffer 使用相对偏移保存域、用户名、密码，并按 usage scenario 选择正确 message type。
- [x] 单元测试：IPC 请求响应序列化。
- [ ] 单元测试：注册表配置解析。
- [ ] 单元测试：API 错误映射。
- [x] 单元测试：`thiserror` IPC 编解码错误能稳定映射到用户可见文案。
- [x] 单元测试：日志脱敏函数会过滤手机号、验证码、密码、token、serialization 字节和换行符。
- [ ] 集成测试：`tracing-appender` 日志能写入 `C:\ProgramData\rdp_auth\logs` 并按配置轮转。
- [ ] 集成测试：helper mock 服务。
- [ ] 集成测试：helper session notification mock，验证 lock/unlock/disconnect/logoff 事件能更新或清理内存状态。
- [ ] 集成测试：Credential Provider 在 helper 命中已认证 session 时使用短等待/立即断开策略，在 helper 未命中时使用首次登录等待策略。
- [ ] 集成测试：helper 不可用或 IPC 超时时，Credential Provider 回退 fail closed，不放行且不长时间阻塞 LogonUI。
- [ ] 集成测试：`send_sms` 请求会携带 host_public_ip，并在公网 IP 获取失败时按策略降级。
- [ ] 集成测试：远程配置拉取、缓存、周期刷新和失败回退。
- [ ] 集成测试：远程配置缓存以 `.enc` 加密文件落盘，helper 重启后可解密加载最后一次有效配置。
- [x] 集成测试：`register_tool config export/import` 在真实机器码和注册表配置路径下完成明文 TOML 导出、重新导入、旧 `.enc` 备份和 health 复查。
- [ ] 集成测试：CP 调 helper 超时。
- [ ] 集成测试：Tauri 管理 GUI 未安装、WebView2 缺失或 GUI 启动失败时，核心 helper 仍可启动，CP 仍按 helper/IPC/fail closed 策略工作。
- [ ] 集成测试：Tauri 管理 GUI 保存配置会走 `register_tool config import` 或等效管理 IPC，加密配置写入失败时不得破坏上一份有效 `.enc` 文件。
- [ ] 集成测试：Tauri 管理 GUI health/status 页面只显示脱敏状态，不显示解密后的 API token、手机号、机器码、验证码、密码或 serialization。
- [x] VM 测试：RDP + NLA + 正确凭证 + mock MFA 成功，Kerberos interactive packed serialization 已验证进入桌面；真实 MFA 接入后需复测。
- [ ] VM 测试：RDP + NLA + 正确凭证 + MFA 失败。
- [ ] VM 测试：首次 RDP 登录时，即使 `GetCredentialCount` / `GetCredentialAt` 早于 `SetSerialization`，也不应被缺失 serialization 保护误断。
- [ ] VM 测试：RDP 未传入 serialization 的降级提示。
- [ ] VM 测试：RDP 用户注销后返回登录界面时，若没有新的 inbound serialization，应断开 RDP 连接而不是停留在孤立 MFA 入口。（代码路径已实现，仍需 VM 验证）
- [ ] VM 测试：RDP 用户锁屏后返回登录界面时，记录实际 usage scenario，并验证无新 inbound serialization 时按策略断开。
- [ ] VM 测试：ReportResult 成功后 helper 记录当前 session 已认证；锁屏/注销返回 LogonUI 且无 inbound serialization 时，helper 命中后走短等待/立即断开。
- [ ] VM 测试：helper 重启后内存状态丢失时，系统仍按首次登录等待窗口处理，不得放行孤立 MFA。
- [ ] VM 测试：session logoff/disconnect 后 helper 清理状态，后续新 session 不得复用旧认证标记。
- [ ] VM 测试：短信按钮点击后逐秒更新 `重新发送(n)`，归零后恢复 `发送验证码` 并可再次点击。
- [ ] VM 测试：安装 Tauri 管理 GUI 后，RDP 首次登录、锁屏返回断开、MFA 超时断开和 helper IPC 超时行为不发生变化。
- [ ] VM 测试：Windows Server 2008 R2 暂不纳入当前测试目标；如未来恢复兼容目标，再验证机器码注册表写入、AES 加密配置读取和重启后解密。
- [ ] VM 测试：服务端不可达时默认拒绝登录。
- [x] VM 测试：系统默认 Provider 未隐藏时可恢复登录。
- [x] VM 测试：Filter 启用后无法绕过 MFA。（当前验证为无法绕过 Provider，真实 MFA 接入后需复测）

## 阶段 12：安全与运维要求

- [ ] Windows 密码和 RDP 原始凭证 serialization 不写日志。
- [ ] 验证码、二次密码、token 不写日志。
- [ ] 手机号必须按脱敏格式写入 UI、诊断日志和 API 日志；禁止记录配置文件中的完整手机号。
- [ ] 文件模式真实手机号只能由 helper 读取并短暂保存在内存中；Credential Provider、诊断日志、策略快照和远程配置缓存不得保存完整手机号。
- [ ] client_ip、host_public_ip、host_private_ips 作为审计字段管理；诊断日志是否记录完整 IP 必须受配置控制。
- [ ] 远程配置必须校验来源和完整性，至少包含版本号、更新时间、TTL 和签名或 HMAC；校验失败不得生效。
- [ ] 远程配置下发不得绕过 MFA、不得关闭所有认证方式、不得禁用 fail closed 安全默认值。
- [ ] 所有业务配置文件必须加密落盘；包括本地统一配置、远程配置缓存、手机号文件、旧版配置迁移结果和后续新增配置文件。
- [ ] 配置加密使用注册表机器码派生 AES key；机器码不得写入日志、配置文件或 IPC 响应。
- [x] 配置导入/导出的明文文件只用于管理员维护，不作为运行期配置来源；工具必须提示明文风险，导入成功后运行期只读取加密文件。
- [x] `health` 和诊断日志只允许记录配置文件路径、加密状态、版本、修改时间和错误码，不得记录解密后的配置内容。
- [x] Credential Provider 诊断日志只记录阶段、PID、session、Provider GUID、serialization 长度和错误码，写入失败不影响 LogonUI。
- [ ] 所有 `tracing` 字段必须先经过脱敏策略评审，禁止直接使用 `?struct` 或 `%struct` 记录包含敏感字段的结构体。
- [ ] 所有 `anyhow::Context` 文案不得拼接敏感值；需要排查时使用脱敏 ID、长度、哈希前缀或内部错误码。
- [ ] 使用后清理敏感内存，必要处调用 Windows 安全清零 API。
- [ ] helper 路径固定，并校验文件存在性。
- [ ] CP 与 helper IPC 增加调用方校验或权限控制。
- [x] helper session 内存状态只保存 session id、状态枚举、时间戳和脱敏诊断码，不保存用户名、手机号、密码、验证码、token 或 serialization。
- [x] helper session 状态必须随 logoff/disconnect/session end/TTL 过期清理，避免 Windows session id 复用导致错误断开。
- [ ] CP 查询 helper session 状态时必须设置短超时，helper 异常时默认 fail closed，不能因为状态服务不可用而绕过 MFA。
- [ ] Tauri 管理 GUI 不得持有 Windows 一次登录密码、RDP serialization、验证码、二次密码、API token 或机器码；所有配置写入必须经加密层和权限校验。
- [ ] Tauri 管理 GUI 的安装、缺失、崩溃、升级失败或 WebView2/runtime 异常不得影响 CP/helper 的登录链路、session 状态清理和 fail closed 策略。
- [ ] 默认 fail closed：二次认证服务不可用时拒绝放行。
- [ ] 如需应急码，必须记录审计日志。
- [ ] 所有错误提示区分用户可见文案和诊断日志。
- [ ] 所有版本发布前必须在 VM 快照环境验证。

## 第一里程碑验收标准

- [x] Rust Credential Provider DLL 能注册并被 LogonUI 加载。
- [x] RDP 登录时能显示自定义二次认证 Tile。
- [x] CP 能收到 `SetSerialization` 传入的 RDP 原始凭证。
- [x] 不做真实二次认证时，CP 能将原始凭证交回 LogonUI 并完成登录。
- [x] 代码中关键 COM、serialization、状态机逻辑都有中文注释。
- [x] 所有改动已提交到 git。

## 第二里程碑验收标准

- [ ] 手机验证码 mock 认证可以阻断或放行 RDP 登录。
- [ ] 二次密码 mock 认证可以阻断或放行 RDP 登录。
- [ ] CP 与 helper 通过命名管道通信。
- [ ] helper 超时或异常不会导致 LogonUI 卡死。
- [ ] 所有改动已提交到 git。

## 第三里程碑验收标准

- [ ] 手机验证码接入真实 API。
- [ ] 二次密码接入真实 API。
- [ ] 登录日志上报服务端。
- [ ] 断网、服务端异常、配置缺失时默认拒绝放行并显示明确提示。
- [ ] 所有改动已提交到 git。

## 暂不处理事项

- [ ] 暂不替代 Windows 一次登录凭证输入。
- [ ] 暂不主动调用 `LsaLogonUser`。
- [ ] 暂不支持 Remote Credential Guard / Restricted Admin 的特殊凭证模型。
- [ ] 暂不在第一阶段隐藏系统默认 Credential Provider。
- [ ] 暂不把网络请求放进 Credential Provider DLL。
