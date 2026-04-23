# Agent 项目入口说明

本文档给后续参与 `rdp_auth` 的开发 agent 使用，用来快速理解项目目标、当前边界和安全开发方式。完整硬约束以 `AGENTS.md` 和 `docs/development.md` 为准；本文只做项目导览和执行提示。

## 项目一句话目标

本项目实现一个全 Rust 维护的 RDP 登录后二次认证链路：RDP/NLA 阶段先完成 Windows 一次凭证输入，目标机 LogonUI 加载自定义 Credential Provider，Credential Provider 在拿到远程 inbound serialization 后展示 MFA UI，MFA 通过后重新打包 Windows 凭证并交给 LogonUI/LSA 完成真正登录。

## 当前架构

```text
mstsc / RDP Client
  -> NLA / Windows 基础凭证
    -> 目标机 LogonUI
      -> credential_provider.dll
        -> 短超时 IPC
          -> remote_auth.exe
            -> 加密配置 / 注册表引导项
            -> 真实认证 API
            -> session 内存状态
            -> 脱敏诊断与审计日志
```

关键边界：

- Credential Provider DLL 运行在 LogonUI 相关进程内，只做 COM 生命周期、UI、RDP inbound serialization、短超时 helper IPC 和认证通过后的凭证打包。
- `remote_auth.exe` 是无 UI helper，负责命名管道服务、请求路由、session notification、配置聚合、API 调用和审计日志。
- `auth_core`、`auth_config`、`auth_ipc`、`auth_logging`、`auth_api` 是按职责拆出的低层库，不能反向依赖上层程序。
- 后续 Tauri/WebView 管理 GUI 只能作为独立管理工具，不得进入 LogonUI 登录链路，也不得成为 helper 核心能力的运行前置。

## Workspace 模块速查

- `crates/auth_core`：纯业务类型和纯函数，例如认证方式、MFA 状态、手机号校验和脱敏。
- `crates/auth_config`：注册表最小引导项、加密配置文件、TOML schema、默认值归一化和旧配置迁移。
- `crates/auth_ipc`：CP 与 helper 之间的非敏感协议类型和 JSON 编解码。
- `crates/auth_logging`：统一日志目录、文件名、诊断记录格式、tracing 文件初始化和脱敏函数。
- `crates/auth_api`：真实服务端 API 的请求/响应结构、超时和错误映射。
- `crates/credential_provider`：Windows Credential Provider DLL、Filter、字段、序列化、RDS session 和 LogonUI 交互。
- `crates/remote_auth`：本地后台 helper、命名管道服务、请求路由、session 内存状态、API 编排和审计。
- `crates/register_tool`：安装、卸载、状态查询、health、应急禁用和配置导入/导出。

## Credential Provider 维护要点

Credential Provider 相关代码必须保持小而可回退：

- COM 导出、类工厂、Provider、Credential、字段定义、序列化、Filter、session、timeout、diagnostics、state 分文件维护。
- 没有 inbound serialization 时不得放行；RDP 孤立 MFA Tile 应 fail closed，并按策略断开会话。
- `UpdateRemoteCredential()` 与 `SetSerialization()` 可能跨进程，原始 Provider CLSID 可通过轻量 handoff 传递，但不得传递用户名、密码或 serialization 字节。
- `GetSerialization()` 只在 MFA 通过且已有可用 inbound 凭证时返回重新打包的 Negotiate serialization。
- CP 日志只能记录脱敏诊断上下文；写入失败必须吞掉，不能影响 LogonUI。
- 不要在 CP 中发网络请求、读取复杂业务文件、启动不可控后台线程或保存长期敏感状态。

## Helper 维护要点

Helper 是复杂业务的承载点，但仍要拆清职责：

- 命名管道 transport 只负责连接生命周期、读一条请求、写一条响应。
- 请求路由只把 `auth_ipc::IpcRequest` 分发到业务 handler，不直接做文件解析或 HTTP 细节。
- session 内存状态只保存 session id、认证状态、时间戳、TTL 和最近事件，不保存用户名、手机号、密码、验证码、token 或 serialization。
- session notification 只把 lock、unlock、disconnect、logoff、session end 转换为 session 状态更新。
- 手机号文件读取只在 helper 内完成，真实手机号只短暂用于发送短信，请求外层和 IPC 响应只允许脱敏值。
- API 调用必须通过 `auth_api`，HTTP 细节不能泄漏到 CP 或 `auth_ipc` 协议外层。
- 审计日志只记录脱敏上下文和结果码，不记录敏感输入。

## 配置与安全边界

- 注册表只保存 Windows 集成必需的最小引导项：COM/Filter 注册、DLL 路径、helper 路径、配置文件路径、机器码、RDP/本地 MFA 策略和应急禁用开关。
- 业务配置统一进入加密配置文件，运行期不读取长期明文 TOML。
- 明文 TOML 只允许通过 `register_tool config export/import` 或后续管理 GUI 的显式维护流程短暂出现。
- IPC 响应不得包含完整手机号、用户名、密码、验证码、token 或 RDP serialization。
- helper 异常、IPC 超时或非法响应时，Credential Provider 必须 fail closed。

## 开发顺序建议

优先收敛主链路，再扩展体验功能：

1. VM 复测 RDP pass-through 主链路、缺失 serialization 断开保护、MFA 超时断开和短信倒计时 UI 刷新。
2. 把超时、缺失 serialization 等待窗口、短信重新发送时间、helper IPC 超时和 session TTL 迁移到统一配置。
3. 稳定 helper/IPC mock 服务和 helper 内存态 session 跟踪，把 CP 内 mock 逻辑逐步迁移到 helper。
4. 接入真实 API、远程配置、手机号文件、审计日志和公网/内网 IP 采集。
5. 在核心 helper、加密配置和 `register_tool` 能力稳定后，再开发独立管理 GUI。
6. 最后接入微信扫码等扩展认证方式。

## 常用文档入口

- `docs/development.md`：硬性开发规范、分层边界、依赖方向、提交前检查。
- `docs/architecture.md`：RDP pass-through MFA 架构、Filter 策略、UI 骨架、超时和无原始凭证策略。
- `docs/tasks.md`：阶段任务清单、当前优先级、兼容性和待办项。
- `docs/configuration.md`：配置 schema、加密配置和注册表边界。
- `docs/install.md`：安装、注册、卸载、恢复和 VM 验证流程。
- `docs/helper-ipc-test.md`：helper IPC 测试方法和协议验证。
- `docs/config-encryption-test.md`：加密配置测试方法。
- `docs/logging.md`：统一日志格式、脱敏规则和 health 边界。

## 排查优先级

RDP 登录链路问题优先按以下顺序看：

1. `credential_provider.log` 是否出现 `UpdateRemoteCredential route_to_mfa`、`SetSerialization unpacked_remote_credential`、`GetSerialization returning_packed_logon`。
2. `ReportResult` 是否返回 `0xC000006D` 等 LSA 登录失败状态；如果是，优先检查域名/用户名组合、认证包和凭证打包。
3. 是否进入缺失 serialization 保护；如果进入，确认是否是首次登录 serialization 慢到，还是已登录会话锁屏/注销后返回 LogonUI。
4. helper IPC 是否超时、异常或返回非法响应；这些情况都不能放行。
5. 日志中是否有未脱敏字段；发现后优先修复日志路径和错误 Display，而不是继续扩展功能。

## 每次任务收尾

- [ ] 查看 `git status --short`，确认没有遗漏本次改动，也没有误带用户已有改动。
- [ ] 新增代码包含必要中文注释，且注释解释维护难点。
- [ ] 确认没有破坏 crate 职责边界和依赖方向。
- [ ] 确认敏感数据没有进入日志、错误文本、IPC 响应或配置快照。
- [ ] 判断是否需要同步 `docs`；无需更新时在收尾说明已检查。
- [ ] 执行 `cargo fmt --all -- --check`。
- [ ] 执行 `cargo check --workspace`。
- [ ] 执行 `cargo test --workspace`。
- [ ] 对 Credential Provider / Filter / RDP session 相关行为，记录 VM 验证状态或补充测试任务。
- [ ] 提交本次有效变更，提交信息使用 `docs:`、`feat:`、`fix:`、`test:` 等短前缀。
