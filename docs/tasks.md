# RDP 登录后二次认证任务清单

## 项目约束

- 所有后续代码、文档、配置变更都必须提交到 git，禁止留下未提交的有效改动。
- 所有新增代码必须包含必要的中文注释，重点解释 Windows COM、Credential Provider 生命周期、凭证序列化、IPC、安全边界等后期维护难点。
- 中文注释应解释“为什么这样做”和“此处有什么坑”，避免只重复代码表面含义。
- 代码必须按功能或逻辑分层，不允许把 COM 导出、类工厂、Provider、Credential、字段定义、凭证序列化、IPC、配置读取、API 调用等长期堆在同一个文件。
- Credential Provider DLL 只做 RDP 凭证接收、二次认证 UI、调用本地 helper、认证通过后转交原始凭证。
- 网络请求、注册表读取、日志、策略判断都放到本地 helper，避免 LogonUI 进程被阻塞或拖垮。
- 第一阶段不隐藏系统默认 Credential Provider，确认 RDP pass-through 链路稳定后再实现过滤器，降低锁死测试机风险。

## 总体目标

实现一个全 Rust 维护的 RDP 登录后二次认证方案：

1. RDP 客户端完成基础 Windows 凭证输入或 NLA 认证。
2. 目标机 LogonUI 加载 Rust Credential Provider。
3. Credential Provider 通过 `SetSerialization` 接收 RDP 传入的原始凭证序列化数据。
4. Credential Provider 展示二次认证界面。
5. 用户完成短信验证码、二次密码或后续微信扫码认证。
6. 二次认证通过后，`GetSerialization` 将原始凭证交回 LogonUI。
7. Winlogon / LSA 继续完成真正的 Windows 登录。

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

## 阶段 3：RDP 原始凭证接收与原样转交

- [x] 实现 `ICredentialProvider::SetSerialization`。
- [x] 深拷贝保存 `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`。
- [x] 保存字段包括 `ulAuthenticationPackage`、`clsidCredentialProvider`、`cbSerialization`、`rgbSerialization`。
- [x] 实现 `ICredentialProviderCredential::GetSerialization`。
- [x] 在未启用二次认证时，将缓存的原始凭证原样返回给 LogonUI。
- [x] 如果没有收到 inbound serialization，显示明确错误并拒绝提交。
- [x] 使用 RDP 测试：mstsc 输入凭证后，目标机 CP 能收到 serialization 并成功继续登录。
- [x] 用中文注释说明为什么不能自己调用 `LsaLogonUser`，以及为什么交给 Winlogon 处理。

## 阶段 4：二次认证 UI 状态机

- [ ] 设计字段枚举，例如 Logo、认证方式、手机号、验证码、发送短信、二次密码、登录、退出、状态文本。
- [ ] 实现手机认证和二次密码认证两个 Tab 或等效切换控件。
- [ ] 微信扫码字段预留，但第一版不接入真实逻辑。
- [ ] 实现字段显示 / 隐藏逻辑。
- [ ] 实现输入框取值和状态文本刷新。
- [ ] 实现按钮点击回调。
- [ ] 设计 `MfaState` 状态机：空闲、发送短信中、等待输入、认证中、成功、失败。
- [ ] 二次认证未通过时，`GetSerialization` 不返回原始凭证。
- [ ] 二次认证通过后，`GetSerialization` 返回缓存的原始凭证。
- [ ] 中文注释解释 LogonUI UI 更新机制和状态切换原因。

## 阶段 5：本地 helper 与 IPC

- [ ] `remote_auth` 启动命名管道服务。
- [ ] `auth_ipc` 定义 JSON 请求响应协议。
- [ ] 支持 `send_sms` 请求。
- [ ] 支持 `verify_sms` 请求。
- [ ] 支持 `verify_second_password` 请求。
- [ ] 支持 `post_login_log` 请求。
- [ ] 第一版 helper 先返回 mock 结果，用固定验证码验证主链路。
- [ ] Credential Provider 通过命名管道调用 helper。
- [ ] 增加超时处理，避免 LogonUI 长时间无响应。
- [ ] 中文注释解释为何 CP DLL 不直接发网络请求。

## 阶段 6：配置读取

- [ ] `auth_config` 读取注册表 `SOFTWARE\rdp_auth\config`。
- [ ] 读取 `hostuuid`。
- [ ] 读取 `serveraddr`。
- [ ] 读取 `ClientIp`。
- [ ] 读取 `r_ip_range`。
- [ ] 读取 `r_time_range`。
- [ ] 读取 `r_region`。
- [ ] 支持读取 `reginfo.ini`，并明确优先级。
- [ ] 配置缺失时返回结构化错误。
- [ ] helper 启动时输出脱敏诊断日志。
- [ ] 中文注释说明注册表路径、字段意义、缺失字段处理策略。

## 阶段 7：真实服务端 API

- [ ] `auth_api` 封装 HTTP client。
- [ ] 实现 `POST /api/host_instance/getSSHLoginCode`。
- [ ] 实现短信验证码校验接口，若路径未确定则先以配置项方式注入。
- [ ] 实现二次密码校验接口，若路径未确定则先以配置项方式注入。
- [ ] 实现 `POST /api/host_instance/postSSHLoginLog`。
- [ ] 定义统一 API 错误码和用户提示文案。
- [ ] 所有请求设置连接超时和总超时。
- [ ] 所有日志脱敏手机号、验证码、密码、token。
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
- [ ] 增加注册表应急开关，例如 `DisableMfa = 1`。
- [ ] 增加安全模式 / 离线恢复文档。
- [ ] 中文注释解释过滤条件，避免维护人员误改导致无法登录。

## 阶段 10：安装、卸载与恢复

- [x] `register_tool install` 写入 Credential Provider 注册表项。
- [x] `register_tool uninstall` 删除注册表项。
- [ ] 注册 helper 路径。
- [x] 初始化 `C:\ProgramData\rdp_auth` 目录。
- [x] 初始化日志目录。
- [x] 提供健康检查命令。
- [x] 提供应急禁用命令。
- [x] 编写 VM 测试和恢复文档。
- [ ] 中文注释解释每个注册表项的作用和删除风险。

## 阶段 11：测试计划

- [ ] 单元测试：认证状态机。
- [ ] 单元测试：IPC 请求响应序列化。
- [ ] 单元测试：注册表配置解析。
- [ ] 单元测试：API 错误映射。
- [ ] 集成测试：helper mock 服务。
- [ ] 集成测试：CP 调 helper 超时。
- [x] VM 测试：RDP + NLA + 正确凭证 + MFA 成功。（当前为 pass-through 验证，真实 MFA 接入后需复测）
- [ ] VM 测试：RDP + NLA + 正确凭证 + MFA 失败。
- [ ] VM 测试：RDP 未传入 serialization 的降级提示。
- [ ] VM 测试：服务端不可达时默认拒绝登录。
- [x] VM 测试：系统默认 Provider 未隐藏时可恢复登录。
- [x] VM 测试：Filter 启用后无法绕过 MFA。（当前验证为无法绕过 Provider，真实 MFA 接入后需复测）

## 阶段 12：安全与运维要求

- [ ] Windows 密码和 RDP 原始凭证 serialization 不写日志。
- [ ] 验证码、二次密码、token 不写日志。
- [ ] 使用后清理敏感内存，必要处调用 Windows 安全清零 API。
- [ ] helper 路径固定，并校验文件存在性。
- [ ] CP 与 helper IPC 增加调用方校验或权限控制。
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
