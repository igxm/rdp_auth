# 开发规范

## Git 要求

- 每次有效代码、文档、配置变更都必须提交到 git。
- 提交前必须确认 `git status --short` 没有遗漏。
- 提交信息使用简短前缀，例如 `docs:`、`feat:`、`fix:`、`test:`。

## 中文注释要求

- 所有新增代码必须包含必要中文注释。
- 注释重点解释维护难点：Windows COM 生命周期、引用计数、凭证序列化、命名管道、安全边界、失败策略。
- 避免只重复代码表面含义，例如“设置变量值”这类注释没有维护价值。

## 代码分层要求

- 代码必须按功能和逻辑分层，不允许把 COM 导出、类工厂、Provider、Credential、字段定义、凭证序列化、IPC、配置读取、API 调用等长期堆在同一个文件。
- 单个文件只应承载一个清晰职责；当文件开始同时处理多个概念时，必须拆分为模块，例如 `dll.rs`、`class_factory.rs`、`provider.rs`、`credential.rs`、`fields.rs`、`serialization.rs`。
- Credential Provider 相关代码应优先按 Windows 生命周期拆分：DLL 入口、COM 类工厂、Provider 枚举、Credential Tile、字段描述符、凭证序列化、UI 状态机。
- helper 相关代码应按运行边界拆分：命名管道服务、请求路由、配置读取、API client、日志、策略判断。
- 新增抽象必须服务于可维护性和测试，不为了“看起来分层”制造空壳；但一旦模块职责稳定，就应及时拆文件。

## 文档同步要求

- 每完成一个任务，都必须判断本次变更是否影响 `docs` 中的对应文档。
- 如果代码行为、安装步骤、测试方法、配置项、注册表路径、架构边界、恢复流程或已知限制发生变化，必须同步更新对应文档。
- 如果没有需要更新的文档，应在任务收尾时明确说明已经检查过文档，无需变更。
- 文档更新应跟随同一个任务提交，不要把代码变更和必要文档长期拆开。

## 本地检查

提交前至少执行：

```powershell
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

也可以运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

## VM 测试要求

Credential Provider 和 Filter 相关功能必须在 Windows VM 快照环境验证。未确认卸载和恢复流程前，不允许在主力机器上隐藏系统默认 Credential Provider。
