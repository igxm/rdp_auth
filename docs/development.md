# 开发规范

## Git 要求

- 每次有效代码、文档、配置变更都必须提交到 git。
- 提交前必须确认 `git status --short` 没有遗漏。
- 提交信息使用简短前缀，例如 `docs:`、`feat:`、`fix:`、`test:`。

## 中文注释要求

- 所有新增代码必须包含必要中文注释。
- 注释重点解释维护难点：Windows COM 生命周期、引用计数、凭证序列化、命名管道、安全边界、失败策略。
- 避免只重复代码表面含义，例如“设置变量值”这类注释没有维护价值。

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
