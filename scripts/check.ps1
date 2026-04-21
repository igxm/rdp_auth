$ErrorActionPreference = "Stop"

# 本地统一检查脚本。后续新增测试后继续放在这里，保证提交前检查入口稳定。
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
