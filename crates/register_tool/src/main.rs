//! Credential Provider 注册工具入口。
//!
//! 后续所有注册表写入都集中到这个工具，避免维护人员手工修改
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
//! 导致无法登录。第一版只提供命令占位和安全提示。

fn main() {
    // 骨架阶段不写注册表，避免尚未实现卸载和恢复流程时污染测试机器。
    println!("register_tool 骨架已启动，暂未执行注册表写入");
}
