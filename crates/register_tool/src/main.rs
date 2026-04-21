//! Credential Provider 注册工具入口。
//!
//! 所有注册表写入都集中到这个工具，避免维护人员手工修改
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
//! 导致无法登录。这个二进制不会自动安装，只有显式执行 `install` 才会写注册表。

mod cli;
mod dirs;
mod guid;
mod paths;
mod registry;

use std::io::Write;

use cli::{Command, parse_args};
use registry::{
    ProviderRegistration, disable_provider, enable_provider, health_check, query_status,
    register_provider, unregister_provider,
};

fn main() {
    if let Err(error) = run() {
        // 有些测试环境会单独吞掉 stderr 或 stdout。错误同时写两边并立即 flush，
        // 这样管理员在 RDP/VM 控制台里更容易看到真实失败原因。
        print_line(&format!("错误: {error}"));
        eprint_line(&format!("错误: {error}"));
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match parse_args(std::env::args_os().skip(1))? {
        Command::Install { dll_path } => {
            let registration = ProviderRegistration::new(dll_path)?;
            register_provider(&registration)?;
            print_line("已注册 RDP 二次认证 Credential Provider");
            print_line(&format!("Provider CLSID: {}", registration.clsid));
            print_line(&format!("Filter CLSID: {}", registration.filter_clsid));
            print_line(&format!("DLL: {}", registration.dll_path.display()));
        }
        Command::Uninstall => {
            unregister_provider()?;
            print_line("已移除 RDP 二次认证 Credential Provider 注册表项");
        }
        Command::Status => {
            let status = query_status()?;
            print_line(&status.to_string());
        }
        Command::Health => {
            let report = health_check()?;
            print_line(&report.to_string());
        }
        Command::Disable => {
            disable_provider()?;
            print_line("已应急禁用 Provider 枚举入口，COM 注册信息已保留");
        }
        Command::Enable => {
            enable_provider()?;
            print_line("已重新启用 Provider 枚举入口");
        }
        Command::Help => {
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    print_line(
        "\
register_tool install --dll <credential_provider.dll>
register_tool uninstall
register_tool status
register_tool health
register_tool disable
register_tool enable

说明:
  install   写入 Credential Provider COM 和 LogonUI 注册表项，需要管理员权限。
  uninstall 删除本 Provider 的注册表项，需要管理员权限。
  status    只读取注册表，不修改系统。
  health    检查注册表、DLL 路径和 ProgramData 目录。
  disable   应急删除 LogonUI 枚举入口，保留 COM 注册信息。
  enable    重新创建 LogonUI 枚举入口。
",
    );
}

fn print_line(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

fn eprint_line(message: &str) {
    eprintln!("{message}");
    let _ = std::io::stderr().flush();
}
