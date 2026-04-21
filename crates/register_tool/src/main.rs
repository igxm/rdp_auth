//! Credential Provider 注册工具入口。
//!
//! 所有注册表写入都集中到这个工具，避免维护人员手工修改
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
//! 导致无法登录。这个二进制不会自动安装，只有显式执行 `install` 才会写注册表。

mod cli;
mod guid;
mod paths;
mod registry;

use cli::{Command, parse_args};
use registry::{ProviderRegistration, query_status, register_provider, unregister_provider};

fn main() {
    if let Err(error) = run() {
        eprintln!("错误: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match parse_args(std::env::args_os().skip(1))? {
        Command::Install { dll_path } => {
            let registration = ProviderRegistration::new(dll_path)?;
            register_provider(&registration)?;
            println!("已注册 RDP 二次认证 Credential Provider");
            println!("CLSID: {}", registration.clsid);
            println!("DLL: {}", registration.dll_path.display());
        }
        Command::Uninstall => {
            unregister_provider()?;
            println!("已移除 RDP 二次认证 Credential Provider 注册表项");
        }
        Command::Status => {
            let status = query_status()?;
            println!("{status}");
        }
        Command::Help => {
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    println!(
        "\
register_tool install --dll <credential_provider.dll>
register_tool uninstall
register_tool status

说明:
  install   写入 Credential Provider COM 和 LogonUI 注册表项，需要管理员权限。
  uninstall 删除本 Provider 的注册表项，需要管理员权限。
  status    只读取注册表，不修改系统。
"
    );
}
