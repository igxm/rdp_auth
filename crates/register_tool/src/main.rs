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

use auth_config::{export_app_config_toml_to_path, import_app_config_toml_from_path};
use cli::{Command, help_text, parse_args};
use registry::{
    ProviderRegistration, disable_provider, enable_provider, health_check, query_app_config,
    query_login_policy, query_status, register_provider, unregister_provider,
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
            print_line(&format!("登录策略:\n{}", query_login_policy()));
            print_line(&format!("业务配置:\n{}", query_app_config()));
        }
        Command::Uninstall => {
            unregister_provider()?;
            print_line("已移除 RDP 二次认证 Credential Provider 注册表项");
        }
        Command::Status => {
            let status = query_status()?;
            print_line(&status.to_string());
            print_line(&format!("登录策略:\n{}", query_login_policy()));
            print_line(&format!("业务配置:\n{}", query_app_config()));
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
        Command::ConfigExport { output_path } => {
            export_app_config_toml_to_path(&output_path).map_err(|error| error.to_string())?;
            print_line(&format!("已导出明文 TOML 配置: {}", output_path.display()));
            print_line(
                "提示: 该文件包含管理员可编辑的明文配置，只用于短期维护；完成导入后请删除或妥善保护。",
            );
        }
        Command::ConfigImport { input_path } => {
            let snapshot =
                import_app_config_toml_from_path(&input_path).map_err(|error| error.to_string())?;
            print_line(&format!(
                "已导入并重新加密配置: {}",
                snapshot.path.display()
            ));
            print_line("提示: 运行期只读取加密 .enc 配置；请删除或妥善保护导入用的明文 TOML。");
            print_line(&format!("业务配置:\n{}", snapshot));
        }
        Command::Help => {
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    print_line(&help_text());
}

fn print_line(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

fn eprint_line(message: &str) {
    eprintln!("{message}");
    let _ = std::io::stderr().flush();
}
