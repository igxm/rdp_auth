//! 命令行解析。
//!
//! `register_tool` 的子命令已经覆盖安装、恢复、健康检查和配置导入导出。
//! 继续手写解析很容易遗漏缺参、未知参数和帮助输出细节，所以这里统一交给
//! `clap` 维护语法和错误提示；业务层仍然使用本模块导出的 `Command`，避免
//! 注册表写入逻辑直接依赖 CLI 框架。

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};

use crate::paths::{normalize_dll_path, normalize_helper_path};

/// 注册工具支持的命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 安装 Credential Provider 注册表项。
    Install {
        dll_path: PathBuf,
        helper_path: Option<PathBuf>,
    },
    /// 卸载 Credential Provider 注册表项。
    Uninstall,
    /// 查询当前注册状态。
    Status,
    /// 检查注册状态、DLL 路径和运行目录。
    Health,
    /// 应急禁用 LogonUI 枚举入口，但保留 COM 注册信息。
    Disable,
    /// 重新启用 LogonUI 枚举入口。
    Enable,
    /// 导出当前加密配置为管理员可编辑的明文 TOML。
    ConfigExport { output_path: PathBuf },
    /// 导入管理员编辑后的明文 TOML，并立即加密写回运行期配置。
    ConfigImport { input_path: PathBuf },
    /// 打印帮助。
    Help,
}

#[derive(Debug, Parser)]
#[command(
    name = "register_tool",
    about = "RDP 二次认证 Credential Provider 安装和维护工具",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<TopCommand>,
}

#[derive(Debug, Subcommand)]
enum TopCommand {
    /// 写入 Credential Provider COM 和 LogonUI 注册表项。
    Install(InstallArgs),
    /// 删除本 Provider 的注册表项。
    Uninstall,
    /// 只读取注册表，不修改系统。
    Status,
    /// 检查注册表、DLL 路径、配置和 ProgramData 目录。
    Health,
    /// 应急删除 LogonUI 枚举入口，保留 COM 注册信息。
    Disable,
    /// 重新创建 LogonUI 枚举入口。
    Enable,
    /// 导出或导入加密业务配置。
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Args)]
struct InstallArgs {
    /// credential_provider.dll 的绝对路径。
    #[arg(long = "dll", value_name = "credential_provider.dll")]
    dll_path: PathBuf,
    /// remote_auth.exe 的绝对路径；缺省时使用 DLL 同目录的 remote_auth.exe。
    #[arg(long = "helper", value_name = "remote_auth.exe")]
    helper_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// 导出明文 TOML，供管理员短期编辑。
    Export(ConfigExportArgs),
    /// 导入明文 TOML，校验后立即加密写回运行期配置。
    Import(ConfigImportArgs),
}

#[derive(Debug, Args)]
struct ConfigExportArgs {
    /// 明文 TOML 导出路径。
    #[arg(long = "out", value_name = "rdp_auth.toml")]
    output_path: PathBuf,
}

#[derive(Debug, Args)]
struct ConfigImportArgs {
    /// 明文 TOML 导入路径。
    #[arg(long = "in", value_name = "rdp_auth.toml")]
    input_path: PathBuf,
}

/// 解析命令行参数。
pub fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut argv = vec![OsString::from("register_tool")];
    argv.extend(args);

    match Cli::try_parse_from(argv) {
        Ok(cli) => cli.into_command(),
        Err(error) if error.kind() == ErrorKind::DisplayHelp => Ok(Command::Help),
        Err(error) => Err(error.to_string()),
    }
}

pub fn help_text() -> String {
    Cli::command().render_long_help().to_string()
}

impl Cli {
    fn into_command(self) -> Result<Command, String> {
        let Some(command) = self.command else {
            return Ok(Command::Help);
        };

        match command {
            TopCommand::Install(args) => Ok(Command::Install {
                dll_path: normalize_dll_path(args.dll_path)?,
                helper_path: args.helper_path.map(normalize_helper_path).transpose()?,
            }),
            TopCommand::Uninstall => Ok(Command::Uninstall),
            TopCommand::Status => Ok(Command::Status),
            TopCommand::Health => Ok(Command::Health),
            TopCommand::Disable => Ok(Command::Disable),
            TopCommand::Enable => Ok(Command::Enable),
            TopCommand::Config(config) => Ok(config.into_command()),
        }
    }
}

impl ConfigCommand {
    fn into_command(self) -> Command {
        match self {
            ConfigCommand::Export(args) => Command::ConfigExport {
                output_path: args.output_path,
            },
            ConfigCommand::Import(args) => Command::ConfigImport {
                input_path: args.input_path,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, help_text, parse_args};
    use std::ffi::OsString;

    #[test]
    fn parses_help_when_no_args() {
        assert_eq!(parse_args(Vec::<OsString>::new()).unwrap(), Command::Help);
    }

    #[test]
    fn parses_help_flag() {
        assert_eq!(
            parse_args([OsString::from("--help")]).unwrap(),
            Command::Help
        );
        assert!(help_text().contains("config"));
    }

    #[test]
    fn rejects_install_without_dll() {
        let error = parse_args([OsString::from("install")]).unwrap_err();
        assert!(error.contains("--dll"));
    }

    #[test]
    fn rejects_install_with_missing_helper() {
        let error = parse_args([
            OsString::from("install"),
            OsString::from("--dll"),
            OsString::from("missing.dll"),
            OsString::from("--helper"),
            OsString::from("missing.exe"),
        ])
        .unwrap_err();

        assert!(error.contains("DLL 路径无效"));
    }

    #[test]
    fn parses_config_export() {
        assert_eq!(
            parse_args([
                OsString::from("config"),
                OsString::from("export"),
                OsString::from("--out"),
                OsString::from("C:\\temp\\rdp_auth.toml"),
            ])
            .unwrap(),
            Command::ConfigExport {
                output_path: "C:\\temp\\rdp_auth.toml".into()
            }
        );
    }

    #[test]
    fn parses_config_import() {
        assert_eq!(
            parse_args([
                OsString::from("config"),
                OsString::from("import"),
                OsString::from("--in"),
                OsString::from("C:\\temp\\rdp_auth.toml"),
            ])
            .unwrap(),
            Command::ConfigImport {
                input_path: "C:\\temp\\rdp_auth.toml".into()
            }
        );
    }
}
