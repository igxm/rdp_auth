//! 命令行解析。
//!
//! 当前命令很少，先不用引入完整 CLI 框架，避免安装工具在早期阶段产生不必要依赖。
//! 如果后续加入服务安装、健康检查、应急禁用等命令，再考虑切换到 clap。

use std::ffi::OsString;
use std::path::PathBuf;

use crate::paths::normalize_dll_path;

/// 注册工具支持的命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 安装 Credential Provider 注册表项。
    Install { dll_path: PathBuf },
    /// 卸载 Credential Provider 注册表项。
    Uninstall,
    /// 查询当前注册状态。
    Status,
    /// 打印帮助。
    Help,
}

/// 解析命令行参数。
pub fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    let Some(command) = args.first().and_then(|value| value.to_str()) else {
        return Ok(Command::Help);
    };

    match command {
        "install" => parse_install(&args[1..]),
        "uninstall" => Ok(Command::Uninstall),
        "status" => Ok(Command::Status),
        "-h" | "--help" | "help" => Ok(Command::Help),
        other => Err(format!("未知命令 `{other}`，请使用 --help 查看用法")),
    }
}

fn parse_install(args: &[OsString]) -> Result<Command, String> {
    let mut dll_path = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].to_str() {
            Some("--dll") => {
                let Some(value) = args.get(index + 1) else {
                    return Err("install --dll 缺少 DLL 路径".to_owned());
                };
                dll_path = Some(normalize_dll_path(PathBuf::from(value))?);
                index += 2;
            }
            Some(flag) => {
                return Err(format!("install 不支持参数 `{flag}`"));
            }
            None => {
                return Err("参数包含非 Unicode 内容，无法安全写入注册表".to_owned());
            }
        }
    }

    let Some(dll_path) = dll_path else {
        return Err("install 需要显式传入 --dll <credential_provider.dll>".to_owned());
    };

    Ok(Command::Install { dll_path })
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_args};
    use std::ffi::OsString;

    #[test]
    fn parses_help_when_no_args() {
        assert_eq!(parse_args(Vec::<OsString>::new()).unwrap(), Command::Help);
    }

    #[test]
    fn rejects_install_without_dll() {
        let error = parse_args([OsString::from("install")]).unwrap_err();
        assert!(error.contains("--dll"));
    }
}
