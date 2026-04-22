//! 统一配置文件读取和默认文件创建。
//!
//! 本模块只处理路径、文件读写和 TOML 解析。后续实现加密时，应在这里调用 envelope
//! 解密层，再把解密后的内存文本交给 `schema` 模块解析。

use std::fmt;
use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::login_policy::{POLICY_REGISTRY_PATH, VALUE_CONFIG_PATH};
use crate::schema::AppConfig;

const DEFAULT_CONFIG_RELATIVE_PATH: &str = r"rdp_auth\config\rdp_auth.toml";

/// 业务配置加载结果，供安装工具和健康检查展示当前生效来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub path: PathBuf,
    pub exists: bool,
    pub parse_error: Option<String>,
    pub config: AppConfig,
}

impl ConfigSnapshot {
    pub fn source_label(&self) -> &'static str {
        if self.exists && self.parse_error.is_none() {
            "配置文件"
        } else {
            "内置安全默认值"
        }
    }
}

impl fmt::Display for ConfigSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "配置文件: {}", self.path.display())?;
        writeln!(
            formatter,
            "配置文件状态: {}",
            if self.exists { "存在" } else { "缺失" }
        )?;
        writeln!(formatter, "配置来源: {}", self.source_label())?;
        if let Some(error) = &self.parse_error {
            writeln!(formatter, "配置解析: 失败，已回退默认值: {error}")?;
        }
        write!(formatter, "{}", self.config.mfa)
    }
}

/// 读取统一业务配置。文件缺失或解析失败时回退内置安全默认值。
pub fn load_app_config_snapshot() -> ConfigSnapshot {
    let path = load_config_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return ConfigSnapshot {
            path,
            exists: false,
            parse_error: None,
            config: AppConfig::default(),
        };
    };

    match toml::from_str::<AppConfig>(&content) {
        Ok(config) => ConfigSnapshot {
            path,
            exists: true,
            parse_error: None,
            config: config.normalized(),
        },
        Err(error) => ConfigSnapshot {
            path,
            exists: true,
            parse_error: Some(error.to_string()),
            config: AppConfig::default(),
        },
    }
}

pub fn load_app_config() -> AppConfig {
    load_app_config_snapshot().config
}

/// 安装时创建默认 TOML 配置。已有文件不覆盖，避免污染管理员配置。
pub fn ensure_default_app_config_file() -> Result<ConfigSnapshot, String> {
    let path = load_config_path();
    if path.exists() {
        return Ok(load_app_config_snapshot());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("创建配置目录 `{}` 失败: {error}", parent.display()))?;
    }
    let content = toml::to_string_pretty(&AppConfig::default())
        .map_err(|error| format!("生成默认配置失败: {error}"))?;
    std::fs::write(&path, content)
        .map_err(|error| format!("写入默认配置 `{}` 失败: {error}", path.display()))?;
    Ok(load_app_config_snapshot())
}

pub fn load_config_path() -> PathBuf {
    let default_path = default_config_path();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey(POLICY_REGISTRY_PATH) else {
        return default_path;
    };
    key.get_value::<String, _>(VALUE_CONFIG_PATH)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(default_path)
}

pub fn default_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(DEFAULT_CONFIG_RELATIVE_PATH)
}
