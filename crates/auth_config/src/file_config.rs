//! 统一配置文件读取和默认文件创建。
//!
//! 本模块只处理路径、文件读写、加密 envelope 调用和 TOML 解析。DPAPI 细节放在
//! `protected_file`，配置字段和默认值归一化放在 `schema`。

use std::fmt;
use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::login_policy::{POLICY_REGISTRY_PATH, VALUE_CONFIG_PATH};
use crate::protected_file::{
    ConfigEnvelopeMetadata, PlaintextFormat, protect_config_bytes, unprotect_config_bytes,
};
use crate::schema::AppConfig;

const DEFAULT_CONFIG_RELATIVE_PATH: &str = r"rdp_auth\config\rdp_auth.toml.enc";

/// 业务配置加载结果，供安装工具和健康检查展示当前生效来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub path: PathBuf,
    pub exists: bool,
    pub encrypted: bool,
    pub envelope: Option<ConfigEnvelopeMetadata>,
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
        writeln!(
            formatter,
            "配置加密: {}",
            if self.encrypted { "是" } else { "否/未知" }
        )?;
        if let Some(envelope) = &self.envelope {
            writeln!(
                formatter,
                "配置 envelope: version={} algorithm={} format={:?} ciphertext_len={}",
                envelope.version,
                envelope.algorithm,
                envelope.plaintext_format,
                envelope.ciphertext_len
            )?;
        }
        if let Some(error) = &self.parse_error {
            writeln!(formatter, "配置读取: 失败，已回退默认值: {error}")?;
        }
        write!(formatter, "{}", self.config.mfa)
    }
}

/// 读取统一业务配置。文件缺失、解密失败或解析失败时回退内置安全默认值。
pub fn load_app_config_snapshot() -> ConfigSnapshot {
    let path = load_config_path();
    let Ok(envelope_bytes) = std::fs::read(&path) else {
        return ConfigSnapshot {
            path,
            exists: false,
            encrypted: false,
            envelope: None,
            parse_error: None,
            config: AppConfig::default(),
        };
    };

    let (plaintext, envelope) = match unprotect_config_bytes(&envelope_bytes) {
        Ok((plaintext, envelope)) => (plaintext, Some(envelope)),
        Err(error) => {
            return ConfigSnapshot {
                path,
                exists: true,
                encrypted: false,
                envelope: None,
                parse_error: Some(error.to_string()),
                config: AppConfig::default(),
            };
        }
    };

    let content = match String::from_utf8(plaintext) {
        Ok(content) => content,
        Err(error) => {
            return ConfigSnapshot {
                path,
                exists: true,
                encrypted: true,
                envelope,
                parse_error: Some(format!("配置明文不是 UTF-8: {error}")),
                config: AppConfig::default(),
            };
        }
    };

    match toml::from_str::<AppConfig>(&content) {
        Ok(config) => ConfigSnapshot {
            path,
            exists: true,
            encrypted: true,
            envelope,
            parse_error: None,
            config: config.normalized(),
        },
        Err(error) => ConfigSnapshot {
            path,
            exists: true,
            encrypted: true,
            envelope,
            parse_error: Some(error.to_string()),
            config: AppConfig::default(),
        },
    }
}

pub fn load_app_config() -> AppConfig {
    load_app_config_snapshot().config
}

/// 安装时创建默认加密 TOML 配置。已有文件不覆盖，避免污染管理员配置。
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
    let encrypted = protect_config_bytes(content.as_bytes(), PlaintextFormat::Toml)
        .map_err(|error| format!("加密默认配置失败: {error}"))?;
    std::fs::write(&path, encrypted)
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
