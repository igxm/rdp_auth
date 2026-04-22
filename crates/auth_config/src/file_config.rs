//! 统一配置文件读取和默认文件创建。
//!
//! 本模块只处理路径、文件读写、AES 加解密调用和 TOML 解析。加密细节放在
//! `protected_file`，机器码读取放在 `machine_code`，配置字段和默认值归一化放在 `schema`。

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::login_policy::{POLICY_REGISTRY_PATH, VALUE_CONFIG_PATH};
use crate::protected_file::{ConfigFileMetadata, protect_config_bytes, unprotect_config_bytes};
use crate::schema::AppConfig;

const DEFAULT_CONFIG_RELATIVE_PATH: &str = r"rdp_auth\config\rdp_auth.toml.enc";

/// 业务配置加载结果，供安装工具和健康检查展示当前生效来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub path: PathBuf,
    pub exists: bool,
    pub modified_unix_seconds: Option<u64>,
    pub encrypted: bool,
    pub encryption: Option<ConfigFileMetadata>,
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
        if let Some(modified) = self.modified_unix_seconds {
            writeln!(formatter, "配置文件修改时间: unix_seconds={modified}")?;
        }
        writeln!(formatter, "配置来源: {}", self.source_label())?;
        writeln!(
            formatter,
            "配置加密: {}",
            if self.encrypted { "是" } else { "否/未知" }
        )?;
        if let Some(encryption) = &self.encryption {
            writeln!(
                formatter,
                "配置加密算法: {} nonce_len={} ciphertext_len={}",
                encryption.algorithm, encryption.nonce_len, encryption.ciphertext_len
            )?;
        }
        if let Some(error) = &self.parse_error {
            writeln!(formatter, "配置读取: 失败，已回退默认值: {error}")?;
        }
        writeln!(formatter, "{}", self.config.auth_methods)?;
        write!(formatter, "{}", self.config.mfa)
    }
}

/// 读取统一业务配置。文件缺失、解密失败或解析失败时回退内置安全默认值。
pub fn load_app_config_snapshot() -> ConfigSnapshot {
    let path = load_config_path();
    let modified_unix_seconds = file_modified_unix_seconds(&path);
    let Ok(protected_bytes) = std::fs::read(&path) else {
        return ConfigSnapshot {
            path,
            exists: false,
            modified_unix_seconds: None,
            encrypted: false,
            encryption: None,
            parse_error: None,
            config: AppConfig::default(),
        };
    };

    let (plaintext, encryption) = match unprotect_config_bytes(&protected_bytes) {
        Ok((plaintext, encryption)) => (plaintext, Some(encryption)),
        Err(error) => {
            return ConfigSnapshot {
                path,
                exists: true,
                modified_unix_seconds,
                encrypted: false,
                encryption: None,
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
                modified_unix_seconds,
                encrypted: true,
                encryption,
                parse_error: Some(format!("配置明文不是 UTF-8: {error}")),
                config: AppConfig::default(),
            };
        }
    };

    match toml::from_str::<AppConfig>(&content) {
        Ok(config) => ConfigSnapshot {
            path,
            exists: true,
            modified_unix_seconds,
            encrypted: true,
            encryption,
            parse_error: None,
            config: config.normalized(),
        },
        Err(error) => ConfigSnapshot {
            path,
            exists: true,
            modified_unix_seconds,
            encrypted: true,
            encryption,
            parse_error: Some(error.to_string()),
            config: AppConfig::default(),
        },
    }
}

pub fn load_app_config() -> AppConfig {
    load_app_config_snapshot().config
}

/// 导出当前加密配置为明文 TOML。
///
/// 明文只允许在管理员显式维护时短暂出现，调用方不得把返回内容写入诊断日志。
pub fn export_app_config_toml() -> Result<String, String> {
    let path = load_config_path();
    let protected_bytes = std::fs::read(&path)
        .map_err(|error| format!("读取加密配置 `{}` 失败: {error}", path.display()))?;
    let (plaintext, _) = unprotect_config_bytes(&protected_bytes)
        .map_err(|error| format!("解密配置 `{}` 失败: {error}", path.display()))?;
    let content =
        String::from_utf8(plaintext).map_err(|error| format!("配置明文不是 UTF-8: {error}"))?;
    normalize_config_toml(&content)
}

pub fn export_app_config_toml_to_path(output_path: &Path) -> Result<(), String> {
    let content = export_app_config_toml()?;
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("创建导出目录 `{}` 失败: {error}", parent.display()))?;
    }
    std::fs::write(output_path, content)
        .map_err(|error| format!("导出明文配置 `{}` 失败: {error}", output_path.display()))
}

pub fn import_app_config_toml_from_path(input_path: &Path) -> Result<ConfigSnapshot, String> {
    let content = std::fs::read_to_string(input_path)
        .map_err(|error| format!("读取明文配置 `{}` 失败: {error}", input_path.display()))?;
    import_app_config_toml(&content)
}

pub fn import_app_config_toml(content: &str) -> Result<ConfigSnapshot, String> {
    let normalized = normalize_config_toml(content)?;
    let encrypted = protect_config_bytes(normalized.as_bytes())
        .map_err(|error| format!("加密导入配置失败: {error}"))?;
    let path = load_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("创建配置目录 `{}` 失败: {error}", parent.display()))?;
    }
    replace_encrypted_config(&path, &encrypted)?;
    Ok(load_app_config_snapshot())
}

fn normalize_config_toml(content: &str) -> Result<String, String> {
    let config = toml::from_str::<AppConfig>(content)
        .map_err(|error| format!("TOML 配置解析失败: {error}"))?
        .normalized();
    toml::to_string_pretty(&config).map_err(|error| format!("生成标准 TOML 失败: {error}"))
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
    let encrypted = protect_config_bytes(content.as_bytes())
        .map_err(|error| format!("加密默认配置失败: {error}"))?;
    std::fs::write(&path, encrypted)
        .map_err(|error| format!("写入默认配置 `{}` 失败: {error}", path.display()))?;
    Ok(load_app_config_snapshot())
}

fn replace_encrypted_config(path: &Path, encrypted: &[u8]) -> Result<(), String> {
    let temp_path = sibling_path_with_suffix(path, ".tmp");
    std::fs::write(&temp_path, encrypted)
        .map_err(|error| format!("写入临时加密配置 `{}` 失败: {error}", temp_path.display()))?;

    if path.exists() {
        let backup_path = next_available_backup_path(path);
        std::fs::rename(path, &backup_path).map_err(|error| {
            let _ = std::fs::remove_file(&temp_path);
            format!(
                "备份现有加密配置 `{}` 到 `{}` 失败: {error}",
                path.display(),
                backup_path.display()
            )
        })?;
        if let Err(error) = std::fs::rename(&temp_path, path) {
            let _ = std::fs::rename(&backup_path, path);
            return Err(format!(
                "写入新加密配置 `{}` 失败，已尝试恢复备份: {error}",
                path.display()
            ));
        }
    } else {
        std::fs::rename(&temp_path, path)
            .map_err(|error| format!("写入加密配置 `{}` 失败: {error}", path.display()))?;
    }

    Ok(())
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

fn file_modified_unix_seconds(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn next_available_backup_path(path: &Path) -> PathBuf {
    let first = sibling_path_with_suffix(path, ".bak");
    if !first.exists() {
        return first;
    }
    for index in 1..=999 {
        let candidate = sibling_path_with_suffix(path, &format!(".bak{index}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    sibling_path_with_suffix(path, ".bak999")
}

fn sibling_path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("rdp_auth.toml.enc");
    path.with_file_name(format!("{file_name}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::{next_available_backup_path, normalize_config_toml, replace_encrypted_config};
    use std::fs;

    #[test]
    fn normalizes_imported_plaintext_config() {
        let normalized = normalize_config_toml(
            r#"
schema_version = 1

[mfa]
timeout_seconds = 180
"#,
        )
        .unwrap();

        assert!(normalized.contains("schema_version = 1"));
        assert!(normalized.contains("timeout_seconds = 180"));
        assert!(normalized.contains("sms_resend_seconds = 60"));
    }

    #[test]
    fn config_snapshot_display_includes_auth_summary() {
        let snapshot = super::ConfigSnapshot {
            path: "C:\\ProgramData\\rdp_auth\\config\\rdp_auth.toml.enc".into(),
            exists: true,
            modified_unix_seconds: Some(1),
            encrypted: true,
            encryption: None,
            parse_error: None,
            config: Default::default(),
        };
        let display = snapshot.to_string();

        assert!(display.contains("启用认证方式: 短信验证码, 二次密码"));
        assert!(display.contains("MFA"));
    }

    #[test]
    fn rejects_invalid_plaintext_config() {
        let error = normalize_config_toml("schema_version = \"bad\"").unwrap_err();
        assert!(error.contains("TOML"));
    }

    #[test]
    fn chooses_next_backup_without_overwriting_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "rdp_auth_config_backup_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("rdp_auth.toml.enc");
        let first_backup = dir.join("rdp_auth.toml.enc.bak");
        fs::write(&first_backup, b"old").unwrap();

        assert_eq!(
            next_available_backup_path(&config),
            dir.join("rdp_auth.toml.enc.bak1")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replace_config_moves_existing_file_to_backup() {
        let dir = std::env::temp_dir().join(format!(
            "rdp_auth_config_replace_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("rdp_auth.toml.enc");
        fs::write(&config, b"old-encrypted").unwrap();

        replace_encrypted_config(&config, b"new-encrypted").unwrap();

        assert_eq!(fs::read(&config).unwrap(), b"new-encrypted");
        assert_eq!(
            fs::read(dir.join("rdp_auth.toml.enc.bak")).unwrap(),
            b"old-encrypted"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
