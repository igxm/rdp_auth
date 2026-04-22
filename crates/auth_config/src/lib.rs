//! 本机配置读取模块。
//!
//! 本 crate 只负责把注册表最小引导项、统一配置文件和默认值转换为结构化配置。
//! 注册表、文件读取、schema 归一化和旧配置迁移必须分层维护，避免后续把 AES
//! 加密、远程缓存、手机号策略和 API 配置继续堆进单个文件。

mod file_config;
mod legacy;
mod login_policy;
mod machine_code;
mod protected_file;
mod schema;

pub use file_config::{
    ConfigSnapshot, default_config_path, ensure_default_app_config_file, export_app_config_toml,
    export_app_config_toml_to_path, import_app_config_toml, import_app_config_toml_from_path,
    load_app_config, load_app_config_snapshot, load_config_path,
};
pub use legacy::{LocalConfig, load_local_config};
pub use login_policy::{
    LoginPolicy, POLICY_REGISTRY_PATH, VALUE_CONFIG_PATH, VALUE_DISABLE_MFA,
    VALUE_ENABLE_CONSOLE_MFA, VALUE_ENABLE_RDP_MFA, ensure_default_login_policy, load_login_policy,
};
pub use machine_code::{
    VALUE_MACHINE_CODE, derive_aes_key_from_machine_code, ensure_machine_code, load_machine_code,
};
pub use protected_file::{
    ConfigFileMetadata, ConfigProtectionError, protect_config_bytes, unprotect_config_bytes,
};
pub use schema::{AppConfig, MfaConfig};
