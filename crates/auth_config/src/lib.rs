//! 本机配置读取模块。
//!
//! 真实实现会读取 `SOFTWARE\dexunyun.com\DexunGuard` 以及 `reginfo.ini`。这里先保留
//! 结构体和占位读取函数，后续接 Windows 注册表时必须继续保持脱敏日志，不允许把
//! host 令牌、验证码或二次密码写入日志。

use std::fmt;
use std::path::PathBuf;

use auth_core::AuthError;
use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

/// 本项目自己的策略配置注册表路径。
///
/// 这个路径只保存登录流程策略，不保存服务端 token、验证码、二次密码等敏感内容。
/// Filter 在 LogonUI 进程内只能做极轻量判断，因此这里必须保持字段少、默认值清晰。
pub const POLICY_REGISTRY_PATH: &str = r"SOFTWARE\rdp_auth\config";
/// 是否启用 RDP/NLA 场景二次认证。
pub const VALUE_ENABLE_RDP_MFA: &str = "EnableRdpMfa";
/// 是否启用本地控制台登录二次认证。
pub const VALUE_ENABLE_CONSOLE_MFA: &str = "EnableConsoleMfa";
/// 应急禁用开关。置为 1 时 Filter 和后续 Provider 逻辑都应尽量放开，避免锁死机器。
pub const VALUE_DISABLE_MFA: &str = "DisableMfa";
/// 统一 TOML 配置文件路径。注册表只保存这个引导路径，不保存业务策略细节。
pub const VALUE_CONFIG_PATH: &str = "ConfigPath";

const DEFAULT_CONFIG_RELATIVE_PATH: &str = r"rdp_auth\config\rdp_auth.toml";

/// 登录场景策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginPolicy {
    /// RDP / NLA 远程登录是否需要进入二次认证。
    pub enable_rdp_mfa: bool,
    /// 本地控制台登录是否需要进入二次认证。默认关闭，避免影响现场维护。
    pub enable_console_mfa: bool,
    /// 应急禁用。这个值优先级最高，用于 VM 或生产机器无法登录时快速恢复。
    pub disable_mfa: bool,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self {
            enable_rdp_mfa: true,
            enable_console_mfa: false,
            disable_mfa: false,
        }
    }
}

impl LoginPolicy {
    /// 判断是否允许 Filter 在本地登录/解锁界面隐藏系统默认 Provider。
    pub fn should_filter_console(self) -> bool {
        self.enable_console_mfa && !self.disable_mfa
    }

    /// 判断是否允许 Filter 接管 RDP/NLA 传入的远程凭证。
    pub fn should_route_rdp(self) -> bool {
        self.enable_rdp_mfa && !self.disable_mfa
    }
}

impl fmt::Display for LoginPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "RDP 二次认证: {}",
            if self.enable_rdp_mfa {
                "启用"
            } else {
                "关闭"
            }
        )?;
        writeln!(
            formatter,
            "本地控制台二次认证: {}",
            if self.enable_console_mfa {
                "启用"
            } else {
                "关闭"
            }
        )?;
        write!(
            formatter,
            "应急禁用开关: {}",
            if self.disable_mfa { "启用" } else { "关闭" }
        )
    }
}

/// 读取登录场景策略。
///
/// 注册表键或单个值缺失时使用安全默认值：RDP 默认启用，本地默认不启用。这样既能
/// 保持远程访问的二次认证目标，也避免因为策略未写入导致本地控制台被意外接管。
pub fn load_login_policy() -> LoginPolicy {
    let default_policy = LoginPolicy::default();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey(POLICY_REGISTRY_PATH) else {
        return default_policy;
    };

    LoginPolicy {
        enable_rdp_mfa: read_bool_value(&key, VALUE_ENABLE_RDP_MFA, default_policy.enable_rdp_mfa),
        enable_console_mfa: read_bool_value(
            &key,
            VALUE_ENABLE_CONSOLE_MFA,
            default_policy.enable_console_mfa,
        ),
        disable_mfa: read_bool_value(&key, VALUE_DISABLE_MFA, default_policy.disable_mfa),
    }
}

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

/// 统一业务配置。当前先落地 MFA 相关参数，后续 helper/API/远程配置继续扩展此结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub mfa: MfaConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            mfa: MfaConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn normalized(mut self) -> Self {
        self.schema_version = default_schema_version();
        self.mfa = self.mfa.normalized();
        self
    }
}

/// MFA 行为配置。
///
/// 这些值会进入 LogonUI 进程，因此必须有保守上下限；非法配置只回退单项默认值，
/// 不允许导致跳过 MFA 或无限等待。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaConfig {
    #[serde(default = "default_mfa_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_missing_serialization_grace_seconds")]
    pub missing_serialization_grace_seconds: u64,
    #[serde(default = "default_sms_resend_seconds")]
    pub sms_resend_seconds: u32,
    #[serde(default = "default_disconnect_when_missing_serialization")]
    pub disconnect_when_missing_serialization: bool,
    #[serde(default = "default_helper_ipc_timeout_ms")]
    pub helper_ipc_timeout_ms: u64,
    #[serde(default = "default_session_state_ttl_seconds")]
    pub session_state_ttl_seconds: u64,
    #[serde(default = "default_authenticated_session_short_grace_seconds")]
    pub authenticated_session_short_grace_seconds: u64,
    #[serde(default = "default_initial_login_grace_seconds")]
    pub initial_login_grace_seconds: u64,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_mfa_timeout_seconds(),
            missing_serialization_grace_seconds: default_missing_serialization_grace_seconds(),
            sms_resend_seconds: default_sms_resend_seconds(),
            disconnect_when_missing_serialization: default_disconnect_when_missing_serialization(),
            helper_ipc_timeout_ms: default_helper_ipc_timeout_ms(),
            session_state_ttl_seconds: default_session_state_ttl_seconds(),
            authenticated_session_short_grace_seconds:
                default_authenticated_session_short_grace_seconds(),
            initial_login_grace_seconds: default_initial_login_grace_seconds(),
        }
    }
}

impl MfaConfig {
    fn normalized(self) -> Self {
        let default = Self::default();
        Self {
            timeout_seconds: bounded_u64(self.timeout_seconds, 30, 600, default.timeout_seconds),
            missing_serialization_grace_seconds: bounded_u64(
                self.missing_serialization_grace_seconds,
                1,
                30,
                default.missing_serialization_grace_seconds,
            ),
            sms_resend_seconds: bounded_u32(
                self.sms_resend_seconds,
                10,
                300,
                default.sms_resend_seconds,
            ),
            disconnect_when_missing_serialization: self.disconnect_when_missing_serialization,
            helper_ipc_timeout_ms: bounded_u64(
                self.helper_ipc_timeout_ms,
                50,
                5_000,
                default.helper_ipc_timeout_ms,
            ),
            session_state_ttl_seconds: bounded_u64(
                self.session_state_ttl_seconds,
                60,
                86_400,
                default.session_state_ttl_seconds,
            ),
            authenticated_session_short_grace_seconds: bounded_u64(
                self.authenticated_session_short_grace_seconds,
                0,
                10,
                default.authenticated_session_short_grace_seconds,
            ),
            initial_login_grace_seconds: bounded_u64(
                self.initial_login_grace_seconds,
                1,
                30,
                default.initial_login_grace_seconds,
            ),
        }
    }
}

impl fmt::Display for MfaConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "MFA 超时: {} 秒", self.timeout_seconds)?;
        writeln!(
            formatter,
            "缺失 serialization 等待窗口: {} 秒",
            self.missing_serialization_grace_seconds
        )?;
        writeln!(formatter, "短信重发间隔: {} 秒", self.sms_resend_seconds)?;
        writeln!(
            formatter,
            "缺失 serialization 时断开 RDP: {}",
            if self.disconnect_when_missing_serialization {
                "启用"
            } else {
                "关闭"
            }
        )?;
        writeln!(
            formatter,
            "helper IPC 超时: {} ms",
            self.helper_ipc_timeout_ms
        )?;
        writeln!(
            formatter,
            "session 状态 TTL: {} 秒",
            self.session_state_ttl_seconds
        )?;
        writeln!(
            formatter,
            "已认证 session 短等待窗口: {} 秒",
            self.authenticated_session_short_grace_seconds
        )?;
        write!(
            formatter,
            "首次登录等待窗口: {} 秒",
            self.initial_login_grace_seconds
        )
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

/// 写入默认登录场景策略。
///
/// 安装工具调用这个函数，集中管理默认值，避免后续 register_tool 和 Filter 对默认策略
/// 理解不一致。这里不覆盖已有值，方便管理员先手工调整策略后重新安装 DLL。
pub fn ensure_default_login_policy() -> Result<LoginPolicy, String> {
    let default_policy = LoginPolicy::default();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(POLICY_REGISTRY_PATH)
        .map_err(|error| format!("创建登录策略注册表项失败，是否使用管理员运行: {error}"))?;

    write_bool_value_if_missing(&key, VALUE_ENABLE_RDP_MFA, default_policy.enable_rdp_mfa)?;
    write_bool_value_if_missing(
        &key,
        VALUE_ENABLE_CONSOLE_MFA,
        default_policy.enable_console_mfa,
    )?;
    write_bool_value_if_missing(&key, VALUE_DISABLE_MFA, default_policy.disable_mfa)?;
    write_string_value_if_missing(
        &key,
        VALUE_CONFIG_PATH,
        &default_config_path().display().to_string(),
    )?;

    Ok(load_login_policy())
}

fn read_bool_value(key: &RegKey, name: &str, default_value: bool) -> bool {
    key.get_value::<u32, _>(name)
        .map(|value| value != 0)
        .unwrap_or(default_value)
}

fn write_bool_value_if_missing(key: &RegKey, name: &str, value: bool) -> Result<(), String> {
    if key.get_value::<u32, _>(name).is_ok() {
        return Ok(());
    }

    let dword_value = if value { 1_u32 } else { 0_u32 };
    key.set_value(name, &dword_value)
        .map_err(|error| format!("写入登录策略 `{name}` 失败: {error}"))
}

fn write_string_value_if_missing(key: &RegKey, name: &str, value: &str) -> Result<(), String> {
    if key.get_value::<String, _>(name).is_ok() {
        return Ok(());
    }

    key.set_value(name, &value)
        .map_err(|error| format!("写入登录策略 `{name}` 失败: {error}"))
}

fn default_schema_version() -> u32 {
    1
}

fn default_mfa_timeout_seconds() -> u64 {
    120
}

fn default_missing_serialization_grace_seconds() -> u64 {
    1
}

fn default_sms_resend_seconds() -> u32 {
    60
}

fn default_disconnect_when_missing_serialization() -> bool {
    true
}

fn default_helper_ipc_timeout_ms() -> u64 {
    300
}

fn default_session_state_ttl_seconds() -> u64 {
    86_400
}

fn default_authenticated_session_short_grace_seconds() -> u64 {
    1
}

fn default_initial_login_grace_seconds() -> u64 {
    5
}

fn bounded_u64(value: u64, min: u64, max: u64, default_value: u64) -> u64 {
    if (min..=max).contains(&value) {
        value
    } else {
        default_value
    }
}

fn bounded_u32(value: u32, min: u32, max: u32, default_value: u32) -> u32 {
    if (min..=max).contains(&value) {
        value
    } else {
        default_value
    }
}

/// RDP 二次认证 helper 所需的本机配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConfig {
    /// 主机唯一标识，对应现有资料中的 `hostuuid`。
    pub host_uuid: String,
    /// 认证服务端地址，对应现有资料中的 `serveraddr`。
    pub server_addr: String,
    /// 客户端 IP 或策略判断所需 IP 字段。
    pub client_ip: Option<String>,
    /// 来源 IP 范围策略。
    pub remote_ip_range: Option<String>,
    /// 登录时间范围策略。
    pub remote_time_range: Option<String>,
    /// 地域策略。
    pub remote_region: Option<String>,
}

/// 读取本机配置。
///
/// 当前阶段只提供明确错误，避免调用方误以为已经接入真实注册表读取。
pub fn load_local_config() -> Result<LocalConfig, AuthError> {
    Err(AuthError::ConfigMissing(
        "尚未实现注册表和 reginfo.ini 配置读取".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, MfaConfig};

    #[test]
    fn partial_toml_uses_defaults() {
        let config: AppConfig = toml::from_str(
            r#"
schema_version = 1

[mfa]
timeout_seconds = 180
"#,
        )
        .unwrap();

        let config = config.normalized();

        assert_eq!(config.mfa.timeout_seconds, 180);
        assert_eq!(config.mfa.missing_serialization_grace_seconds, 1);
        assert_eq!(config.mfa.sms_resend_seconds, 60);
    }

    #[test]
    fn invalid_ranges_fall_back_to_safe_defaults() {
        let config = AppConfig {
            schema_version: 1,
            mfa: MfaConfig {
                timeout_seconds: 1,
                missing_serialization_grace_seconds: 0,
                sms_resend_seconds: 3,
                helper_ipc_timeout_ms: 10_000,
                session_state_ttl_seconds: 1,
                authenticated_session_short_grace_seconds: 20,
                initial_login_grace_seconds: 0,
                disconnect_when_missing_serialization: true,
            },
        }
        .normalized();

        assert_eq!(config.mfa, MfaConfig::default());
    }
}
