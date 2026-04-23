//! 统一配置 schema 和默认值归一化。
//!
//! 这里不做文件 IO、不读注册表，也不处理 AES 加密。保持 schema 纯净，后续新增
//! `[phone]`、`[api]`、`[audit]` 等配置时可以直接在本模块补结构和单元测试。

use std::fmt;

use auth_core::AuthMethod;
use serde::{Deserialize, Serialize};

/// 统一业务配置。当前先落地 MFA 相关参数，后续 helper/API/远程配置继续扩展此结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub auth_methods: AuthMethodsConfig,
    #[serde(default)]
    pub mfa: MfaConfig,
    #[serde(default)]
    pub phone: PhoneConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub remote_config: RemoteConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            auth_methods: AuthMethodsConfig::default(),
            mfa: MfaConfig::default(),
            phone: PhoneConfig::default(),
            api: ApiConfig::default(),
            audit: AuditConfig::default(),
            remote_config: RemoteConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn normalized(mut self) -> Self {
        self.schema_version = default_schema_version();
        self.auth_methods = self.auth_methods.normalized();
        self.mfa = self.mfa.normalized();
        self.phone = self.phone.normalized();
        self.api = self.api.normalized();
        self.audit = self.audit.normalized();
        self.remote_config = self.remote_config.normalized();
        self.logging = self.logging.normalized();
        self
    }
}

/// 认证方式开关配置。
///
/// 所有方式都关闭时必须回退到安全默认集合，不能因为配置错误让 MFA UI 没有可选项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMethodsConfig {
    #[serde(default = "default_auth_phone_code")]
    pub phone_code: bool,
    #[serde(default = "default_auth_second_password")]
    pub second_password: bool,
    #[serde(default = "default_auth_wechat")]
    pub wechat: bool,
}

impl Default for AuthMethodsConfig {
    fn default() -> Self {
        Self {
            phone_code: default_auth_phone_code(),
            second_password: default_auth_second_password(),
            wechat: default_auth_wechat(),
        }
    }
}

impl AuthMethodsConfig {
    fn normalized(self) -> Self {
        if self.phone_code || self.second_password || self.wechat {
            self
        } else {
            Self::default()
        }
    }

    pub fn enabled_methods(&self) -> Vec<AuthMethod> {
        let mut methods = Vec::new();
        if self.phone_code {
            methods.push(AuthMethod::PhoneCode);
        }
        if self.second_password {
            methods.push(AuthMethod::SecondPassword);
        }
        if self.wechat {
            methods.push(AuthMethod::Wechat);
        }
        if methods.is_empty() {
            methods.extend(AuthMethod::DEFAULT_METHODS);
        }
        methods
    }
}

impl fmt::Display for AuthMethodsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "启用认证方式: {}",
            self.enabled_methods()
                .iter()
                .map(|method| match method {
                    AuthMethod::PhoneCode => "短信验证码",
                    AuthMethod::SecondPassword => "二次密码",
                    AuthMethod::Wechat => "微信扫码",
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(formatter, "短信验证码: {}", enabled_label(self.phone_code))?;
        writeln!(
            formatter,
            "二次密码: {}",
            enabled_label(self.second_password)
        )?;
        write!(formatter, "微信扫码: {}", enabled_label(self.wechat))
    }
}

/// 手机号来源。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhoneSource {
    /// 用户在 CP UI 中手动输入手机号。
    Input,
    /// helper 从加密业务配置读取真实手机号，CP 只接收脱敏展示值。
    #[serde(alias = "file")]
    Config,
}

impl Default for PhoneSource {
    fn default() -> Self {
        Self::Input
    }
}

/// 手机号策略配置。真实手机号随业务配置加密落盘，CP 只通过 helper 获取脱敏快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneConfig {
    #[serde(default)]
    pub source: PhoneSource,
    #[serde(default)]
    pub number: String,
    #[serde(default = "default_phone_validation_pattern")]
    pub validation_pattern: String,
}

impl Default for PhoneConfig {
    fn default() -> Self {
        Self {
            source: PhoneSource::default(),
            number: String::new(),
            validation_pattern: default_phone_validation_pattern(),
        }
    }
}

impl PhoneConfig {
    fn normalized(mut self) -> Self {
        self.number = self.number.trim().to_owned();
        if self.validation_pattern.trim().is_empty() {
            self.validation_pattern = default_phone_validation_pattern();
        }
        self
    }
}

/// 服务端 API 与公网 IP 查询配置。真实请求由 helper/auth_api 执行，CP 不读取这些字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_base_url")]
    pub base_url: String,
    #[serde(default = "default_public_ip_endpoint")]
    pub public_ip_endpoint: String,
    #[serde(default = "default_api_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_api_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_require_public_ip_for_sms")]
    pub require_public_ip_for_sms: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: default_api_base_url(),
            public_ip_endpoint: default_public_ip_endpoint(),
            connect_timeout_seconds: default_api_connect_timeout_seconds(),
            request_timeout_seconds: default_api_request_timeout_seconds(),
            require_public_ip_for_sms: default_require_public_ip_for_sms(),
        }
    }
}

impl ApiConfig {
    fn normalized(mut self) -> Self {
        let default = Self::default();
        if self.base_url.trim().is_empty() {
            self.base_url = default.base_url;
        }
        if self.public_ip_endpoint.trim().is_empty() {
            self.public_ip_endpoint = default.public_ip_endpoint;
        }
        self.connect_timeout_seconds = bounded_u64(
            self.connect_timeout_seconds,
            1,
            60,
            default.connect_timeout_seconds,
        );
        self.request_timeout_seconds = bounded_u64(
            self.request_timeout_seconds,
            1,
            120,
            default.request_timeout_seconds,
        );
        self
    }
}

/// 审计日志配置。诊断日志和业务审计要分开，IP 字段按策略决定是否完整记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub ip_logging: IpLoggingMode,
    #[serde(default = "default_post_login_log")]
    pub post_login_log: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            ip_logging: IpLoggingMode::default(),
            post_login_log: default_post_login_log(),
        }
    }
}

impl AuditConfig {
    fn normalized(self) -> Self {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpLoggingMode {
    Full,
    Masked,
    Off,
}

impl Default for IpLoggingMode {
    fn default() -> Self {
        Self::Masked
    }
}

/// 远程配置缓存与刷新策略。缓存文件也必须通过 AES 加密落盘。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfig {
    #[serde(default = "default_remote_config_enabled")]
    pub enabled: bool,
    #[serde(default = "default_remote_config_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_remote_config_cache_path")]
    pub cache_path: String,
    #[serde(default = "default_remote_config_refresh_seconds")]
    pub refresh_seconds: u64,
    #[serde(default = "default_remote_config_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            enabled: default_remote_config_enabled(),
            endpoint: default_remote_config_endpoint(),
            cache_path: default_remote_config_cache_path(),
            refresh_seconds: default_remote_config_refresh_seconds(),
            ttl_seconds: default_remote_config_ttl_seconds(),
        }
    }
}

impl RemoteConfig {
    fn normalized(mut self) -> Self {
        let default = Self::default();
        if self.endpoint.trim().is_empty() {
            self.endpoint = default.endpoint;
        }
        if self.cache_path.trim().is_empty() {
            self.cache_path = default.cache_path;
        }
        self.refresh_seconds =
            bounded_u64(self.refresh_seconds, 60, 86_400, default.refresh_seconds);
        self.ttl_seconds = bounded_u64(self.ttl_seconds, 60, 604_800, default.ttl_seconds);
        self
    }
}

/// helper 诊断日志配置。运行期日志内容仍必须由调用方脱敏后写入。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_logging_dir")]
    pub dir: String,
    #[serde(default)]
    pub diagnostic_level: DiagnosticLogLevel,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: default_logging_dir(),
            diagnostic_level: DiagnosticLogLevel::default(),
        }
    }
}

impl LoggingConfig {
    fn normalized(mut self) -> Self {
        if self.dir.trim().is_empty() {
            self.dir = default_logging_dir();
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl Default for DiagnosticLogLevel {
    fn default() -> Self {
        Self::Info
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

fn default_schema_version() -> u32 {
    1
}

fn default_auth_phone_code() -> bool {
    true
}

fn default_auth_second_password() -> bool {
    true
}

fn default_auth_wechat() -> bool {
    false
}

fn default_phone_validation_pattern() -> String {
    r"^1[3-9]\d{9}$".to_owned()
}

fn default_api_base_url() -> String {
    "https://example.invalid".to_owned()
}

fn default_public_ip_endpoint() -> String {
    "https://example.invalid/ip".to_owned()
}

fn default_api_connect_timeout_seconds() -> u64 {
    5
}

fn default_api_request_timeout_seconds() -> u64 {
    10
}

fn default_require_public_ip_for_sms() -> bool {
    false
}

fn default_post_login_log() -> bool {
    true
}

fn default_remote_config_enabled() -> bool {
    false
}

fn default_remote_config_endpoint() -> String {
    "/api/host_instance/config".to_owned()
}

fn default_remote_config_cache_path() -> String {
    r"C:\ProgramData\rdp_auth\config\remote_policy.json.enc".to_owned()
}

fn default_remote_config_refresh_seconds() -> u64 {
    300
}

fn default_remote_config_ttl_seconds() -> u64 {
    900
}

fn default_logging_dir() -> String {
    r"C:\ProgramData\rdp_auth\logs".to_owned()
}

fn default_mfa_timeout_seconds() -> u64 {
    120
}

fn default_missing_serialization_grace_seconds() -> u64 {
    1
}

fn default_sms_resend_seconds() -> u32 {
    300
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

fn enabled_label(value: bool) -> &'static str {
    if value { "启用" } else { "关闭" }
}

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, AuthMethodsConfig, DiagnosticLogLevel, IpLoggingMode, MfaConfig, PhoneSource,
    };
    use auth_core::AuthMethod;

    #[test]
    fn partial_toml_uses_defaults() {
        let config = toml::from_str::<AppConfig>(
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
        assert_eq!(config.mfa.sms_resend_seconds, 300);
        assert_eq!(
            config.auth_methods.enabled_methods(),
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
        assert_eq!(config.phone.source, PhoneSource::Input);
        assert_eq!(config.api.connect_timeout_seconds, 5);
        assert_eq!(config.audit.ip_logging, IpLoggingMode::Masked);
        assert!(!config.remote_config.enabled);
        assert_eq!(config.logging.diagnostic_level, DiagnosticLogLevel::Info);
    }

    #[test]
    fn invalid_ranges_fall_back_to_safe_defaults() {
        let config = AppConfig {
            schema_version: 1,
            auth_methods: AuthMethodsConfig::default(),
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
            phone: Default::default(),
            ..Default::default()
        }
        .normalized();

        assert_eq!(config.mfa, MfaConfig::default());
    }

    #[test]
    fn auth_methods_parse_and_disable_hidden_methods() {
        let config = toml::from_str::<AppConfig>(
            r#"
schema_version = 1

[auth_methods]
phone_code = false
second_password = true
wechat = false
"#,
        )
        .unwrap();

        assert_eq!(
            config.normalized().auth_methods.enabled_methods(),
            vec![AuthMethod::SecondPassword]
        );
    }

    #[test]
    fn auth_methods_display_lists_enabled_methods() {
        let config = AuthMethodsConfig {
            phone_code: false,
            second_password: true,
            wechat: true,
        };
        let display = config.to_string();

        assert!(display.contains("启用认证方式: 二次密码, 微信扫码"));
        assert!(display.contains("短信验证码: 关闭"));
        assert!(display.contains("二次密码: 启用"));
        assert!(display.contains("微信扫码: 启用"));
    }

    #[test]
    fn all_auth_methods_disabled_falls_back_to_safe_defaults() {
        let config = AppConfig {
            schema_version: 1,
            auth_methods: AuthMethodsConfig {
                phone_code: false,
                second_password: false,
                wechat: false,
            },
            mfa: MfaConfig::default(),
            phone: Default::default(),
            ..Default::default()
        }
        .normalized();

        assert_eq!(
            config.auth_methods.enabled_methods(),
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
    }

    #[test]
    fn phone_config_parses_config_source_and_trims_number() {
        let config = toml::from_str::<AppConfig>(
            r#"
schema_version = 1

[phone]
source = "config"
number = " 13812348888 "
validation_pattern = ""
"#,
        )
        .unwrap();

        let config = config.normalized();

        assert_eq!(config.phone.source, PhoneSource::Config);
        assert_eq!(config.phone.number, "13812348888");
        assert_eq!(config.phone.validation_pattern, r"^1[3-9]\d{9}$");
    }

    #[test]
    fn legacy_file_source_aliases_to_config_without_reading_path() {
        let config = toml::from_str::<AppConfig>(
            r#"
schema_version = 1

[phone]
source = "file"
file_path = "C:\\ProgramData\\rdp_auth\\phone.txt"
number = "13812348888"
"#,
        )
        .unwrap()
        .normalized();

        assert_eq!(config.phone.source, PhoneSource::Config);
        assert_eq!(config.phone.number, "13812348888");
    }

    #[test]
    fn full_schema_groups_parse_and_normalize_ranges() {
        let config = toml::from_str::<AppConfig>(
            r#"
schema_version = 1

[api]
base_url = ""
public_ip_endpoint = ""
connect_timeout_seconds = 0
request_timeout_seconds = 999
require_public_ip_for_sms = true

[audit]
ip_logging = "off"
post_login_log = false

[remote_config]
enabled = true
endpoint = ""
cache_path = ""
refresh_seconds = 1
ttl_seconds = 9999999

[logging]
dir = ""
diagnostic_level = "debug"
"#,
        )
        .unwrap()
        .normalized();

        assert_eq!(config.api.base_url, "https://example.invalid");
        assert_eq!(config.api.public_ip_endpoint, "https://example.invalid/ip");
        assert_eq!(config.api.connect_timeout_seconds, 5);
        assert_eq!(config.api.request_timeout_seconds, 10);
        assert!(config.api.require_public_ip_for_sms);
        assert_eq!(config.audit.ip_logging, IpLoggingMode::Off);
        assert!(!config.audit.post_login_log);
        assert!(config.remote_config.enabled);
        assert_eq!(config.remote_config.endpoint, "/api/host_instance/config");
        assert!(
            config
                .remote_config
                .cache_path
                .ends_with(r"rdp_auth\config\remote_policy.json.enc")
        );
        assert_eq!(config.remote_config.refresh_seconds, 300);
        assert_eq!(config.remote_config.ttl_seconds, 900);
        assert!(config.logging.dir.ends_with(r"rdp_auth\logs"));
        assert_eq!(config.logging.diagnostic_level, DiagnosticLogLevel::Debug);
    }
}
