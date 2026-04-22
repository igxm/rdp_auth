//! 统一配置 schema 和默认值归一化。
//!
//! 这里不做文件 IO、不读注册表，也不处理 DPAPI。保持 schema 纯净，后续新增
//! `[phone]`、`[api]`、`[audit]` 等配置时可以直接在本模块补结构和单元测试。

use std::fmt;

use serde::{Deserialize, Serialize};

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
