//! helper 侧策略快照构建。
//!
//! Credential Provider 只应该拿到可渲染的脱敏快照。真实手机号随加密配置进入 helper，
//! CP 不直接读取配置文件，也不接收完整手机号。

use auth_config::AppConfig;
use auth_core::{is_valid_default_phone_number, mask_phone_number};
use auth_ipc::{PhoneInputSource, PolicySnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyContext {
    pub snapshot: PolicySnapshot,
    pub configured_phone: Option<String>,
}

pub fn load_policy_context_from_disk() -> PolicyContext {
    let config = auth_config::load_app_config();
    policy_context_from_config(&config)
}

pub fn policy_context_from_config(config: &AppConfig) -> PolicyContext {
    let valid_configured_phone = Some(config.phone.number.as_str())
        .filter(|phone| is_valid_default_phone_number(phone))
        .map(ToOwned::to_owned);
    let masked_phone = valid_configured_phone.as_deref().map(mask_phone_number);

    PolicyContext {
        snapshot: PolicySnapshot {
            auth_methods: config.auth_methods.enabled_methods(),
            phone_source: PhoneInputSource::Configured,
            masked_phone,
            phone_editable: false,
            mfa_timeout_seconds: config.mfa.timeout_seconds,
            sms_resend_seconds: config.mfa.sms_resend_seconds,
        },
        configured_phone: valid_configured_phone,
    }
}

#[cfg(test)]
pub fn policy_snapshot_from_config(config: &AppConfig) -> PolicySnapshot {
    policy_context_from_config(config).snapshot
}

#[cfg(test)]
mod tests {
    use super::policy_snapshot_from_config;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use auth_core::AuthMethod;
    use auth_ipc::PhoneInputSource;

    #[test]
    fn default_phone_policy_requires_configured_phone_without_input() {
        let config = AppConfig::default();

        let snapshot = policy_snapshot_from_config(&config);

        assert_eq!(
            snapshot.auth_methods,
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
        assert_eq!(snapshot.phone_source, PhoneInputSource::Configured);
        assert!(!snapshot.phone_editable);
        assert_eq!(snapshot.masked_phone, None);
        assert_eq!(snapshot.mfa_timeout_seconds, 120);
        assert_eq!(snapshot.sms_resend_seconds, 60);
    }

    #[test]
    fn configured_phone_policy_returns_only_masked_phone() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = policy_snapshot_from_config(&config);

        assert_eq!(snapshot.phone_source, PhoneInputSource::Configured);
        assert!(!snapshot.phone_editable);
        assert_eq!(snapshot.masked_phone, Some("138****8888".to_owned()));
    }

    #[test]
    fn invalid_configured_phone_does_not_leak_raw_value() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "not-a-phone".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = policy_snapshot_from_config(&config);

        assert_eq!(snapshot.masked_phone, None);
    }
}
