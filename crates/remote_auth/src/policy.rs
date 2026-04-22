//! helper 侧策略快照构建。
//!
//! Credential Provider 只应该拿到可渲染的脱敏快照。真实手机号文件读取、配置归一化和超时策略聚合放在
//! helper 内完成，避免 LogonUI 进程直接碰磁盘文件、复杂配置或未来的远程策略。
use std::fs;

use auth_config::{AppConfig, PhoneSource};
use auth_core::{is_valid_default_phone_number, mask_phone_number};
use auth_ipc::{PhoneInputSource, PolicySnapshot};

pub fn load_policy_snapshot_from_disk() -> PolicySnapshot {
    let config = auth_config::load_app_config();
    let configured_phone = match config.phone.source {
        PhoneSource::Input => None,
        PhoneSource::File => fs::read_to_string(&config.phone.file_path).ok(),
    };

    policy_snapshot_from_config(&config, configured_phone.as_deref())
}

pub fn policy_snapshot_from_config(
    config: &AppConfig,
    configured_phone: Option<&str>,
) -> PolicySnapshot {
    let phone_source = match config.phone.source {
        PhoneSource::Input => PhoneInputSource::ManualInput,
        PhoneSource::File => PhoneInputSource::ConfiguredFile,
    };
    let masked_phone = match config.phone.source {
        PhoneSource::Input => None,
        PhoneSource::File => configured_phone
            .map(str::trim)
            .filter(|phone| is_valid_default_phone_number(phone))
            .map(mask_phone_number),
    };

    PolicySnapshot {
        auth_methods: config.auth_methods.enabled_methods(),
        phone_source,
        masked_phone,
        phone_editable: matches!(config.phone.source, PhoneSource::Input),
        mfa_timeout_seconds: config.mfa.timeout_seconds,
        sms_resend_seconds: config.mfa.sms_resend_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::policy_snapshot_from_config;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use auth_core::AuthMethod;
    use auth_ipc::PhoneInputSource;

    #[test]
    fn input_phone_policy_keeps_phone_editable_without_masked_value() {
        let config = AppConfig::default();

        let snapshot = policy_snapshot_from_config(&config, None);

        assert_eq!(
            snapshot.auth_methods,
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
        assert_eq!(snapshot.phone_source, PhoneInputSource::ManualInput);
        assert!(snapshot.phone_editable);
        assert_eq!(snapshot.masked_phone, None);
        assert_eq!(snapshot.mfa_timeout_seconds, 120);
        assert_eq!(snapshot.sms_resend_seconds, 60);
    }

    #[test]
    fn file_phone_policy_returns_only_masked_phone() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::File,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = policy_snapshot_from_config(&config, Some("13812348888\r\n"));

        assert_eq!(snapshot.phone_source, PhoneInputSource::ConfiguredFile);
        assert!(!snapshot.phone_editable);
        assert_eq!(snapshot.masked_phone, Some("138****8888".to_owned()));
    }

    #[test]
    fn invalid_file_phone_does_not_leak_raw_value() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::File,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = policy_snapshot_from_config(&config, Some("not-a-phone"));

        assert_eq!(snapshot.masked_phone, None);
    }
}
