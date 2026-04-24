//! helper 侧策略快照构建。
//!
//! Credential Provider 只应该拿到可渲染的脱敏快照。真实手机号随加密配置进入 helper，
//! CP 不直接读取配置文件，也不接收完整手机号。

use auth_config::AppConfig;
use auth_core::{is_valid_default_phone_number, mask_phone_number};
use auth_ipc::{PhoneChoiceSnapshot, PhoneInputSource, PolicySnapshot};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, PartialEq, Eq)]
pub struct PolicyContext {
    pub snapshot: PolicySnapshot,
    pub configured_phones: Vec<ConfiguredPhone>,
    pub configured_phone: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConfiguredPhone {
    pub choice_id: String,
    pub raw_phone: String,
    pub masked_phone: String,
}

pub fn load_policy_context_from_disk() -> PolicyContext {
    let config = auth_config::load_app_config();
    policy_context_from_config(&config)
}

pub fn policy_context_from_config(config: &AppConfig) -> PolicyContext {
    let phone_numbers = if config.phone.numbers.is_empty() {
        vec![config.phone.number.clone()]
    } else {
        config.phone.numbers.clone()
    };
    let configured_phones = configured_phones_from_numbers(&phone_numbers);
    let masked_phone = configured_phones
        .first()
        .map(|phone| phone.masked_phone.clone());
    let configured_phone = configured_phones
        .first()
        .map(|phone| phone.raw_phone.clone());

    PolicyContext {
        snapshot: PolicySnapshot {
            auth_methods: config.auth_methods.enabled_methods(),
            phone_source: PhoneInputSource::Configured,
            masked_phone,
            phone_choices: configured_phones
                .iter()
                .map(|phone| PhoneChoiceSnapshot {
                    id: phone.choice_id.clone(),
                    masked: phone.masked_phone.clone(),
                })
                .collect(),
            // 手机号选择版本号只用于检测 CP 持有的脱敏选择列表是否仍然匹配当前 helper 进程。
            // 这里不能把完整手机号编码进版本号，因此使用 helper 启动期生成的非敏感运行时版本。
            phone_choices_version: new_phone_choices_version(),
            phone_editable: false,
            mfa_timeout_seconds: config.mfa.timeout_seconds,
            sms_resend_seconds: config.mfa.sms_resend_seconds,
        },
        configured_phones,
        configured_phone,
    }
}

fn new_phone_choices_version() -> String {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("choices-{}-{now_nanos:x}", std::process::id())
}

fn configured_phones_from_numbers(numbers: &[String]) -> Vec<ConfiguredPhone> {
    numbers
        .iter()
        .enumerate()
        .filter(|(_, phone)| is_valid_default_phone_number(phone))
        .map(|(index, phone)| {
            // choice_id 是 CP/helper 之间后续选择手机号的唯一凭据，不能包含手机号数字。
            // 完整手机号只留在 helper 内存中，策略快照和 IPC 只能使用该 ID 与脱敏显示值。
            let choice_id = format!("phone-{index}");
            ConfiguredPhone {
                choice_id,
                raw_phone: phone.clone(),
                masked_phone: mask_phone_number(phone),
            }
        })
        .collect()
}

#[cfg(test)]
pub fn policy_snapshot_from_config(config: &AppConfig) -> PolicySnapshot {
    policy_context_from_config(config).snapshot
}

#[cfg(test)]
mod tests {
    use super::{policy_context_from_config, policy_snapshot_from_config};
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use auth_core::AuthMethod;
    use auth_ipc::{PhoneChoiceSnapshot, PhoneInputSource};

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
        assert!(snapshot.phone_choices_version.starts_with("choices-"));
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

        let context = policy_context_from_config(&config);
        let snapshot = context.snapshot;

        assert_eq!(snapshot.phone_source, PhoneInputSource::Configured);
        assert!(!snapshot.phone_editable);
        assert_eq!(snapshot.masked_phone, Some("138****8888".to_owned()));
        assert!(snapshot.phone_choices_version.starts_with("choices-"));
        assert_eq!(
            snapshot.phone_choices,
            vec![PhoneChoiceSnapshot {
                id: "phone-0".to_owned(),
                masked: "138****8888".to_owned()
            }]
        );
        assert_eq!(context.configured_phone, Some("13812348888".to_owned()));
        assert_eq!(context.configured_phones.len(), 1);
        assert_eq!(context.configured_phones[0].choice_id, "phone-0");
        assert_eq!(context.configured_phones[0].masked_phone, "138****8888");
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

        let context = policy_context_from_config(&config);
        let snapshot = context.snapshot;

        assert_eq!(snapshot.masked_phone, None);
        assert!(snapshot.phone_choices.is_empty());
        assert!(snapshot.phone_choices_version.starts_with("choices-"));
        assert_eq!(context.configured_phone, None);
        assert!(context.configured_phones.is_empty());
    }

    #[test]
    fn configured_phone_list_returns_masked_choices_without_raw_snapshot() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13800000000".to_owned(),
                numbers: vec![
                    "bad".to_owned(),
                    "13812348888".to_owned(),
                    "13912349999".to_owned(),
                ],
                ..Default::default()
            },
            ..Default::default()
        }
        .normalized();

        let context = policy_context_from_config(&config);
        let snapshot_debug = format!("{:?}", context.snapshot);

        assert_eq!(context.configured_phone, Some("13812348888".to_owned()));
        assert_eq!(
            context
                .configured_phones
                .iter()
                .map(|phone| (phone.choice_id.as_str(), phone.masked_phone.as_str()))
                .collect::<Vec<_>>(),
            vec![("phone-1", "138****8888"), ("phone-2", "139****9999")]
        );
        assert_eq!(
            context.snapshot.masked_phone,
            Some("138****8888".to_owned())
        );
        assert_eq!(
            context.snapshot.phone_choices,
            vec![
                PhoneChoiceSnapshot {
                    id: "phone-1".to_owned(),
                    masked: "138****8888".to_owned()
                },
                PhoneChoiceSnapshot {
                    id: "phone-2".to_owned(),
                    masked: "139****9999".to_owned()
                },
            ]
        );
        assert!(
            context
                .snapshot
                .phone_choices_version
                .starts_with("choices-")
        );
        assert!(!snapshot_debug.contains("13812348888"));
        assert!(!snapshot_debug.contains("13912349999"));
    }
}
