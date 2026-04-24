//! helper 侧 MFA mock 处理。
//!
//! 真实 API 接入前，helper 先提供和 Credential Provider 当前 mock 行为一致的验证语义。
//! 手机号只允许来自 helper 解密后的配置；CP 和 IPC 都不再携带完整手机号。

use auth_ipc::IpcResponse;
use tracing::info;

use crate::policy::PolicyContext;
use crate::session_challenge::{SmsChallengeState, VerifyChallengeError};
use std::time::Instant;

const MOCK_SMS_CODE: &str = "123456";
const MOCK_SECOND_PASSWORD: &str = "mock-password";

pub fn handle_send_sms(
    session_id: u32,
    phone_choice_id: &str,
    policy: &PolicyContext,
    sms_challenges: &mut SmsChallengeState,
    now: Instant,
) -> IpcResponse {
    info!(
        target: "remote_auth",
        event = "send_sms_requested",
        session_id,
        phone_choice_id,
        "helper 收到发送短信请求"
    );

    match resolve_configured_phone(phone_choice_id, policy) {
        Ok(_) => {
            let challenge_ttl =
                sms_challenges.issue_mock_challenge(session_id, phone_choice_id, now);
            info!(
                target: "remote_auth",
                event = "send_sms_resolved_choice",
                session_id,
                phone_choice_id,
                challenge_ttl_seconds = challenge_ttl.as_secs(),
                "helper 已解析手机号选择"
            );
            IpcResponse::success("验证码已发送")
        }
        Err(message) => {
            info!(
                target: "remote_auth",
                event = "send_sms_rejected_choice",
                session_id,
                phone_choice_id,
                reason = %crate::diagnostics::sanitize_log_value(message),
                "helper 拒绝发送短信请求"
            );
            IpcResponse::failure(message)
        }
    }
}

pub fn handle_verify_sms(
    session_id: u32,
    phone_choice_id: &str,
    code: &str,
    policy: &PolicyContext,
    sms_challenges: &mut SmsChallengeState,
    now: Instant,
) -> IpcResponse {
    info!(
        target: "remote_auth",
        event = "verify_sms_requested",
        session_id,
        phone_choice_id,
        code_len = code.chars().count(),
        "helper 收到短信验证码校验请求"
    );

    if let Err(message) = resolve_configured_phone(phone_choice_id, policy) {
        info!(
            target: "remote_auth",
            event = "verify_sms_rejected_choice",
            session_id,
            phone_choice_id,
            reason = %crate::diagnostics::sanitize_log_value(message),
            "helper 拒绝短信验证码校验请求"
        );
        return IpcResponse::failure(message);
    }

    if let Err(error) = sms_challenges.verify_pending_challenge(session_id, phone_choice_id, now) {
        let message = challenge_error_message(error);
        info!(
            target: "remote_auth",
            event = "verify_sms_rejected_challenge",
            session_id,
            phone_choice_id,
            reason = %crate::diagnostics::sanitize_log_value(message),
            "helper 拒绝短信验证码校验请求"
        );
        return IpcResponse::failure(message);
    }

    if code.trim() == MOCK_SMS_CODE {
        let _ = sms_challenges.mark_verified(session_id, now);
        info!(
            target: "remote_auth",
            event = "verify_sms_passed",
            session_id,
            phone_choice_id,
            "helper 短信验证码校验通过"
        );
        IpcResponse::success("短信验证码验证通过")
    } else {
        info!(
            target: "remote_auth",
            event = "verify_sms_failed",
            session_id,
            phone_choice_id,
            "helper 短信验证码校验失败"
        );
        IpcResponse::failure("短信验证码错误")
    }
}

pub fn handle_verify_second_password(password: &str) -> IpcResponse {
    if password == MOCK_SECOND_PASSWORD {
        IpcResponse::success("二次密码验证通过")
    } else {
        IpcResponse::failure("二次密码错误")
    }
}

fn resolve_configured_phone(
    phone_choice_id: &str,
    policy: &PolicyContext,
) -> Result<String, &'static str> {
    // helper 只接受非敏感选择 ID，不接受完整手机号。这样即使 CP/UI 支持多号码选择，
    // 真实手机号也不会跨出 helper 进程边界。
    policy
        .configured_phones
        .iter()
        .find(|phone| phone.choice_id == phone_choice_id)
        .map(|phone| phone.raw_phone.clone())
        .ok_or("手机号配置无效，请联系管理员")
}

fn challenge_error_message(error: VerifyChallengeError) -> &'static str {
    match error {
        // helper 只要发现 challenge 缺失或过期，就要求用户重新发送，避免继续使用未知状态。
        VerifyChallengeError::Missing => "验证码已过期，请重新发送",
        VerifyChallengeError::ChoiceChanged => "手机号选择已变化，请重新发送验证码",
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_send_sms, handle_verify_second_password, handle_verify_sms};
    use crate::policy::policy_context_from_config;
    use crate::session_challenge::SmsChallengeState;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use std::time::{Duration, Instant};

    #[test]
    fn send_sms_requires_configured_phone() {
        let policy = policy_context_from_config(&AppConfig::default());
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        let response = handle_send_sms(7, "phone-0", &policy, &mut sms_challenges, Instant::now());

        assert!(!response.ok);
        assert_eq!(response.message, "手机号配置无效，请联系管理员");
    }

    #[test]
    fn send_sms_uses_configured_phone_without_cp_value() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config);
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        let response = handle_send_sms(7, "phone-0", &policy, &mut sms_challenges, Instant::now());

        assert!(response.ok);
    }

    #[test]
    fn verify_sms_uses_mock_code() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config);
        let now = Instant::now();
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        assert!(handle_send_sms(7, "phone-0", &policy, &mut sms_challenges, now).ok);
        assert!(handle_verify_sms(7, "phone-0", "123456", &policy, &mut sms_challenges, now).ok);

        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));
        assert!(handle_send_sms(7, "phone-0", &policy, &mut sms_challenges, now).ok);
        assert!(!handle_verify_sms(7, "phone-0", "000000", &policy, &mut sms_challenges, now).ok);
    }

    #[test]
    fn send_sms_rejects_unknown_phone_choice_id() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config);
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        let response =
            handle_send_sms(7, "phone-999", &policy, &mut sms_challenges, Instant::now());

        assert!(!response.ok);
        assert_eq!(response.message, "手机号配置无效，请联系管理员");
    }

    #[test]
    fn verify_sms_requires_pending_challenge() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config);
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        let response = handle_verify_sms(
            7,
            "phone-0",
            "123456",
            &policy,
            &mut sms_challenges,
            Instant::now(),
        );

        assert!(!response.ok);
        assert_eq!(response.message, "验证码已过期，请重新发送");
    }

    #[test]
    fn verify_sms_rejects_changed_phone_choice() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                numbers: vec!["13812348888".to_owned(), "13912349999".to_owned()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config);
        let now = Instant::now();
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        assert!(handle_send_sms(7, "phone-0", &policy, &mut sms_challenges, now).ok);

        let response = handle_verify_sms(7, "phone-1", "123456", &policy, &mut sms_challenges, now);

        assert!(!response.ok);
        assert_eq!(response.message, "手机号选择已变化，请重新发送验证码");
    }

    #[test]
    fn verify_second_password_uses_mock_password() {
        assert!(handle_verify_second_password("mock-password").ok);
        assert!(!handle_verify_second_password("wrong").ok);
    }
}
