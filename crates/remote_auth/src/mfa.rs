//! helper 侧 MFA 处理。
//!
//! 手机号只允许来自 helper 解密后的配置，CP 和 IPC 都不再携带完整手机号。
//! 真实短信校验改为 challenge_token + code 后，challenge_token 只留在 helper 内存里，
//! verify_sms 阶段只把 token 继续发往后端，不再把手机号重新传回服务端。
use std::time::Instant;

use auth_api::{AuthApiClient, Error as AuthApiError};
use auth_ipc::IpcResponse;
use tracing::info;

use crate::policy::PolicyContext;
use crate::session_challenge::{SmsChallengeState, VerifyChallengeError};

const MOCK_SMS_CODE: &str = "123456";
const MOCK_SECOND_PASSWORD: &str = "mock-password";

trait SmsVerifyApi {
    fn verify_sms_code(&self, challenge_token: &str, code: &str) -> Result<(), AuthApiError>;
}

impl SmsVerifyApi for AuthApiClient {
    fn verify_sms_code(&self, challenge_token: &str, code: &str) -> Result<(), AuthApiError> {
        AuthApiClient::verify_sms_code(self, challenge_token, code)
    }
}

pub fn handle_send_sms(
    session_id: u32,
    phone_choice_id: &str,
    phone_choices_version: &str,
    policy: &PolicyContext,
    sms_challenges: &mut SmsChallengeState,
    now: Instant,
) -> IpcResponse {
    info!(
        target: "remote_auth",
        event = "send_sms_requested",
        session_id,
        phone_choice_id,
        phone_choices_version,
        "helper 收到发送短信请求"
    );

    if let Err(message) = validate_phone_choices_version(phone_choices_version, policy) {
        info!(
            target: "remote_auth",
            event = "send_sms_rejected_version",
            session_id,
            phone_choice_id,
            phone_choices_version,
            reason = %crate::diagnostics::sanitize_log_value(message),
            "helper 拒绝发送短信请求"
        );
        return IpcResponse::failure(message);
    }

    match resolve_configured_phone(phone_choice_id, policy) {
        Ok(_) => {
            let challenge_ttl = sms_challenges.issue_mock_challenge(
                session_id,
                phone_choice_id,
                phone_choices_version,
                now,
            );
            info!(
                target: "remote_auth",
                event = "send_sms_resolved_choice",
                session_id,
                phone_choice_id,
                phone_choices_version,
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
                phone_choices_version,
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
    phone_choices_version: &str,
    code: &str,
    policy: &PolicyContext,
    sms_challenges: &mut SmsChallengeState,
    now: Instant,
) -> IpcResponse {
    let config = auth_config::load_app_config();
    let api_client = match AuthApiClient::new(config.api.clone()) {
        Ok(client) => Some(client),
        Err(error) => {
            info!(
                target: "remote_auth",
                event = "verify_sms_api_client_invalid",
                session_id,
                phone_choice_id,
                phone_choices_version,
                reason = error.diagnostic_code(),
                "helper 无法初始化短信验证 API 客户端"
            );
            None
        }
    };
    handle_verify_sms_with_api(
        session_id,
        phone_choice_id,
        phone_choices_version,
        code,
        policy,
        sms_challenges,
        now,
        api_client.as_ref(),
    )
}

fn handle_verify_sms_with_api(
    session_id: u32,
    phone_choice_id: &str,
    phone_choices_version: &str,
    code: &str,
    policy: &PolicyContext,
    sms_challenges: &mut SmsChallengeState,
    now: Instant,
    api: Option<&impl SmsVerifyApi>,
) -> IpcResponse {
    info!(
        target: "remote_auth",
        event = "verify_sms_requested",
        session_id,
        phone_choice_id,
        phone_choices_version,
        code_len = code.chars().count(),
        "helper 收到短信验证码校验请求"
    );

    if let Err(message) = validate_phone_choices_version(phone_choices_version, policy) {
        info!(
            target: "remote_auth",
            event = "verify_sms_rejected_version",
            session_id,
            phone_choice_id,
            phone_choices_version,
            reason = %crate::diagnostics::sanitize_log_value(message),
            "helper 拒绝短信验证码校验请求"
        );
        return IpcResponse::failure(message);
    }

    if let Err(message) = resolve_configured_phone(phone_choice_id, policy) {
        info!(
            target: "remote_auth",
            event = "verify_sms_rejected_choice",
            session_id,
            phone_choice_id,
            phone_choices_version,
            reason = %crate::diagnostics::sanitize_log_value(message),
            "helper 拒绝短信验证码校验请求"
        );
        return IpcResponse::failure(message);
    }

    let challenge_token = match sms_challenges.pending_challenge_token(
        session_id,
        phone_choice_id,
        phone_choices_version,
        now,
    ) {
        Ok(challenge_token) => challenge_token,
        Err(error) => {
            let message = challenge_error_message(error);
            info!(
                target: "remote_auth",
                event = "verify_sms_rejected_challenge",
                session_id,
                phone_choice_id,
                phone_choices_version,
                reason = %crate::diagnostics::sanitize_log_value(message),
                "helper 拒绝短信验证码校验请求"
            );
            return IpcResponse::failure(message);
        }
    };

    match api {
        Some(api) => match api.verify_sms_code(&challenge_token, code) {
            Ok(()) => {
                let _ = sms_challenges.mark_verified(session_id, now);
                info!(
                    target: "remote_auth",
                    event = "verify_sms_passed",
                    session_id,
                    phone_choice_id,
                    phone_choices_version,
                    verify_mode = "challenge_token",
                    "helper 短信验证码校验通过"
                );
                IpcResponse::success("短信验证码验证通过")
            }
            Err(AuthApiError::NotImplemented { .. }) if code.trim() == MOCK_SMS_CODE => {
                // 在真实 verify 接口尚未接入前，只允许明确的 NotImplemented 回退到现有 mock 语义，
                // 这样可以先验证 challenge_token + code 的 helper 边界，而不会把网络故障误判成验证码成功。
                let _ = sms_challenges.mark_verified(session_id, now);
                info!(
                    target: "remote_auth",
                    event = "verify_sms_passed",
                    session_id,
                    phone_choice_id,
                    phone_choices_version,
                    verify_mode = "mock_fallback",
                    "helper 短信验证码校验通过"
                );
                IpcResponse::success("短信验证码验证通过")
            }
            Err(error) => {
                info!(
                    target: "remote_auth",
                    event = "verify_sms_failed",
                    session_id,
                    phone_choice_id,
                    phone_choices_version,
                    verify_mode = "challenge_token",
                    reason = error.diagnostic_code(),
                    "helper 短信验证码校验失败"
                );
                IpcResponse::failure(error.user_message())
            }
        },
        None => {
            info!(
                target: "remote_auth",
                event = "verify_sms_failed",
                session_id,
                phone_choice_id,
                phone_choices_version,
                verify_mode = "challenge_token",
                reason = "api_client_unavailable",
                "helper 短信验证码校验失败"
            );
            IpcResponse::failure("认证服务配置无效，请联系管理员")
        }
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
        VerifyChallengeError::VersionChanged => "手机号配置已更新，请重新发送验证码",
    }
}

fn validate_phone_choices_version(
    phone_choices_version: &str,
    policy: &PolicyContext,
) -> Result<(), &'static str> {
    // 版本号只用于检查“当前请求看到的脱敏手机号列表”是否仍与 helper 进程内的映射一致。
    // 一旦 helper 重启或后续配置刷新导致版本变化，就必须拒绝旧请求，避免 choice id 错配到新号码。
    if phone_choices_version.is_empty()
        || phone_choices_version != policy.snapshot.phone_choices_version
    {
        return Err("手机号配置已更新，请重新发送验证码");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use auth_api::ApiError;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};

    use super::{
        MOCK_SMS_CODE, SmsVerifyApi, handle_send_sms, handle_verify_second_password,
        handle_verify_sms_with_api,
    };
    use crate::policy::policy_context_from_config;
    use crate::session_challenge::SmsChallengeState;

    #[derive(Clone)]
    struct FakeVerifyApi {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        result: Result<(), ApiError>,
    }

    impl FakeVerifyApi {
        fn success() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                result: Ok(()),
            }
        }

        fn reject(result: ApiError) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                result: Err(result),
            }
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl SmsVerifyApi for FakeVerifyApi {
        fn verify_sms_code(&self, challenge_token: &str, code: &str) -> Result<(), ApiError> {
            self.calls
                .lock()
                .unwrap()
                .push((challenge_token.to_owned(), code.to_owned()));
            self.result.clone()
        }
    }

    #[test]
    fn send_sms_requires_configured_phone() {
        let policy = policy_context_from_config(&AppConfig::default());
        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));

        let response = handle_send_sms(
            7,
            "phone-0",
            &policy.snapshot.phone_choices_version,
            &policy,
            &mut sms_challenges,
            Instant::now(),
        );

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

        let response = handle_send_sms(
            7,
            "phone-0",
            &policy.snapshot.phone_choices_version,
            &policy,
            &mut sms_challenges,
            Instant::now(),
        );

        assert!(response.ok);
    }

    #[test]
    fn verify_sms_uses_challenge_token_api() {
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
        let api = FakeVerifyApi::success();

        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );
        assert!(
            handle_verify_sms_with_api(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                MOCK_SMS_CODE,
                &policy,
                &mut sms_challenges,
                now,
                Some(&api),
            )
            .ok
        );
        assert_eq!(
            api.calls(),
            vec![("mock-challenge-7-1".to_owned(), MOCK_SMS_CODE.to_owned())]
        );

        let mut sms_challenges = SmsChallengeState::new(Duration::from_secs(120));
        let api = FakeVerifyApi::reject(ApiError::ServerRejected {
            code: "bad_code".to_owned(),
        });
        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );
        assert!(
            !handle_verify_sms_with_api(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                "000000",
                &policy,
                &mut sms_challenges,
                now,
                Some(&api),
            )
            .ok
        );
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

        let response = handle_send_sms(
            7,
            "phone-999",
            &policy.snapshot.phone_choices_version,
            &policy,
            &mut sms_challenges,
            Instant::now(),
        );

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

        let response = handle_verify_sms_with_api(
            7,
            "phone-0",
            &policy.snapshot.phone_choices_version,
            MOCK_SMS_CODE,
            &policy,
            &mut sms_challenges,
            Instant::now(),
            Some(&FakeVerifyApi::success()),
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

        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );

        let response = handle_verify_sms_with_api(
            7,
            "phone-1",
            &policy.snapshot.phone_choices_version,
            MOCK_SMS_CODE,
            &policy,
            &mut sms_challenges,
            now,
            Some(&FakeVerifyApi::success()),
        );

        assert!(!response.ok);
        assert_eq!(response.message, "手机号选择已变化，请重新发送验证码");
    }

    #[test]
    fn verify_sms_rejects_changed_phone_choices_version() {
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

        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );

        let response = handle_verify_sms_with_api(
            7,
            "phone-0",
            "choices-stale",
            MOCK_SMS_CODE,
            &policy,
            &mut sms_challenges,
            now,
            Some(&FakeVerifyApi::success()),
        );

        assert!(!response.ok);
        assert_eq!(response.message, "手机号配置已更新，请重新发送验证码");
    }

    #[test]
    fn verify_second_password_uses_mock_password() {
        assert!(handle_verify_second_password("mock-password").ok);
        assert!(!handle_verify_second_password("wrong").ok);
    }

    #[test]
    fn verify_sms_maps_api_errors_to_safe_message() {
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
        let api = FakeVerifyApi::reject(ApiError::HttpStatus { status: 503 });

        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );

        let response = handle_verify_sms_with_api(
            7,
            "phone-0",
            &policy.snapshot.phone_choices_version,
            MOCK_SMS_CODE,
            &policy,
            &mut sms_challenges,
            now,
            Some(&api),
        );

        assert!(!response.ok);
        assert_eq!(
            response.message,
            "认证服务暂时不可用，请稍后重试或联系管理员"
        );
    }

    #[test]
    fn verify_sms_rejects_missing_api_client() {
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

        assert!(
            handle_send_sms(
                7,
                "phone-0",
                &policy.snapshot.phone_choices_version,
                &policy,
                &mut sms_challenges,
                now,
            )
            .ok
        );

        let response = handle_verify_sms_with_api(
            7,
            "phone-0",
            &policy.snapshot.phone_choices_version,
            MOCK_SMS_CODE,
            &policy,
            &mut sms_challenges,
            now,
            None::<&FakeVerifyApi>,
        );

        assert!(!response.ok);
        assert_eq!(response.message, "认证服务配置无效，请联系管理员");
    }
}
