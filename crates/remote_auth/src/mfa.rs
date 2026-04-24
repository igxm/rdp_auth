//! helper 侧 MFA mock 处理。
//!
//! 真实 API 接入前，helper 先提供和 Credential Provider 当前 mock 行为一致的验证语义。
//! 手机号只能来自 helper 解密后的配置，CP 和 IPC 都不再携带真实手机号。
use auth_ipc::IpcResponse;

use crate::policy::PolicyContext;

const MOCK_SMS_CODE: &str = "123456";
const MOCK_SECOND_PASSWORD: &str = "mock-password";

pub fn handle_send_sms(phone_choice_id: &str, policy: &PolicyContext) -> IpcResponse {
    match resolve_configured_phone(phone_choice_id, policy) {
        Ok(_) => IpcResponse::success("验证码已发送"),
        Err(message) => IpcResponse::failure(message),
    }
}

pub fn handle_verify_sms(phone_choice_id: &str, code: &str, policy: &PolicyContext) -> IpcResponse {
    if let Err(message) = resolve_configured_phone(phone_choice_id, policy) {
        return IpcResponse::failure(message);
    }
    if code.trim() == MOCK_SMS_CODE {
        IpcResponse::success("短信验证码验证通过")
    } else {
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
    // helper 只接受非敏感选择 ID，不接受完整手机号。这样即使 CP/UI 未来支持多号码选择，
    // 真实手机号也不会跨出 helper 进程边界。
    policy
        .configured_phones
        .iter()
        .find(|phone| phone.choice_id == phone_choice_id)
        .map(|phone| phone.raw_phone.clone())
        .ok_or("手机号配置无效，请联系管理员")
}

#[cfg(test)]
mod tests {
    use super::{handle_send_sms, handle_verify_second_password, handle_verify_sms};
    use crate::policy::policy_context_from_config;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    #[test]
    fn send_sms_requires_configured_phone() {
        let policy = policy_context_from_config(&AppConfig::default());

        let response = handle_send_sms("phone-0", &policy);

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

        let response = handle_send_sms("phone-0", &policy);

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

        assert!(handle_verify_sms("phone-0", "123456", &policy).ok);
        assert!(!handle_verify_sms("phone-0", "000000", &policy).ok);
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

        let response = handle_send_sms("phone-999", &policy);

        assert!(!response.ok);
        assert_eq!(response.message, "手机号配置无效，请联系管理员");
    }

    #[test]
    fn verify_second_password_uses_mock_password() {
        assert!(handle_verify_second_password("mock-password").ok);
        assert!(!handle_verify_second_password("wrong").ok);
    }
}
