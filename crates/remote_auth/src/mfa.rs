//! helper 侧 MFA mock 处理。
//!
//! 真实 API 接入前，helper 先提供和 Credential Provider 当前 mock 行为一致的验证语义。这里仍然按
//! helper 边界处理手机号来源：文件模式只使用 helper 自己读取到的真实手机号，CP 不能把文件手机号传回来。
use auth_core::is_valid_default_phone_number;
use auth_ipc::{IpcResponse, PhoneInputSource};

use crate::policy::PolicyContext;

const MOCK_SMS_CODE: &str = "123456";
const MOCK_SECOND_PASSWORD: &str = "mock-password";

pub fn handle_send_sms(
    source: PhoneInputSource,
    phone: Option<&str>,
    policy: &PolicyContext,
) -> IpcResponse {
    match resolve_phone(source, phone, policy) {
        Ok(_) => IpcResponse::success("验证码已发送"),
        Err(message) => IpcResponse::failure(message),
    }
}

pub fn handle_verify_sms(phone: Option<&str>, code: &str, policy: &PolicyContext) -> IpcResponse {
    let resolved_phone = if policy.snapshot.phone_editable {
        resolve_phone(PhoneInputSource::ManualInput, phone, policy)
    } else {
        resolve_phone(PhoneInputSource::ConfiguredFile, None, policy)
    };
    if let Err(message) = resolved_phone {
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

fn resolve_phone(
    source: PhoneInputSource,
    phone: Option<&str>,
    policy: &PolicyContext,
) -> Result<String, &'static str> {
    match source {
        PhoneInputSource::ManualInput => {
            let value = phone.map(str::trim).filter(|value| !value.is_empty());
            let Some(value) = value else {
                return Err("请输入正确的手机号");
            };
            if is_valid_default_phone_number(value) {
                Ok(value.to_owned())
            } else {
                Err("请输入正确的手机号")
            }
        }
        PhoneInputSource::ConfiguredFile => policy
            .configured_phone
            .clone()
            .ok_or("手机号配置无效，请联系管理员"),
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_send_sms, handle_verify_second_password, handle_verify_sms};
    use crate::policy::policy_context_from_config;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use auth_ipc::PhoneInputSource;

    #[test]
    fn send_sms_accepts_valid_manual_phone() {
        let policy = policy_context_from_config(&AppConfig::default(), None);

        let response = handle_send_sms(PhoneInputSource::ManualInput, Some("13812348888"), &policy);

        assert!(response.ok);
    }

    #[test]
    fn send_sms_rejects_invalid_manual_phone() {
        let policy = policy_context_from_config(&AppConfig::default(), None);

        let response = handle_send_sms(PhoneInputSource::ManualInput, Some("bad"), &policy);

        assert!(!response.ok);
        assert!(!response.message.contains("bad"));
    }

    #[test]
    fn send_sms_uses_configured_file_phone_without_cp_value() {
        let config = AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::File,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = policy_context_from_config(&config, Some("13812348888"));

        let response = handle_send_sms(PhoneInputSource::ConfiguredFile, None, &policy);

        assert!(response.ok);
    }

    #[test]
    fn verify_sms_uses_mock_code() {
        let policy = policy_context_from_config(&AppConfig::default(), None);

        assert!(handle_verify_sms(Some("13812348888"), "123456", &policy).ok);
        assert!(!handle_verify_sms(Some("13812348888"), "000000", &policy).ok);
    }

    #[test]
    fn verify_second_password_uses_mock_password() {
        assert!(handle_verify_second_password("mock-password").ok);
        assert!(!handle_verify_second_password("wrong").ok);
    }
}
