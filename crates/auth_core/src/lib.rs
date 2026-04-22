//! RDP 二次认证的纯业务模型。
//!
//! 这个 crate 不依赖 Windows COM、网络和本地 IPC，目的是把认证方式、状态机和错误语义
//! 保持为可单元测试的普通 Rust 代码。后续维护时优先把业务判断放在这里，避免
//! `credential_provider` DLL 里混入难以调试的业务分支。

use serde::{Deserialize, Serialize};

/// 用户在登录界面选择的二次认证方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// 手机短信验证码认证，第一版主链路之一。
    PhoneCode,
    /// 二次密码认证，第一版主链路之一。
    SecondPassword,
    /// 微信扫码认证，先保留枚举值，真实流程在后续里程碑接入。
    Wechat,
}

impl AuthMethod {
    pub const DEFAULT_METHODS: [Self; 2] = [Self::PhoneCode, Self::SecondPassword];
}

/// 校验当前默认的中国大陆手机号格式。
///
/// 这里故意不用正则库，避免为了一个固定规则增加运行期依赖；后续 helper 支持
/// `phone.validation_pattern` 时，可以在 helper 层使用可配置正则。
pub fn is_valid_default_phone_number(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 11
        && bytes[0] == b'1'
        && matches!(bytes[1], b'3'..=b'9')
        && bytes.iter().all(u8::is_ascii_digit)
}

/// 返回可展示的脱敏手机号，非法输入统一返回安全占位，避免泄漏前后缀。
pub fn mask_phone_number(value: &str) -> String {
    if !is_valid_default_phone_number(value) {
        return "手机号不可用".to_owned();
    }
    format!("{}****{}", &value[..3], &value[7..])
}

/// Credential Provider 内部使用的二次认证状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaState {
    /// 初始空闲状态，此时还没有发起任何 helper 调用。
    Idle,
    /// 正在请求短信验证码，UI 应避免重复点击发送按钮。
    SendingCode,
    /// 已经发送验证码，等待用户输入。
    WaitingInput,
    /// 正在校验二次认证，Credential Provider 暂时不能交出原始 RDP 凭证。
    Verifying,
    /// 二次认证通过，`GetSerialization` 才允许返回缓存的原始凭证。
    Verified,
    /// 二次认证失败，保存用户可见的简短错误文案。
    Failed(String),
}

impl MfaState {
    /// 判断当前状态是否允许把 RDP 原始凭证交回 LogonUI。
    pub fn allows_serialization(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// 跨 crate 共享的认证错误类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthError {
    /// LogonUI 没有通过 `SetSerialization` 传入 RDP 原始凭证。
    MissingInboundSerialization,
    /// helper、服务端或本地策略拒绝本次二次认证。
    VerificationRejected(String),
    /// 本机配置不完整，通常由 `auth_config` 返回。
    ConfigMissing(String),
    /// 外部依赖超时。默认策略是 fail closed，不放行 RDP 登录。
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::{MfaState, is_valid_default_phone_number, mask_phone_number};

    #[test]
    fn only_verified_state_allows_serialization() {
        assert!(MfaState::Verified.allows_serialization());
        assert!(!MfaState::Idle.allows_serialization());
        assert!(!MfaState::Failed("验证码错误".to_owned()).allows_serialization());
    }

    #[test]
    fn validates_default_phone_number_rule() {
        assert!(is_valid_default_phone_number("13812348888"));
        assert!(!is_valid_default_phone_number("12812348888"));
        assert!(!is_valid_default_phone_number("1381234888"));
        assert!(!is_valid_default_phone_number("1381234888x"));
    }

    #[test]
    fn masks_valid_phone_and_hides_invalid_phone() {
        assert_eq!(mask_phone_number("13812348888"), "138****8888");
        assert_eq!(mask_phone_number("bad"), "手机号不可用");
    }
}
