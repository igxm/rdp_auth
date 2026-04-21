//! RDP 二次认证的纯业务模型。
//!
//! 这个 crate 不依赖 Windows COM、网络和本地 IPC，目的是把认证方式、状态机和错误语义
//! 保持为可单元测试的普通 Rust 代码。后续维护时优先把业务判断放在这里，避免
//! `credential_provider` DLL 里混入难以调试的业务分支。

/// 用户在登录界面选择的二次认证方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// 手机短信验证码认证，第一版主链路之一。
    PhoneCode,
    /// 二次密码认证，第一版主链路之一。
    SecondPassword,
    /// 微信扫码认证，先保留枚举值，真实流程在后续里程碑接入。
    Wechat,
}

/// Credential Provider 内部使用的二次认证状态。
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    use super::MfaState;

    #[test]
    fn only_verified_state_allows_serialization() {
        assert!(MfaState::Verified.allows_serialization());
        assert!(!MfaState::Idle.allows_serialization());
        assert!(!MfaState::Failed("验证码错误".to_owned()).allows_serialization());
    }
}
