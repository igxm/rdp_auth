//! Credential Provider 共享状态和固定标识。
//!
//! 这个模块只保存跨 COM 对象需要共享或测试的轻量状态，不放 UI 字段、DLL 入口或
//! 凭证序列化逻辑。后续新增状态时，优先判断它属于 Provider 生命周期还是 Credential
//! Tile 生命周期，避免状态边界混乱。

use std::sync::Mutex;

use auth_core::{AuthMethod, MfaState};
use windows::Win32::UI::Shell::{CPUS_LOGON, CREDENTIAL_PROVIDER_USAGE_SCENARIO};
use windows::core::GUID;

use crate::serialization::InboundSerialization;

/// 当前 Credential Provider 的 CLSID。
///
/// 后续 `register_tool` 会把同一个 CLSID 写入系统 Credential Providers 注册表路径。
/// 这个值一旦发布就不应随意修改，否则升级时会出现旧 Provider 残留和新 Provider 并存。
pub const RDP_MFA_PROVIDER_CLSID: GUID = GUID::from_u128(0x92d2cf8d_8e19_49d2_9be3_3f7d9de8c2a1);

/// 当前 Credential Provider Filter 的 CLSID。
///
/// Filter 和 Provider 放在同一个 DLL，但必须使用不同 CLSID 注册。Filter 负责隐藏系统
/// 默认 Provider，强制 RDP/NLA 凭证先进入我们的二次认证 Tile。
pub const RDP_MFA_FILTER_CLSID: GUID = GUID::from_u128(0x15e6a4c5_21f7_4f8c_a805_a3c3b2d0a8b2);

static LAST_REMOTE_SOURCE_PROVIDER: Mutex<Option<GUID>> = Mutex::new(None);

/// 记录 `UpdateRemoteCredential` 重定向前的原始 Provider CLSID。
///
/// Filter 和 Provider 位于同一个 DLL，通常也在同一个 LogonUI 进程内。Filter 必须把
/// serialization 的 Provider CLSID 临时改成本项目 CLSID，LogonUI 才会把远程凭证交给
/// 我们；但认证通过后又要恢复原始 Provider CLSID，避免系统按错误 Provider 上下文解释
/// 原始密码序列化数据。
pub fn remember_remote_source_provider(provider: GUID) {
    *LAST_REMOTE_SOURCE_PROVIDER
        .lock()
        .expect("remote source provider lock poisoned") = Some(provider);
}

/// 取出最近一次 RDP 远程凭证的原始 Provider CLSID。
pub fn take_remote_source_provider() -> Option<GUID> {
    LAST_REMOTE_SOURCE_PROVIDER
        .lock()
        .expect("remote source provider lock poisoned")
        .take()
}

/// Credential Provider 内部状态。
#[derive(Debug, Clone)]
pub struct CredentialProviderState {
    /// 二次认证状态决定 `GetSerialization` 是否可以放行原始 RDP 凭证。
    pub mfa_state: MfaState,
    /// 是否已经收到 LogonUI 传入的 RDP 原始凭证序列化数据。
    pub has_inbound_serialization: bool,
    /// 深拷贝后的 RDP 原始凭证。不能保存 LogonUI 传入的原始指针。
    pub inbound_serialization: Option<InboundSerialization>,
    /// 阶段 3 用于验证 pass-through 链路的开关；真实 MFA 接入后应由策略控制。
    pub allow_passthrough_without_mfa: bool,
    /// 当前使用场景。第一版只支持 RDP 登录常见的 logon/unlock 场景。
    pub usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    /// 当前选择的二次认证方式。UI 通过组合框切换，后续 helper 会按这个值路由请求。
    pub selected_method: AuthMethod,
    /// 手机号输入值。Credential Provider 进程内只短暂保存 UI 内容，不写日志。
    pub phone: String,
    /// 短信验证码输入值。验证码属于敏感内容，只能保存在内存状态中。
    pub sms_code: String,
    /// 二次密码输入值。后续接入 helper 后必须通过 IPC 传递，不允许写日志。
    pub second_password: String,
    /// 用户可见状态文本。这里不放诊断细节，避免把敏感失败原因显示在登录界面。
    pub status_message: String,
    /// 短信验证码重新发送剩余秒数。倒计时后续需要由 LogonUI 事件或 helper 心跳推进；
    /// 当前先保存禁用态，避免用户连续点击发送验证码。
    pub sms_resend_remaining: u32,
}

impl Default for CredentialProviderState {
    fn default() -> Self {
        Self {
            mfa_state: MfaState::Idle,
            has_inbound_serialization: false,
            inbound_serialization: None,
            allow_passthrough_without_mfa: false,
            usage_scenario: CPUS_LOGON,
            selected_method: AuthMethod::PhoneCode,
            phone: String::new(),
            sms_code: String::new(),
            second_password: String::new(),
            status_message: "请选择二次认证方式".to_owned(),
            sms_resend_remaining: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialProviderState, RDP_MFA_PROVIDER_CLSID, remember_remote_source_provider,
        take_remote_source_provider,
    };
    use windows::core::GUID;

    #[test]
    fn provider_clsid_is_not_zero() {
        assert_ne!(RDP_MFA_PROVIDER_CLSID, GUID::zeroed());
    }

    #[test]
    fn default_state_waits_for_inbound_serialization() {
        let state = CredentialProviderState::default();
        assert!(!state.has_inbound_serialization);
    }

    #[test]
    fn default_state_requires_mfa_before_serialization() {
        let state = CredentialProviderState::default();
        assert!(!state.allow_passthrough_without_mfa);
    }

    #[test]
    fn remembers_and_takes_remote_source_provider() {
        let provider = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);

        remember_remote_source_provider(provider);

        assert_eq!(take_remote_source_provider(), Some(provider));
        assert_eq!(take_remote_source_provider(), None);
    }
}
