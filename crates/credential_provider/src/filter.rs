//! Credential Provider Filter 实现。
//!
//! 仅注册 Provider 时，LogonUI 仍可能让系统默认 Password Provider 自动消费 RDP/NLA
//! 传入的凭证，用户就会直接进入桌面。Filter 的职责是在我们的 Provider 同时存在时，
//! 隐藏其他 Provider，让 RDP 凭证先进入二次认证 Tile。

use windows::Win32::Foundation::E_POINTER;
use windows::Win32::UI::Shell::{
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProviderFilter, ICredentialProviderFilter_Impl,
};
use windows::core::{BOOL, Error, GUID, Result, implement};

use crate::serialization::InboundSerialization;
use crate::state::RDP_MFA_PROVIDER_CLSID;

/// RDP 二次认证 Filter。
#[implement(ICredentialProviderFilter)]
pub struct RdpMfaFilter;

impl ICredentialProviderFilter_Impl for RdpMfaFilter_Impl {
    fn Filter(
        &self,
        usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _flags: u32,
        providers: *const GUID,
        allow: *mut BOOL,
        provider_count: u32,
    ) -> Result<()> {
        if providers.is_null() || allow.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        // 只在登录/解锁场景过滤。其他场景保持系统默认行为，避免影响 CredUI/改密等流程。
        if !matches!(usage_scenario, CPUS_LOGON | CPUS_UNLOCK_WORKSTATION) {
            return Ok(());
        }

        let providers = unsafe {
            // SAFETY: LogonUI 传入 `provider_count` 个 Provider CLSID，指针已做非空检查。
            std::slice::from_raw_parts(providers, provider_count as usize)
        };
        let allow = unsafe {
            // SAFETY: LogonUI 传入 `provider_count` 个 BOOL 输出位，指针已做非空检查。
            std::slice::from_raw_parts_mut(allow, provider_count as usize)
        };

        let has_our_provider = providers
            .iter()
            .any(|provider| *provider == RDP_MFA_PROVIDER_CLSID);
        if !has_our_provider {
            // 如果系统这轮枚举里没有我们的 Provider，绝不隐藏其他 Provider，避免锁死登录。
            return Ok(());
        }

        for (provider, allow_provider) in providers.iter().zip(allow.iter_mut()) {
            *allow_provider = (*provider == RDP_MFA_PROVIDER_CLSID).into();
        }
        Ok(())
    }

    fn UpdateRemoteCredential(
        &self,
        input: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        if input.is_null() || output.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        // RDP/NLA 场景下系统可能要求 Filter 转换远程凭证。这里不解析凭证，只深拷贝并
        // 把 Provider CLSID 改成我们的 Provider，让后续 SetSerialization 能交给二次认证 Tile。
        let inbound = unsafe {
            // SAFETY: 指针来自 LogonUI，立即深拷贝，不保存原始指针。
            InboundSerialization::copy_from_raw(input)?
        };
        inbound.write_to(output)
    }
}
