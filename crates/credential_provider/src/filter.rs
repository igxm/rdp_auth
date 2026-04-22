//! Credential Provider Filter 实现。
//!
//! 仅注册 Provider 时，LogonUI 仍可能让系统默认 Password Provider 自动消费 RDP/NLA
//! 传入的凭证，用户就会直接进入桌面。这里把“远程 RDP 接管”和“本地控制台过滤”
//! 分开处理：RDP/NLA 优先走 `UpdateRemoteCredential` 重定向，本地登录默认不隐藏系统
//! Provider，避免影响管理员现场维护、PIN、Windows Hello 等正常入口。

use auth_config::LoginPolicy;
use auth_config::load_login_policy;
use windows::Win32::Foundation::E_POINTER;
use windows::Win32::UI::Shell::{
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProviderFilter, ICredentialProviderFilter_Impl,
};
use windows::core::{BOOL, Error, GUID, Result, implement};

use crate::diagnostics::log_event;
use crate::serialization::InboundSerialization;
use crate::session::is_current_rdp_session;
use crate::state::{RDP_MFA_PROVIDER_CLSID, remember_remote_source_provider};

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

        let providers = unsafe {
            // SAFETY: LogonUI 传入 `provider_count` 个 Provider CLSID，指针已做非空检查。
            std::slice::from_raw_parts(providers, provider_count as usize)
        };
        let allow = unsafe {
            // SAFETY: LogonUI 传入 `provider_count` 个 BOOL 输出位，指针已做非空检查。
            std::slice::from_raw_parts_mut(allow, provider_count as usize)
        };

        let policy = load_login_policy();
        let is_rdp_session = is_current_rdp_session();
        let filter_action = filter_action_for_scenario(policy, usage_scenario, is_rdp_session);
        let has_our_provider = providers
            .iter()
            .any(|provider| *provider == RDP_MFA_PROVIDER_CLSID);
        log_event(
            "Filter",
            format!(
                "provider_count={} has_our_provider={} policy={} is_rdp_session={} action={:?}",
                provider_count, has_our_provider, policy, is_rdp_session, filter_action
            ),
        );
        if matches!(
            filter_action,
            ProviderFilterAction::LeaveUnchanged | ProviderFilterAction::OnlyOurProvider
        ) && !has_our_provider
        {
            // 如果系统这轮枚举里没有我们的 Provider，绝不隐藏其他 Provider，避免锁死登录。
            return Ok(());
        }

        match filter_action {
            ProviderFilterAction::LeaveUnchanged => {}
            ProviderFilterAction::HideOurProvider => {
                for (provider, allow_provider) in providers.iter().zip(allow.iter_mut()) {
                    if *provider == RDP_MFA_PROVIDER_CLSID {
                        *allow_provider = false.into();
                    }
                }
            }
            ProviderFilterAction::OnlyOurProvider => {
                for (provider, allow_provider) in providers.iter().zip(allow.iter_mut()) {
                    *allow_provider = (*provider == RDP_MFA_PROVIDER_CLSID).into();
                }
            }
        }
        Ok(())
    }

    fn UpdateRemoteCredential(
        &self,
        input: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        if input.is_null() || output.is_null() {
            log_event("UpdateRemoteCredential", "null input_or_output");
            return Err(Error::from_hresult(E_POINTER));
        }

        let policy = load_login_policy();
        log_event(
            "UpdateRemoteCredential",
            format!(
                "called policy={} should_route_rdp={}",
                policy,
                policy.should_route_rdp()
            ),
        );
        if !policy.should_route_rdp() {
            // 应急禁用或关闭 RDP MFA 时，不改写远程凭证归属，交回系统默认 Provider 处理。
            // 这样管理员可以通过注册表开关快速恢复 RDP 登录测试环境。
            let inbound = unsafe {
                // SAFETY: 指针来自 LogonUI，立即深拷贝，不保存原始指针。
                InboundSerialization::copy_from_raw(input)?
            };
            log_event(
                "UpdateRemoteCredential",
                format!(
                    "bypass_route auth_package={} source_provider={:?} bytes_len={}",
                    inbound.authentication_package,
                    inbound.provider_clsid(),
                    inbound.bytes.len()
                ),
            );
            return inbound.write_to_with_provider(output, inbound.provider_clsid());
        }

        // RDP/NLA 场景下系统可能要求 Filter 转换远程凭证。这里不解析凭证，只深拷贝并
        // 把 Provider CLSID 改成我们的 Provider，让后续 SetSerialization 能交给二次认证 Tile。
        let inbound = unsafe {
            // SAFETY: 指针来自 LogonUI，立即深拷贝，不保存原始指针。
            InboundSerialization::copy_from_raw(input)?
        };
        log_event(
            "UpdateRemoteCredential",
            format!(
                "route_to_mfa auth_package={} source_provider={:?} target_provider={:?} bytes_len={}",
                inbound.authentication_package,
                inbound.provider_clsid(),
                RDP_MFA_PROVIDER_CLSID,
                inbound.bytes.len()
            ),
        );
        remember_remote_source_provider(inbound.provider_clsid());
        inbound.write_to_with_provider(output, RDP_MFA_PROVIDER_CLSID)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderFilterAction {
    LeaveUnchanged,
    HideOurProvider,
    OnlyOurProvider,
}

fn filter_action_for_scenario(
    policy: LoginPolicy,
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    is_rdp_session: bool,
) -> ProviderFilterAction {
    if !matches!(usage_scenario, CPUS_LOGON | CPUS_UNLOCK_WORKSTATION) {
        return ProviderFilterAction::LeaveUnchanged;
    }

    if policy.disable_mfa {
        return ProviderFilterAction::HideOurProvider;
    }

    if is_rdp_session {
        if policy.enable_rdp_mfa {
            ProviderFilterAction::OnlyOurProvider
        } else {
            ProviderFilterAction::HideOurProvider
        }
    } else if policy.enable_console_mfa {
        ProviderFilterAction::OnlyOurProvider
    } else {
        ProviderFilterAction::HideOurProvider
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderFilterAction, filter_action_for_scenario};
    use auth_config::LoginPolicy;
    use windows::Win32::UI::Shell::{CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION};

    #[test]
    fn rdp_logon_keeps_only_our_provider_when_rdp_mfa_is_enabled() {
        let policy = LoginPolicy {
            enable_rdp_mfa: true,
            enable_console_mfa: false,
            disable_mfa: false,
        };

        assert_eq!(
            filter_action_for_scenario(policy, CPUS_LOGON, true),
            ProviderFilterAction::OnlyOurProvider
        );
    }

    #[test]
    fn local_logon_hides_our_provider_by_default() {
        let policy = LoginPolicy {
            enable_rdp_mfa: true,
            enable_console_mfa: false,
            disable_mfa: false,
        };

        assert_eq!(
            filter_action_for_scenario(policy, CPUS_LOGON, false),
            ProviderFilterAction::HideOurProvider
        );
    }

    #[test]
    fn local_logon_keeps_only_our_provider_when_console_mfa_is_enabled() {
        let policy = LoginPolicy {
            enable_rdp_mfa: true,
            enable_console_mfa: true,
            disable_mfa: false,
        };

        assert_eq!(
            filter_action_for_scenario(policy, CPUS_UNLOCK_WORKSTATION, false),
            ProviderFilterAction::OnlyOurProvider
        );
    }

    #[test]
    fn disabled_mfa_hides_our_provider_and_keeps_system_providers() {
        let policy = LoginPolicy {
            enable_rdp_mfa: true,
            enable_console_mfa: true,
            disable_mfa: true,
        };

        assert_eq!(
            filter_action_for_scenario(policy, CPUS_LOGON, true),
            ProviderFilterAction::HideOurProvider
        );
        assert_eq!(
            filter_action_for_scenario(policy, CPUS_LOGON, false),
            ProviderFilterAction::HideOurProvider
        );
    }

    #[test]
    fn cred_ui_is_left_unchanged() {
        let policy = LoginPolicy {
            enable_rdp_mfa: true,
            enable_console_mfa: true,
            disable_mfa: false,
        };

        assert_eq!(
            filter_action_for_scenario(policy, CPUS_CREDUI, true),
            ProviderFilterAction::LeaveUnchanged
        );
    }
}
