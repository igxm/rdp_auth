//! `ICredentialProvider` 的最小实现。
//!
//! Provider 对象负责 LogonUI 的枚举生命周期：使用场景、字段描述符、Credential 数量和
//! Credential 实例创建。它不直接处理字段输入，也不做网络或 IPC。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_POINTER};
use windows::Win32::UI::Shell::{
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_NO_DEFAULT,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProvider, ICredentialProvider_Impl,
    ICredentialProviderCredential, ICredentialProviderEvents,
};
use windows::core::{BOOL, Error, Ref, Result, implement};

use crate::credential::RdpMfaCredential;
use crate::diagnostics::log_event;
use crate::fields::{FIELD_COUNT, field_descriptor};
use crate::helper_client::get_current_policy_snapshot;
use crate::serialization::InboundSerialization;
use crate::session::is_current_rdp_session;
use crate::state::{CredentialProviderState, RDP_MFA_PROVIDER_CLSID, take_remote_source_provider};
use crate::timeout::{start_mfa_timeout_timer, start_missing_serialization_disconnect_timer};

/// 最小 Credential Provider。
///
/// 这里用 `Mutex` 是因为 COM 可能从不同调用栈访问 Provider 状态；后续如果确认 LogonUI
/// 调用线程模型更细，可以再收窄锁范围。不要在持锁时做 IPC 或网络，避免登录界面死锁。
#[implement(ICredentialProvider)]
pub struct RdpMfaProvider {
    state: Arc<Mutex<CredentialProviderState>>,
}

impl Default for RdpMfaProvider {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(CredentialProviderState::default())),
        }
    }
}

impl ICredentialProvider_Impl for RdpMfaProvider_Impl {
    fn SetUsageScenario(
        &self,
        usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _flags: u32,
    ) -> Result<()> {
        match usage_scenario {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                log_event(
                    "SetUsageScenario",
                    format!("accepted usage_scenario={:?}", usage_scenario),
                );
                self.state
                    .lock()
                    .expect("provider state poisoned")
                    .usage_scenario = usage_scenario;
                Ok(())
            }
            // 当前目标是 RDP 登录后二次认证，所以改密、CredUI、PLAP 都先明确拒绝。
            _ => {
                log_event(
                    "SetUsageScenario",
                    format!("rejected usage_scenario={:?}", usage_scenario),
                );
                Err(Error::from_hresult(E_NOTIMPL))
            }
        }
    }

    fn SetSerialization(
        &self,
        serialization: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        let copied = if serialization.is_null() {
            log_event("SetSerialization", "called with null serialization");
            None
        } else {
            let mut copied = unsafe {
                // SAFETY: 指针来自 LogonUI 的 `SetSerialization` 调用，立即深拷贝，不保存原始指针。
                InboundSerialization::copy_from_raw(serialization)?
            };
            log_event(
                "SetSerialization",
                format!(
                    "copied auth_package={} source_provider={:?} bytes_len={}",
                    copied.authentication_package,
                    copied.source_provider,
                    copied.bytes.len()
                ),
            );
            if copied.source_provider == RDP_MFA_PROVIDER_CLSID {
                if let Some(source_provider) = take_remote_source_provider() {
                    log_event(
                        "SetSerialization",
                        format!(
                            "restored_source_provider from={:?} to={:?}",
                            RDP_MFA_PROVIDER_CLSID, source_provider
                        ),
                    );
                    copied.source_provider = source_provider;
                } else {
                    log_event(
                        "SetSerialization",
                        format!(
                            "missing_original_source_provider current_provider={:?}",
                            copied.source_provider
                        ),
                    );
                }
            }
            Some(copied)
        };

        let remote_logon_credential = copied
            .as_ref()
            .and_then(|inbound| match inbound.unpack_remote_logon_credential() {
                Ok(credential) => {
                    log_event(
                        "SetSerialization",
                        format!(
                            "unpacked_remote_credential username_chars={} domain_chars={} password_chars={}",
                            credential.username_len(),
                            credential.domain_len(),
                            credential.password_len()
                        ),
                    );
                    Some(credential)
                }
                Err(error) => {
                    log_event(
                        "SetSerialization",
                        format!("unpack_remote_credential_failed error={error}"),
                    );
                    None
                }
            });

        let mut state = self.state.lock().expect("provider state poisoned");
        state.has_inbound_serialization = copied.is_some();
        state.inbound_serialization = copied;
        state.remote_logon_credential = remote_logon_credential;
        if state.has_inbound_serialization {
            // 新的 RDP serialization 代表一次新的登录尝试；首次短信发送延长窗口的标记
            // 必须随之重置，否则上一轮 Tile 状态会影响下一轮 fail closed 超时策略。
            state.sms_sent_timeout_extended = false;
        }
        let should_start_timeout = state.has_inbound_serialization;
        log_event(
            "SetSerialization",
            format!(
                "state_updated has_inbound_serialization={} has_remote_logon_credential={}",
                state.has_inbound_serialization,
                state.remote_logon_credential.is_some()
            ),
        );
        drop(state);
        if should_start_timeout {
            start_mfa_timeout_timer(Arc::clone(&self.state));
        }
        Ok(())
    }

    fn Advise(
        &self,
        _events: Ref<ICredentialProviderEvents>,
        _advise_context: usize,
    ) -> Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        Ok(FIELD_COUNT)
    }

    fn GetFieldDescriptorAt(
        &self,
        index: u32,
    ) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        field_descriptor(index)
    }

    fn GetCredentialCount(
        &self,
        count: *mut u32,
        default: *mut u32,
        autologon_with_default: *mut BOOL,
    ) -> Result<()> {
        if count.is_null() || default.is_null() || autologon_with_default.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        unsafe {
            // SAFETY: LogonUI 传入的三个输出指针已做非空检查。
            *count = 1;
            *default = CREDENTIAL_PROVIDER_NO_DEFAULT;
            *autologon_with_default = false.into();
        }
        let should_guard_missing_inbound = {
            let state = self.state.lock().expect("provider state poisoned");
            !state.has_inbound_serialization && is_current_rdp_session()
        };
        if should_guard_missing_inbound {
            // 在 LogonUI 真正取 Credential 对象前先启动保护，尽量减少孤立 MFA Tile
            // 可见时间；如果随后 SetSerialization 到达，generation 会让该定时器自退。
            start_missing_serialization_disconnect_timer(Arc::clone(&self.state));
        }
        log_event("GetCredentialCount", "count=1 default=none autologon=false");
        Ok(())
    }

    fn GetCredentialAt(&self, index: u32) -> Result<ICredentialProviderCredential> {
        if index != 0 {
            log_event("GetCredentialAt", format!("invalid index={index}"));
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        refresh_policy_snapshot_from_helper(&self.state);
        let should_guard_missing_inbound = {
            let state = self.state.lock().expect("provider state poisoned");
            !state.has_inbound_serialization && is_current_rdp_session()
        };
        if should_guard_missing_inbound {
            // RDP 锁屏/注销后返回登录界面时，LogonUI 可能只枚举我们的 Tile，
            // 但不再提供新的 NLA 原始凭证。当前架构不保存首次登录密码，因此不能
            // 让用户停留在孤立 MFA 入口；给 SetSerialization 一个短暂机会后断开，
            // 迫使客户端重新发起 RDP/NLA 并重新提供一次凭证。
            start_missing_serialization_disconnect_timer(Arc::clone(&self.state));
        }
        log_event("GetCredentialAt", "returning credential index=0");
        Ok(RdpMfaCredential::new(Arc::clone(&self.state)).into())
    }
}

fn refresh_policy_snapshot_from_helper(state: &Arc<Mutex<CredentialProviderState>>) {
    let timeout_ms = {
        state
            .lock()
            .expect("provider state poisoned")
            .helper_ipc_timeout_ms
    };

    // 这里在不持有 Provider 状态锁时调用 helper，避免 LogonUI COM 调用栈和命名管道等待互相卡住。
    // helper 只返回脱敏策略快照；如果 helper 不可用，CP 保留本地配置/安全默认值，不能因此放行登录。
    match get_current_policy_snapshot(Duration::from_millis(timeout_ms)) {
        Ok(snapshot) => {
            let method_count = snapshot.auth_methods.len();
            let phone_editable = snapshot.phone_editable;
            let has_masked_phone = snapshot.masked_phone.is_some();
            state
                .lock()
                .expect("provider state poisoned")
                .apply_policy_snapshot(&snapshot);
            log_event(
                "GetPolicySnapshot",
                format!(
                    "applied method_count={method_count} phone_editable={phone_editable} has_masked_phone={has_masked_phone}"
                ),
            );
        }
        Err(error) => log_event("GetPolicySnapshot", format!("failed error={error}")),
    }
}
