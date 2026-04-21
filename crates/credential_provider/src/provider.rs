//! `ICredentialProvider` 的最小实现。
//!
//! Provider 对象负责 LogonUI 的枚举生命周期：使用场景、字段描述符、Credential 数量和
//! Credential 实例创建。它不直接处理字段输入，也不做网络或 IPC。

use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_POINTER};
use windows::Win32::UI::Shell::{
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_NO_DEFAULT,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProvider, ICredentialProvider_Impl,
    ICredentialProviderCredential, ICredentialProviderEvents,
};
use windows::core::{BOOL, Error, Ref, Result, implement};

use crate::credential::RdpMfaCredential;
use crate::fields::{FIELD_COUNT, field_descriptor};
use crate::serialization::InboundSerialization;
use crate::state::CredentialProviderState;

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
                self.state
                    .lock()
                    .expect("provider state poisoned")
                    .usage_scenario = usage_scenario;
                Ok(())
            }
            // 当前目标是 RDP 登录后二次认证，所以改密、CredUI、PLAP 都先明确拒绝。
            _ => Err(Error::from_hresult(E_NOTIMPL)),
        }
    }

    fn SetSerialization(
        &self,
        serialization: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        let copied = if serialization.is_null() {
            None
        } else {
            Some(unsafe {
                // SAFETY: 指针来自 LogonUI 的 `SetSerialization` 调用，立即深拷贝，不保存原始指针。
                InboundSerialization::copy_from_raw(serialization)?
            })
        };

        let mut state = self.state.lock().expect("provider state poisoned");
        state.has_inbound_serialization = copied.is_some();
        state.inbound_serialization = copied;
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
        Ok(())
    }

    fn GetCredentialAt(&self, index: u32) -> Result<ICredentialProviderCredential> {
        if index != 0 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        Ok(RdpMfaCredential::new(Arc::clone(&self.state)).into())
    }
}
