//! 单个 Credential Tile 的最小实现。
//!
//! Credential 对象负责字段值、用户交互和 `GetSerialization`。阶段 2 只返回一个说明性
//! 文本字段，不交出任何凭证；阶段 3 会在这里接入原始 RDP 凭证的返回逻辑。

use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{E_NOTIMPL, E_POINTER, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{
    CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPGSR_NO_CREDENTIAL_NOT_FINISHED,
    CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
    ICredentialProviderCredential, ICredentialProviderCredential_Impl,
    ICredentialProviderCredentialEvents,
};
use windows::core::{BOOL, Error, PCWSTR, PWSTR, Ref, Result, implement};

use crate::fields::FIELD_STATUS;
use crate::memory::alloc_wide_string;
use crate::state::CredentialProviderState;

/// 最小 Credential 对象。
#[implement(ICredentialProviderCredential)]
pub struct RdpMfaCredential {
    state: Arc<Mutex<CredentialProviderState>>,
}

impl RdpMfaCredential {
    /// 创建 Credential Tile，并共享 Provider 在 `SetSerialization` 中缓存的原始凭证。
    pub fn new(state: Arc<Mutex<CredentialProviderState>>) -> Self {
        Self { state }
    }
}

impl ICredentialProviderCredential_Impl for RdpMfaCredential_Impl {
    fn Advise(&self, _events: Ref<ICredentialProviderCredentialEvents>) -> Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }

    fn SetSelected(&self) -> Result<BOOL> {
        Ok(false.into())
    }

    fn SetDeselected(&self) -> Result<()> {
        Ok(())
    }

    fn GetFieldState(
        &self,
        field_id: u32,
        field_state: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        interactive_state: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> Result<()> {
        if field_id != FIELD_STATUS || field_state.is_null() || interactive_state.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }
        unsafe {
            // SAFETY: 两个输出指针已做非空检查，字段 ID 也已限制在当前最小字段集合内。
            *field_state = CPFS_DISPLAY_IN_BOTH;
            *interactive_state = CPFIS_NONE;
        }
        Ok(())
    }

    fn GetStringValue(&self, field_id: u32) -> Result<PWSTR> {
        if field_id != FIELD_STATUS {
            return Err(Error::from_hresult(E_POINTER));
        }
        alloc_wide_string("RDP 二次认证")
    }

    fn GetBitmapValue(&self, _field_id: u32) -> Result<HBITMAP> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetCheckboxValue(
        &self,
        _field_id: u32,
        _checked: *mut BOOL,
        _label: *mut PWSTR,
    ) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetSubmitButtonValue(&self, _field_id: u32) -> Result<u32> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetComboBoxValueCount(
        &self,
        _field_id: u32,
        _items: *mut u32,
        _selected_item: *mut u32,
    ) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetComboBoxValueAt(&self, _field_id: u32, _item: u32) -> Result<PWSTR> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn SetStringValue(&self, _field_id: u32, _value: &PCWSTR) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn SetCheckboxValue(&self, _field_id: u32, _checked: BOOL) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn SetComboBoxSelectedValue(&self, _field_id: u32, _selected_item: u32) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn CommandLinkClicked(&self, _field_id: u32) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn GetSerialization(
        &self,
        response: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        serialization: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        status_text: *mut PWSTR,
        status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        if response.is_null() || serialization.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let state = self.state.lock().expect("credential state poisoned");
        let can_return =
            state.mfa_state.allows_serialization() || state.allow_passthrough_without_mfa;
        let Some(inbound) = state.inbound_serialization.as_ref() else {
            unsafe {
                // SAFETY: `response` 已做非空检查；没有原始凭证时必须拒绝交出凭证。
                *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                if !status_icon.is_null() {
                    *status_icon = CPSI_ERROR;
                }
                if !status_text.is_null() {
                    *status_text = alloc_wide_string("未收到 RDP 原始凭证，无法继续登录")?;
                }
            }
            return Ok(());
        };

        if !can_return {
            unsafe {
                // SAFETY: `response` 已做非空检查；MFA 未通过时保持在当前 Tile。
                *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            }
            return Ok(());
        }

        // Credential Provider 在 CPUS_LOGON/UNLOCK 场景下不直接调用 LsaLogonUser。
        // 正确边界是把序列化凭证交给 LogonUI/Winlogon，由系统继续交给 LSA；这样才能
        // 保持 Windows 登录审计、策略和错误处理都走系统原生链路。
        inbound.write_to(serialization)?;
        unsafe {
            // SAFETY: `response` 已做非空检查；`serialization` 已由 `write_to` 填充。
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        Ok(())
    }

    fn ReportResult(
        &self,
        _status: NTSTATUS,
        _sub_status: NTSTATUS,
        _status_text: *mut PWSTR,
        _status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        Ok(())
    }
}
