//! 单个 Credential Tile 的最小实现。
//!
//! Credential 对象负责字段值、用户交互和 `GetSerialization`。阶段 2 只返回一个说明性
//! 文本字段，不交出任何凭证；阶段 3 会在这里接入原始 RDP 凭证的返回逻辑。

use std::sync::Mutex;

use auth_core::MfaState;
use windows::Win32::Foundation::{E_NOTIMPL, E_POINTER, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{
    CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPGSR_NO_CREDENTIAL_NOT_FINISHED,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON, ICredentialProviderCredential,
    ICredentialProviderCredential_Impl, ICredentialProviderCredentialEvents,
};
use windows::core::{BOOL, Error, PCWSTR, PWSTR, Ref, Result, implement};

use crate::fields::FIELD_STATUS;
use crate::memory::alloc_wide_string;

/// 最小 Credential 对象。
#[implement(ICredentialProviderCredential)]
pub struct RdpMfaCredential {
    state: Mutex<MfaState>,
}

impl Default for RdpMfaCredential {
    fn default() -> Self {
        Self {
            state: Mutex::new(MfaState::Idle),
        }
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
        _serialization: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _status_text: *mut PWSTR,
        _status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        if response.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        unsafe {
            // SAFETY: `response` 已做非空检查。阶段 2 还不交出凭证，只让 Tile 能被枚举。
            *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        }
        let mut state = self.state.lock().expect("credential state poisoned");
        *state = MfaState::Idle;
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
