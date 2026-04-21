//! 单个 Credential Tile 的最小实现。
//!
//! Credential 对象负责字段值、用户交互和 `GetSerialization`。阶段 2 只返回一个说明性
//! 文本字段，不交出任何凭证；阶段 3 会在这里接入原始 RDP 凭证的返回逻辑。

use std::sync::{Arc, Mutex};

use auth_core::{AuthMethod, MfaState};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_POINTER, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{
    CPFIS_DISABLED, CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE,
    CPFS_HIDDEN, CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON, ICredentialProviderCredential,
    ICredentialProviderCredential_Impl, ICredentialProviderCredentialEvents,
};
use windows::core::{BOOL, Error, IUnknownImpl, PCWSTR, PWSTR, Ref, Result, implement};

use crate::fields::MfaField;
use crate::memory::alloc_wide_string;
use crate::state::CredentialProviderState;

const AUTH_METHOD_LABELS: [&str; 3] = ["手机验证码", "二次密码", "微信扫码（预留）"];

/// 最小 Credential 对象。
#[implement(ICredentialProviderCredential)]
pub struct RdpMfaCredential {
    state: Arc<Mutex<CredentialProviderState>>,
    events: Arc<Mutex<Option<ICredentialProviderCredentialEvents>>>,
}

impl RdpMfaCredential {
    /// 创建 Credential Tile，并共享 Provider 在 `SetSerialization` 中缓存的原始凭证。
    pub fn new(state: Arc<Mutex<CredentialProviderState>>) -> Self {
        Self {
            state,
            events: Arc::new(Mutex::new(None)),
        }
    }
}

impl RdpMfaCredential_Impl {
    fn refresh_visible_fields(&self) -> Result<()> {
        let events = self
            .events
            .lock()
            .expect("credential events poisoned")
            .clone();
        let Some(events) = events else {
            return Ok(());
        };

        let credential = self.to_interface::<ICredentialProviderCredential>();
        let state = self
            .state
            .lock()
            .expect("credential state poisoned")
            .clone();
        for field_id in 0..MfaField::COUNT {
            let Some(field) = MfaField::from_id(field_id) else {
                continue;
            };
            let (field_state, interactive_state) = field_visibility(field, &state);
            unsafe {
                // SAFETY: `credential` 是当前 COM 对象的接口指针；events 由 LogonUI
                // 在 `Advise` 中提供。切换认证方式或按钮状态后必须主动通知 LogonUI，
                // 否则它可能继续显示旧字段，造成 UI 不同步。
                events.SetFieldState(&credential, field_id, field_state)?;
                events.SetFieldInteractiveState(&credential, field_id, interactive_state)?;
            }
        }

        let send_sms_label = wide_null(send_sms_label(&state));
        unsafe {
            // SAFETY: `SetFieldString` 同步读取字符串；临时宽字符串在调用结束前有效。
            events.SetFieldString(
                &credential,
                MfaField::SendSms as u32,
                PCWSTR(send_sms_label.as_ptr()),
            )?;
        }
        Ok(())
    }
}

impl ICredentialProviderCredential_Impl for RdpMfaCredential_Impl {
    fn Advise(&self, events: Ref<ICredentialProviderCredentialEvents>) -> Result<()> {
        *self.events.lock().expect("credential events poisoned") = events.cloned();
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        *self.events.lock().expect("credential events poisoned") = None;
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
        if field_state.is_null() || interactive_state.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }
        let Some(field) = MfaField::from_id(field_id) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let state = self.state.lock().expect("credential state poisoned");
        let (visible_state, input_state) = field_visibility(field, &state);
        unsafe {
            // SAFETY: 两个输出指针已做非空检查，字段 ID 也已限制在当前字段集合内。
            *field_state = visible_state;
            *interactive_state = input_state;
        }
        Ok(())
    }

    fn GetStringValue(&self, field_id: u32) -> Result<PWSTR> {
        let Some(field) = MfaField::from_id(field_id) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let state = self.state.lock().expect("credential state poisoned");
        let value = match field {
            MfaField::Title => "RDP 二次认证",
            MfaField::AuthMethod => auth_method_label(state.selected_method),
            MfaField::Phone => state.phone.as_str(),
            MfaField::SmsCode => state.sms_code.as_str(),
            MfaField::SendSms => send_sms_label(&state),
            MfaField::SecondPassword => state.second_password.as_str(),
            MfaField::WechatNotice => "微信扫码认证已预留，当前版本暂未接入。",
            MfaField::Submit => "登录",
            MfaField::Cancel => "取消",
            MfaField::Status => status_text(&state),
        };
        alloc_wide_string(value)
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

    fn GetSubmitButtonValue(&self, field_id: u32) -> Result<u32> {
        if field_id != MfaField::Submit as u32 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        Ok(MfaField::Status as u32)
    }

    fn GetComboBoxValueCount(
        &self,
        field_id: u32,
        _items: *mut u32,
        _selected_item: *mut u32,
    ) -> Result<()> {
        if field_id != MfaField::AuthMethod as u32 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        if _items.is_null() || _selected_item.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let state = self.state.lock().expect("credential state poisoned");
        unsafe {
            // SAFETY: 两个输出指针已做非空检查，组合框固定提供三种认证方式。
            *_items = AUTH_METHOD_LABELS.len() as u32;
            *_selected_item = auth_method_index(state.selected_method);
        }
        Ok(())
    }

    fn GetComboBoxValueAt(&self, field_id: u32, item: u32) -> Result<PWSTR> {
        if field_id != MfaField::AuthMethod as u32 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let Some(label) = AUTH_METHOD_LABELS.get(item as usize) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };
        alloc_wide_string(label)
    }

    fn SetStringValue(&self, field_id: u32, value: &PCWSTR) -> Result<()> {
        let Some(field) = MfaField::from_id(field_id) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };
        let value = unsafe {
            // SAFETY: LogonUI 传入的是以 NUL 结尾的只读宽字符串；这里立即复制到 Rust String。
            value.to_string().unwrap_or_default()
        };

        let mut state = self.state.lock().expect("credential state poisoned");
        match field {
            MfaField::Phone => state.phone = value,
            MfaField::SmsCode => state.sms_code = value,
            MfaField::SecondPassword => state.second_password = value,
            _ => return Err(Error::from_hresult(E_INVALIDARG)),
        }
        Ok(())
    }

    fn SetCheckboxValue(&self, _field_id: u32, _checked: BOOL) -> Result<()> {
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn SetComboBoxSelectedValue(&self, field_id: u32, selected_item: u32) -> Result<()> {
        if field_id != MfaField::AuthMethod as u32 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let Some(method) = auth_method_from_index(selected_item) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let mut state = self.state.lock().expect("credential state poisoned");
        state.selected_method = method;
        state.status_message = match method {
            AuthMethod::PhoneCode => "请输入手机号并发送验证码".to_owned(),
            AuthMethod::SecondPassword => "请输入二次密码".to_owned(),
            AuthMethod::Wechat => "微信扫码认证暂未接入，请选择其他方式".to_owned(),
        };
        drop(state);
        self.refresh_visible_fields()?;
        Ok(())
    }

    fn CommandLinkClicked(&self, field_id: u32) -> Result<()> {
        let Some(field) = MfaField::from_id(field_id) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let mut state = self.state.lock().expect("credential state poisoned");
        match field {
            MfaField::SendSms => {
                if state.sms_resend_remaining > 0 {
                    return Ok(());
                }
                // helper 接入前先只更新 UI 状态，不在 LogonUI 进程里做网络请求。
                state.mfa_state = MfaState::WaitingInput;
                state.sms_resend_remaining = 60;
                state.status_message = "验证码已发送，请输入短信验证码".to_owned();
                drop(state);
                self.refresh_visible_fields()
            }
            MfaField::Cancel => {
                state.mfa_state = MfaState::Failed("用户取消二次认证".to_owned());
                state.status_message = "已取消二次认证".to_owned();
                drop(state);
                self.refresh_visible_fields()
            }
            _ => Err(Error::from_hresult(E_INVALIDARG)),
        }
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

fn field_visibility(
    field: MfaField,
    state: &CredentialProviderState,
) -> (
    CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
) {
    match field {
        MfaField::Title => (CPFS_DISPLAY_IN_BOTH, CPFIS_NONE),
        MfaField::AuthMethod => (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED),
        MfaField::Phone | MfaField::SmsCode | MfaField::SendSms
            if state.selected_method == AuthMethod::PhoneCode =>
        {
            let interactive_state = if field == MfaField::SendSms && state.sms_resend_remaining > 0
            {
                CPFIS_DISABLED
            } else {
                CPFIS_NONE
            };
            (CPFS_DISPLAY_IN_SELECTED_TILE, interactive_state)
        }
        MfaField::SecondPassword if state.selected_method == AuthMethod::SecondPassword => {
            (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED)
        }
        MfaField::WechatNotice if state.selected_method == AuthMethod::Wechat => {
            (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_DISABLED)
        }
        MfaField::Submit | MfaField::Cancel => (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE),
        MfaField::Status => (CPFS_HIDDEN, CPFIS_NONE),
        _ => (CPFS_HIDDEN, CPFIS_NONE),
    }
}

fn auth_method_index(method: AuthMethod) -> u32 {
    match method {
        AuthMethod::PhoneCode => 0,
        AuthMethod::SecondPassword => 1,
        AuthMethod::Wechat => 2,
    }
}

fn auth_method_from_index(index: u32) -> Option<AuthMethod> {
    match index {
        0 => Some(AuthMethod::PhoneCode),
        1 => Some(AuthMethod::SecondPassword),
        2 => Some(AuthMethod::Wechat),
        _ => None,
    }
}

fn auth_method_label(method: AuthMethod) -> &'static str {
    AUTH_METHOD_LABELS[auth_method_index(method) as usize]
}

fn status_text(state: &CredentialProviderState) -> &str {
    match &state.mfa_state {
        MfaState::Failed(message) => message.as_str(),
        _ => state.status_message.as_str(),
    }
}

fn send_sms_label(state: &CredentialProviderState) -> &str {
    if state.sms_resend_remaining > 0 {
        "重新发送(60)"
    } else {
        "发送验证码"
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{auth_method_from_index, auth_method_index, field_visibility, send_sms_label};
    use crate::fields::MfaField;
    use crate::state::CredentialProviderState;
    use auth_core::AuthMethod;
    use windows::Win32::UI::Shell::{CPFIS_DISABLED, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN};

    #[test]
    fn auth_method_indices_are_stable_for_combobox() {
        assert_eq!(auth_method_index(AuthMethod::PhoneCode), 0);
        assert_eq!(auth_method_index(AuthMethod::SecondPassword), 1);
        assert_eq!(auth_method_index(AuthMethod::Wechat), 2);
        assert_eq!(auth_method_from_index(0), Some(AuthMethod::PhoneCode));
        assert_eq!(auth_method_from_index(1), Some(AuthMethod::SecondPassword));
        assert_eq!(auth_method_from_index(2), Some(AuthMethod::Wechat));
        assert_eq!(auth_method_from_index(3), None);
    }

    #[test]
    fn phone_fields_only_show_for_phone_method() {
        let mut state = CredentialProviderState::default();
        state.selected_method = AuthMethod::PhoneCode;
        assert_eq!(
            field_visibility(MfaField::Phone, &state).0,
            CPFS_DISPLAY_IN_SELECTED_TILE
        );
        state.selected_method = AuthMethod::SecondPassword;
        assert_eq!(field_visibility(MfaField::Phone, &state).0, CPFS_HIDDEN);
    }

    #[test]
    fn second_password_field_only_shows_for_password_method() {
        let mut state = CredentialProviderState::default();
        state.selected_method = AuthMethod::SecondPassword;
        assert_eq!(
            field_visibility(MfaField::SecondPassword, &state).0,
            CPFS_DISPLAY_IN_SELECTED_TILE
        );
        state.selected_method = AuthMethod::PhoneCode;
        assert_eq!(
            field_visibility(MfaField::SecondPassword, &state).0,
            CPFS_HIDDEN
        );
    }

    #[test]
    fn sms_button_is_disabled_during_resend_window() {
        let mut state = CredentialProviderState::default();
        state.sms_resend_remaining = 60;

        assert_eq!(send_sms_label(&state), "重新发送(60)");
        assert_eq!(
            field_visibility(MfaField::SendSms, &state).1,
            CPFIS_DISABLED
        );
    }

    #[test]
    fn status_field_is_hidden_to_remove_duplicate_second_section() {
        let state = CredentialProviderState::default();

        assert_eq!(field_visibility(MfaField::Status, &state).0, CPFS_HIDDEN);
    }
}
