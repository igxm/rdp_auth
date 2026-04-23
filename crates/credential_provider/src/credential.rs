//! 单个 Credential Tile 的最小实现。
//!
//! Credential 对象负责字段值、用户交互和 `GetSerialization`。阶段 2 只返回一个说明性
//! 文本字段，不交出任何凭证；阶段 3 会在这里接入原始 RDP 凭证的返回逻辑。

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

use crate::diagnostics::log_event;
use crate::fields::MfaField;
use crate::helper_client::{log_mark_result, mark_current_session_authenticated};
use crate::memory::alloc_wide_string;
use crate::session::disconnect_current_session;
use crate::state::{CredentialProviderState, RDP_MFA_PROVIDER_CLSID};

const MOCK_SMS_CODE: &str = "123456";
const MOCK_SECOND_PASSWORD: &str = "mock-password";

/// 最小 Credential 对象。
#[implement(ICredentialProviderCredential)]
pub struct RdpMfaCredential {
    state: Arc<Mutex<CredentialProviderState>>,
    events: Arc<Mutex<Option<ICredentialProviderCredentialEvents>>>,
}

struct SendCom<T>(T);

// SAFETY: 这里只用于短信倒计时线程调用 LogonUI 提供的字段刷新接口，刷新失败会被记录并忽略。
// Credential Provider 的主认证状态仍由 Mutex 保护，不能把该包装扩展为通用跨线程 COM 访问模型。
unsafe impl<T> Send for SendCom<T> {}

impl<T> SendCom<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
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

        let send_sms_label = wide_null(&send_sms_label_owned(&state));
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

    fn start_sms_resend_countdown(&self, generation: u64) {
        let state = Arc::clone(&self.state);
        let events = self
            .events
            .lock()
            .expect("credential events poisoned")
            .clone();
        let Some(events) = events else {
            log_event(
                "SmsCountdown",
                format!("timer_skipped_no_events generation={generation}"),
            );
            return;
        };
        let events = SendCom(events);
        let credential = SendCom(self.to_interface::<ICredentialProviderCredential>());

        let spawn_result = thread::Builder::new()
            .name("rdp_auth_sms_resend".to_owned())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    let state_snapshot = {
                        let mut state = state.lock().expect("credential state poisoned");
                        if state.sms_resend_generation != generation {
                            log_event(
                                "SmsCountdown",
                                format!(
                                    "timer_stale generation={} current_generation={}",
                                    generation, state.sms_resend_generation
                                ),
                            );
                            return;
                        }
                        if state.sms_resend_remaining == 0 {
                            log_event(
                                "SmsCountdown",
                                format!("timer_completed generation={generation}"),
                            );
                            return;
                        }
                        state.sms_resend_remaining -= 1;
                        log_event(
                            "SmsCountdown",
                            format!(
                                "tick generation={} remaining={}",
                                generation, state.sms_resend_remaining
                            ),
                        );
                        state.clone()
                    };

                    if let Err(error) = refresh_send_sms_field(
                        events.as_ref(),
                        credential.as_ref(),
                        &state_snapshot,
                    ) {
                        log_event(
                            "SmsCountdown",
                            format!("refresh_failed generation={generation} error={error}"),
                        );
                    }
                }
            });

        if let Err(error) = spawn_result {
            log_event(
                "SmsCountdown",
                format!("timer_spawn_failed generation={generation} error={error}"),
            );
        }
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
        if field == MfaField::SendSms {
            return alloc_wide_string(&send_sms_label_owned(&state));
        }
        let value = match field {
            MfaField::Title => "RDP 二次认证",
            MfaField::AuthMethod => auth_method_label(state.selected_method),
            MfaField::Phone => state.phone.as_str(),
            MfaField::SmsCode => state.sms_code.as_str(),
            MfaField::SendSms => unreachable!("SendSms is handled before the static label match"),
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
            // SAFETY: 两个输出指针已做非空检查；认证方式列表来自归一化后的配置，至少有一个安全默认项。
            *_items = state.available_auth_methods.len() as u32;
            *_selected_item = auth_method_selected_index(&state);
        }
        Ok(())
    }

    fn GetComboBoxValueAt(&self, field_id: u32, item: u32) -> Result<PWSTR> {
        if field_id != MfaField::AuthMethod as u32 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let state = self.state.lock().expect("credential state poisoned");
        let Some(method) = state.available_auth_methods.get(item as usize).copied() else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };
        alloc_wide_string(auth_method_label(method))
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
            MfaField::Phone => {
                if !state.phone_editable {
                    log_event("SetStringValue", "field=Phone ignored_readonly_policy");
                    return Ok(());
                }
                log_event(
                    "SetStringValue",
                    format!("field=Phone chars={}", value.chars().count()),
                );
                state.phone = value;
            }
            MfaField::SmsCode => {
                log_event(
                    "SetStringValue",
                    format!("field=SmsCode chars={}", value.chars().count()),
                );
                state.sms_code = value;
            }
            MfaField::SecondPassword => {
                log_event(
                    "SetStringValue",
                    format!("field=SecondPassword chars={}", value.chars().count()),
                );
                state.second_password = value;
            }
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
        let state_snapshot = self
            .state
            .lock()
            .expect("credential state poisoned")
            .clone();
        let Some(method) = state_snapshot
            .available_auth_methods
            .get(selected_item as usize)
            .copied()
        else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let mut state = self.state.lock().expect("credential state poisoned");
        state.selected_method = method;
        log_event(
            "SetComboBoxSelectedValue",
            format!(
                "selected_method={:?} selected_item={}",
                method, selected_item
            ),
        );
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
                    log_event(
                        "CommandLinkClicked",
                        format!("send_sms_ignored remaining={}", state.sms_resend_remaining),
                    );
                    return Ok(());
                }
                // helper 接入前先只更新 UI 状态，不在 LogonUI 进程里做网络请求。CP DLL
                // 被 LogonUI 加载，网络超时、TLS 初始化或服务端卡顿都会卡住登录界面；真实短信发送必须
                // 放到 remote_auth helper，通过短超时 IPC 返回可展示结果，失败时按 fail closed 处理。
                state.mfa_state = MfaState::WaitingInput;
                state.sms_resend_remaining = state.sms_resend_seconds;
                state.sms_resend_generation = state.sms_resend_generation.wrapping_add(1);
                if state.sms_resend_generation == 0 {
                    state.sms_resend_generation = 1;
                }
                let generation = state.sms_resend_generation;
                let remaining = state.sms_resend_remaining;
                state.status_message = "验证码已发送，请输入短信验证码".to_owned();
                log_event(
                    "CommandLinkClicked",
                    format!("send_sms_mock remaining={remaining} generation={generation}"),
                );
                drop(state);
                self.refresh_visible_fields()?;
                self.start_sms_resend_countdown(generation);
                Ok(())
            }
            MfaField::Cancel => {
                state.mfa_state = MfaState::Failed("用户取消二次认证".to_owned());
                state.status_message = "已取消二次认证".to_owned();
                log_event(
                    "CommandLinkClicked",
                    "cancel_clicked disconnect_current_session",
                );
                drop(state);
                self.refresh_visible_fields()?;
                // 取消按钮在 RDP 登录场景中应结束这次远程登录尝试。这里走
                // WTSDisconnectSession 断开当前会话，而不是返回伪造凭证或假装登录失败。
                // 如果 API 调用失败，保持 Credential Tile 可用，避免因为取消路径再次锁住界面。
                let _ = disconnect_current_session();
                Ok(())
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

        let mut state = self.state.lock().expect("credential state poisoned");
        log_event(
            "GetSerialization",
            format!(
                "start mfa_state={:?} has_inbound={} allow_passthrough={} selected_method={:?}",
                state.mfa_state,
                state.has_inbound_serialization,
                state.allow_passthrough_without_mfa,
                state.selected_method
            ),
        );
        if !state.mfa_state.allows_serialization() && !state.allow_passthrough_without_mfa {
            match verify_mock_mfa(&mut state) {
                Ok(()) => {
                    log_event(
                        "GetSerialization",
                        format!("mock_verified selected_method={:?}", state.selected_method),
                    );
                }
                Err(message) => {
                    log_event(
                        "GetSerialization",
                        format!(
                            "mock_rejected selected_method={:?} reason={}",
                            state.selected_method, message
                        ),
                    );
                    unsafe {
                        // SAFETY: `response` 已做非空检查；mock 认证失败时不能交出凭证。
                        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                        if !status_icon.is_null() {
                            *status_icon = CPSI_ERROR;
                        }
                        if !status_text.is_null() {
                            *status_text = alloc_wide_string(message)?;
                        }
                    }
                    return Ok(());
                }
            }
        }

        let can_return =
            state.mfa_state.allows_serialization() || state.allow_passthrough_without_mfa;
        let Some(remote_logon_credential) = state.remote_logon_credential.as_ref().cloned() else {
            log_event("GetSerialization", "missing_inbound_serialization");
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
            log_event("GetSerialization", "mfa_not_ready_no_credential");
            unsafe {
                // SAFETY: `response` 已做非空检查；MFA 未通过时保持在当前 Tile。
                *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            }
            return Ok(());
        }

        // Credential Provider 在 CPUS_LOGON/UNLOCK 场景下不直接调用 LsaLogonUser。
        // 正确边界是把序列化凭证交给 LogonUI/Winlogon，由系统继续交给 LSA；这样才能
        // 保持 Windows 登录审计、策略和错误处理都走系统原生链路。
        let usage_scenario = state.usage_scenario;
        drop(state);
        let packed = match remote_logon_credential
            .pack_for_logon(RDP_MFA_PROVIDER_CLSID, usage_scenario)
        {
            Ok(packed) => packed,
            Err(error) => {
                log_event(
                    "GetSerialization",
                    format!("pack_remote_credential_failed error={error}"),
                );
                unsafe {
                    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                    if !status_icon.is_null() {
                        *status_icon = CPSI_ERROR;
                    }
                    if !status_text.is_null() {
                        *status_text = alloc_wide_string("RDP 原始凭证重新打包失败，无法继续登录")?;
                    }
                }
                return Ok(());
            }
        };
        log_event(
            "GetSerialization",
            format!(
                "returning_packed_logon auth_package={} source_provider={:?} bytes_len={}",
                packed.authentication_package,
                packed.source_provider,
                packed.bytes.len()
            ),
        );
        packed.write_to(serialization)?;
        unsafe {
            // SAFETY: `response` 已做非空检查；`serialization` 已由 `write_to` 填充。
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        Ok(())
    }

    fn ReportResult(
        &self,
        status: NTSTATUS,
        sub_status: NTSTATUS,
        _status_text: *mut PWSTR,
        _status_icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        log_event(
            "ReportResult",
            format!(
                "status=0x{:08X} sub_status=0x{:08X}",
                status.0, sub_status.0
            ),
        );
        if status.0 == 0 {
            let timeout_ms = {
                self.state
                    .lock()
                    .expect("credential state poisoned")
                    .helper_ipc_timeout_ms
            };
            log_mark_result(mark_current_session_authenticated(Duration::from_millis(
                timeout_ms,
            )));
        }
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
            let interactive_state = if field == MfaField::Phone && !state.phone_editable {
                CPFIS_DISABLED
            } else if field == MfaField::SendSms && state.sms_resend_remaining > 0 {
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

#[cfg(test)]
fn auth_method_index(method: AuthMethod) -> u32 {
    match method {
        AuthMethod::PhoneCode => 0,
        AuthMethod::SecondPassword => 1,
        AuthMethod::Wechat => 2,
    }
}

fn auth_method_selected_index(state: &CredentialProviderState) -> u32 {
    state
        .available_auth_methods
        .iter()
        .position(|method| *method == state.selected_method)
        .unwrap_or(0) as u32
}

fn auth_method_label(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::PhoneCode => "手机验证码",
        AuthMethod::SecondPassword => "二次密码",
        AuthMethod::Wechat => "微信扫码（预留）",
    }
}

fn status_text(state: &CredentialProviderState) -> &str {
    match &state.mfa_state {
        MfaState::Failed(message) => message.as_str(),
        _ => state.status_message.as_str(),
    }
}

fn verify_mock_mfa(state: &mut CredentialProviderState) -> std::result::Result<(), &'static str> {
    if !state
        .available_auth_methods
        .contains(&state.selected_method)
    {
        state.mfa_state = MfaState::Failed("当前认证方式已被配置禁用".to_owned());
        state.status_message = "当前认证方式已被配置禁用".to_owned();
        return Err("当前认证方式已被配置禁用");
    }
    state.mfa_state = MfaState::Verifying;
    let result = match state.selected_method {
        AuthMethod::PhoneCode => {
            if state.phone.trim().is_empty() {
                Err("请输入手机号")
            } else if state.sms_code.trim() == MOCK_SMS_CODE {
                Ok(())
            } else {
                Err("短信验证码错误，测试验证码为 123456")
            }
        }
        AuthMethod::SecondPassword => {
            if state.second_password == MOCK_SECOND_PASSWORD {
                Ok(())
            } else {
                Err("二次密码错误，测试密码为 mock-password")
            }
        }
        AuthMethod::Wechat => Err("微信扫码认证暂未接入，请选择手机验证码或二次密码"),
    };

    match result {
        Ok(()) => {
            state.mfa_state = MfaState::Verified;
            state.status_message = "mock 二次认证通过".to_owned();
            Ok(())
        }
        Err(message) => {
            state.mfa_state = MfaState::Failed(message.to_owned());
            state.status_message = message.to_owned();
            Err(message)
        }
    }
}

fn send_sms_label_owned(state: &CredentialProviderState) -> String {
    if state.sms_resend_remaining > 0 {
        format!("重新发送({})", state.sms_resend_remaining)
    } else {
        "发送验证码".to_owned()
    }
}

fn refresh_send_sms_field(
    events: &ICredentialProviderCredentialEvents,
    credential: &ICredentialProviderCredential,
    state: &CredentialProviderState,
) -> Result<()> {
    let label = wide_null(&send_sms_label_owned(state));
    let (_, interactive_state) = field_visibility(MfaField::SendSms, state);
    unsafe {
        // SAFETY: events 由 LogonUI 提供；字符串在同步调用期间有效。这里只刷新发送短信按钮，
        // 避免后台倒计时线程触碰其他输入字段或重排整个 Tile。
        events.SetFieldString(credential, MfaField::SendSms as u32, PCWSTR(label.as_ptr()))?;
        events.SetFieldInteractiveState(credential, MfaField::SendSms as u32, interactive_state)?;
    }
    Ok(())
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{MOCK_SECOND_PASSWORD, MOCK_SMS_CODE, verify_mock_mfa};
    use super::{
        auth_method_index, auth_method_selected_index, field_visibility, send_sms_label_owned,
    };
    use crate::fields::MfaField;
    use crate::state::CredentialProviderState;
    use auth_core::{AuthMethod, MfaState};
    use auth_ipc::{PhoneInputSource, PolicySnapshot};
    use windows::Win32::UI::Shell::{CPFIS_DISABLED, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN};

    #[test]
    fn auth_method_indices_are_stable_for_combobox() {
        assert_eq!(auth_method_index(AuthMethod::PhoneCode), 0);
        assert_eq!(auth_method_index(AuthMethod::SecondPassword), 1);
        assert_eq!(auth_method_index(AuthMethod::Wechat), 2);
    }

    #[test]
    fn selected_index_uses_configured_method_order() {
        let mut state = CredentialProviderState::default();
        state.available_auth_methods = vec![AuthMethod::SecondPassword];
        state.selected_method = AuthMethod::SecondPassword;

        assert_eq!(auth_method_selected_index(&state), 0);
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
    fn configured_phone_policy_disables_phone_field_and_displays_masked_value() {
        let mut state = CredentialProviderState::default();
        state.apply_policy_snapshot(&PolicySnapshot {
            auth_methods: vec![AuthMethod::PhoneCode],
            phone_source: PhoneInputSource::Configured,
            masked_phone: Some("138****8888".to_owned()),
            phone_editable: false,
            mfa_timeout_seconds: 120,
            sms_resend_seconds: 60,
        });

        assert_eq!(state.phone, "138****8888");
        assert_eq!(field_visibility(MfaField::Phone, &state).1, CPFIS_DISABLED);
        assert_eq!(
            field_visibility(MfaField::SmsCode, &state).0,
            CPFS_DISPLAY_IN_SELECTED_TILE
        );
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

        assert_eq!(send_sms_label_owned(&state), "重新发送(60)");
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

    #[test]
    fn mock_sms_code_verifies_when_phone_and_code_match() {
        let mut state = CredentialProviderState::default();
        state.selected_method = AuthMethod::PhoneCode;
        state.phone = "13800138000".to_owned();
        state.sms_code = MOCK_SMS_CODE.to_owned();

        assert_eq!(verify_mock_mfa(&mut state), Ok(()));
        assert_eq!(state.mfa_state, MfaState::Verified);
    }

    #[test]
    fn mock_second_password_verifies_when_password_matches() {
        let mut state = CredentialProviderState::default();
        state.selected_method = AuthMethod::SecondPassword;
        state.second_password = MOCK_SECOND_PASSWORD.to_owned();

        assert_eq!(verify_mock_mfa(&mut state), Ok(()));
        assert_eq!(state.mfa_state, MfaState::Verified);
    }

    #[test]
    fn mock_verification_rejects_wrong_sms_code() {
        let mut state = CredentialProviderState::default();
        state.selected_method = AuthMethod::PhoneCode;
        state.phone = "13800138000".to_owned();
        state.sms_code = "000000".to_owned();

        assert!(verify_mock_mfa(&mut state).is_err());
        assert!(matches!(state.mfa_state, MfaState::Failed(_)));
    }

    #[test]
    fn mock_verification_rejects_disabled_method() {
        let mut state = CredentialProviderState::default();
        state.available_auth_methods = vec![AuthMethod::SecondPassword];
        state.selected_method = AuthMethod::PhoneCode;
        state.phone = "13800138000".to_owned();
        state.sms_code = MOCK_SMS_CODE.to_owned();

        assert!(verify_mock_mfa(&mut state).is_err());
        assert_eq!(state.status_message, "当前认证方式已被配置禁用");
    }
}
