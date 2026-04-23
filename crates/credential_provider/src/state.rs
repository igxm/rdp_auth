//! Credential Provider 共享状态和固定标识。
//!
//! 这个模块只保存跨 COM 对象需要共享或测试的轻量状态，不放 UI 字段、DLL 入口或
//! 凭证序列化逻辑。后续新增状态时，优先判断它属于 Provider 生命周期还是 Credential
//! Tile 生命周期，避免状态边界混乱。

use std::path::PathBuf;
use std::sync::Mutex;

use auth_config::load_app_config;
use auth_core::{AuthMethod, MfaState};
use auth_ipc::PolicySnapshot;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Shell::{CPUS_LOGON, CREDENTIAL_PROVIDER_USAGE_SCENARIO};
use windows::core::GUID;

use crate::diagnostics::log_event;
use crate::serialization::{InboundSerialization, RemoteLogonCredential};

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
/// Filter 必须把 serialization 的 Provider CLSID 临时改成本项目 CLSID，LogonUI 才会把远程凭证交给
/// 我们；但认证通过后又要恢复原始 Provider CLSID，避免系统按错误 Provider 上下文解释原始密码序列化数据。
///
/// 实机 RDP 链路里 `UpdateRemoteCredential` 和后续 Provider `SetSerialization` 可能不在同一个进程内，
/// 单纯依赖静态变量会丢失这个 CLSID。这里同时写入按 session 区分的轻量 handoff 文件；文件只保存 Provider
/// GUID，不保存用户名、密码或 `rgbSerialization`，避免把敏感凭证材料落盘。
pub fn remember_remote_source_provider(provider: GUID) {
    *LAST_REMOTE_SOURCE_PROVIDER
        .lock()
        .expect("remote source provider lock poisoned") = Some(provider);
    match write_remote_source_provider_handoff(provider) {
        Ok(()) => log_event(
            "RemoteProviderHandoff",
            format!("write_ok provider={:?}", provider),
        ),
        Err(error) => log_event(
            "RemoteProviderHandoff",
            format!("write_failed provider={:?} error={}", provider, error),
        ),
    }
}

/// 取出最近一次 RDP 远程凭证的原始 Provider CLSID。
pub fn take_remote_source_provider() -> Option<GUID> {
    let memory_provider = LAST_REMOTE_SOURCE_PROVIDER
        .lock()
        .expect("remote source provider lock poisoned")
        .take();
    if memory_provider.is_some() {
        let _ = remove_remote_source_provider_handoff();
        log_event(
            "RemoteProviderHandoff",
            format!("take_memory provider={:?}", memory_provider),
        );
        return memory_provider;
    }
    let file_provider = read_remote_source_provider_handoff();
    log_event(
        "RemoteProviderHandoff",
        format!("take_file provider={:?}", file_provider),
    );
    file_provider
}

fn write_remote_source_provider_handoff(provider: GUID) -> std::io::Result<()> {
    let Some(path) = remote_source_provider_handoff_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{:032x}", provider.to_u128()))
}

fn read_remote_source_provider_handoff() -> Option<GUID> {
    let path = remote_source_provider_handoff_path()?;
    let value = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(path);
    u128::from_str_radix(value.trim(), 16)
        .ok()
        .map(GUID::from_u128)
}

fn remove_remote_source_provider_handoff() -> std::io::Result<()> {
    let Some(path) = remote_source_provider_handoff_path() else {
        return Ok(());
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remote_source_provider_handoff_path() -> Option<PathBuf> {
    Some(provider_handoff_dir().join(format!(
        "remote_provider_session_{}.txt",
        current_session_id()?
    )))
}

#[cfg(not(test))]
fn provider_handoff_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\rdp_auth")
}

#[cfg(test)]
fn provider_handoff_dir() -> PathBuf {
    std::env::temp_dir().join("rdp_auth_credential_provider_tests")
}

fn current_session_id() -> Option<u32> {
    let mut session_id = 0_u32;
    unsafe {
        // SAFETY: 输出指针指向当前栈变量；失败时返回 None，不使用未初始化的 session id。
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)
            .ok()
            .map(|_| session_id)
    }
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
    /// 从 RDP/NLA authentication buffer 中解出的 Windows 一次凭证，用于 MFA 通过后重新打包。
    ///
    /// 该字段包含明文密码，只能留在内存中短暂使用，禁止写入日志或落盘。后续应补充安全清零。
    pub remote_logon_credential: Option<RemoteLogonCredential>,
    /// 阶段 3 用于验证 pass-through 链路的开关；真实 MFA 接入后应由策略控制。
    pub allow_passthrough_without_mfa: bool,
    /// 当前使用场景。第一版只支持 RDP 登录常见的 logon/unlock 场景。
    pub usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    /// 当前选择的二次认证方式。UI 通过组合框切换，后续 helper 会按这个值路由请求。
    pub selected_method: AuthMethod,
    /// 当前配置允许展示和提交的认证方式。全部关闭时由 auth_config 回退到安全默认集合。
    pub available_auth_methods: Vec<AuthMethod>,
    /// 手机号输入值。Credential Provider 进程内只短暂保存 UI 内容，不写日志。
    pub phone: String,
    /// 手机号字段是否允许用户编辑。文件模式下 helper 只下发脱敏号码，CP 必须禁用编辑。
    pub phone_editable: bool,
    /// 短信验证码输入值。验证码属于敏感内容，只能保存在内存状态中。
    pub sms_code: String,
    /// 二次密码输入值。后续接入 helper 后必须通过 IPC 传递，不允许写日志。
    pub second_password: String,
    /// 用户可见状态文本。这里不放诊断细节，避免把敏感失败原因显示在登录界面。
    pub status_message: String,
    /// 短信验证码重新发送剩余秒数。倒计时后续需要由 LogonUI 事件或 helper 心跳推进；
    /// 当前先保存禁用态，避免用户连续点击发送验证码。
    pub sms_resend_remaining: u32,
    /// 短信倒计时 generation。重复点击或后续真实 helper 重置倒计时时，旧刷新线程醒来后自退。
    pub sms_resend_generation: u64,
    /// 二次认证超时秒数。后续由 helper 策略快照下发，当前使用安全默认值 120 秒。
    pub mfa_timeout_seconds: u64,
    /// RDP 场景无 inbound serialization 时的等待窗口，避免锁屏后卡在无法放行的 MFA Tile。
    pub missing_serialization_grace_seconds: u64,
    /// 短信验证码重新发送间隔。helper 接入前由本地 TOML 配置控制 UI 倒计时。
    pub sms_resend_seconds: u32,
    /// 无 inbound serialization 时是否断开 RDP。安全默认值为启用。
    pub disconnect_when_missing_serialization: bool,
    /// 超时定时器 generation。每次新的 RDP serialization 都递增，旧定时器醒来后据此自退。
    pub timeout_generation: u64,
}

impl Default for CredentialProviderState {
    fn default() -> Self {
        let app_config = load_app_config();
        let mfa_config = app_config.mfa;
        let available_auth_methods = app_config.auth_methods.enabled_methods();
        let selected_method = available_auth_methods
            .first()
            .copied()
            .unwrap_or(AuthMethod::PhoneCode);
        Self {
            mfa_state: MfaState::Idle,
            has_inbound_serialization: false,
            inbound_serialization: None,
            remote_logon_credential: None,
            allow_passthrough_without_mfa: false,
            usage_scenario: CPUS_LOGON,
            selected_method,
            available_auth_methods,
            phone: String::new(),
            phone_editable: true,
            sms_code: String::new(),
            second_password: String::new(),
            status_message: "请选择二次认证方式".to_owned(),
            sms_resend_remaining: 0,
            sms_resend_generation: 0,
            mfa_timeout_seconds: mfa_config.timeout_seconds,
            missing_serialization_grace_seconds: mfa_config.missing_serialization_grace_seconds,
            sms_resend_seconds: mfa_config.sms_resend_seconds,
            disconnect_when_missing_serialization: mfa_config.disconnect_when_missing_serialization,
            timeout_generation: 0,
        }
    }
}

impl CredentialProviderState {
    /// 应用 helper 下发的脱敏策略快照。
    ///
    /// 这里不读取手机号文件，也不接触真实手机号；文件模式只把 helper 返回的脱敏值显示在 UI 中，
    /// 并禁用手机号输入框，避免 CP 进程保存或修改真实手机号。
    pub fn apply_policy_snapshot(&mut self, snapshot: &PolicySnapshot) {
        if !snapshot.auth_methods.is_empty() {
            self.available_auth_methods = snapshot.auth_methods.clone();
        }
        if !self.available_auth_methods.contains(&self.selected_method) {
            self.selected_method = self
                .available_auth_methods
                .first()
                .copied()
                .unwrap_or(AuthMethod::PhoneCode);
        }
        self.phone_editable = snapshot.phone_editable;
        if !snapshot.phone_editable {
            self.phone = snapshot.masked_phone.clone().unwrap_or_default();
        }
        self.mfa_timeout_seconds = snapshot.mfa_timeout_seconds;
        self.sms_resend_seconds = snapshot.sms_resend_seconds;
    }
}

#[cfg(test)]
mod tests {
    use auth_core::AuthMethod;
    use auth_ipc::{PhoneInputSource, PolicySnapshot};

    use super::{
        CredentialProviderState, RDP_MFA_PROVIDER_CLSID, remember_remote_source_provider,
        take_remote_source_provider, write_remote_source_provider_handoff,
    };
    use std::sync::Mutex;
    use windows::core::GUID;

    static TEST_REMOTE_PROVIDER_LOCK: Mutex<()> = Mutex::new(());

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
    fn default_state_uses_safe_mfa_timeout() {
        let state = CredentialProviderState::default();
        assert_eq!(state.mfa_timeout_seconds, 120);
        assert_eq!(state.missing_serialization_grace_seconds, 1);
        assert_eq!(state.sms_resend_seconds, 60);
        assert!(state.disconnect_when_missing_serialization);
        assert_eq!(state.timeout_generation, 0);
        assert_eq!(state.sms_resend_generation, 0);
        assert!(state.phone_editable);
        assert_eq!(
            state.available_auth_methods,
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
    }

    #[test]
    fn file_phone_policy_snapshot_disables_phone_input_and_uses_masked_value() {
        let mut state = CredentialProviderState::default();

        state.apply_policy_snapshot(&PolicySnapshot {
            auth_methods: vec![AuthMethod::PhoneCode],
            phone_source: PhoneInputSource::ConfiguredFile,
            masked_phone: Some("138****8888".to_owned()),
            phone_editable: false,
            mfa_timeout_seconds: 90,
            sms_resend_seconds: 45,
        });

        assert_eq!(state.phone, "138****8888");
        assert!(!state.phone_editable);
        assert_eq!(state.available_auth_methods, vec![AuthMethod::PhoneCode]);
        assert_eq!(state.selected_method, AuthMethod::PhoneCode);
        assert_eq!(state.mfa_timeout_seconds, 90);
        assert_eq!(state.sms_resend_seconds, 45);
    }

    #[test]
    fn manual_phone_policy_snapshot_keeps_existing_input_editable() {
        let mut state = CredentialProviderState::default();
        state.phone = "13800138000".to_owned();

        state.apply_policy_snapshot(&PolicySnapshot {
            auth_methods: vec![AuthMethod::SecondPassword],
            phone_source: PhoneInputSource::ManualInput,
            masked_phone: None,
            phone_editable: true,
            mfa_timeout_seconds: 120,
            sms_resend_seconds: 60,
        });

        assert_eq!(state.phone, "13800138000");
        assert!(state.phone_editable);
        assert_eq!(state.selected_method, AuthMethod::SecondPassword);
    }

    #[test]
    fn remembers_and_takes_remote_source_provider() {
        let _guard = TEST_REMOTE_PROVIDER_LOCK.lock().unwrap();
        let provider = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);

        remember_remote_source_provider(provider);

        assert_eq!(take_remote_source_provider(), Some(provider));
        assert_eq!(take_remote_source_provider(), None);
    }

    #[test]
    fn takes_remote_source_provider_from_handoff_file_when_memory_is_empty() {
        let _guard = TEST_REMOTE_PROVIDER_LOCK.lock().unwrap();
        let _ = take_remote_source_provider();
        let provider = GUID::from_u128(0x22222222_3333_4444_5555_666666666666);

        write_remote_source_provider_handoff(provider).unwrap();

        assert_eq!(take_remote_source_provider(), Some(provider));
        assert_eq!(take_remote_source_provider(), None);
    }
}
