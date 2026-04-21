//! Rust Credential Provider DLL 的最小 COM 加载骨架。
//!
//! 这个 DLL 的长期职责非常窄：接收 LogonUI 通过 `SetSerialization` 传入的 RDP 原始凭证，
//! 展示二次认证 UI，通过本地 helper 完成认证，然后在 `GetSerialization` 中把原始凭证
//! 交还给 LogonUI。网络、注册表和复杂策略都不应放在这里，否则一旦阻塞或崩溃会直接
//! 影响 Windows 登录界面。

use std::ffi::c_void;
use std::sync::Mutex;

use auth_core::MfaState;
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOTIMPL, E_POINTER,
    HINSTANCE, NTSTATUS,
};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::System::Com::{
    CoTaskMemAlloc, CoTaskMemFree, IClassFactory, IClassFactory_Impl,
};
use windows::Win32::UI::Shell::{
    CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFT_LARGE_TEXT, CPGSR_NO_CREDENTIAL_NOT_FINISHED,
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_NO_DEFAULT, CREDENTIAL_PROVIDER_STATUS_ICON,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProvider, ICredentialProvider_Impl,
    ICredentialProviderCredential, ICredentialProviderCredential_Impl,
    ICredentialProviderCredentialEvents, ICredentialProviderEvents,
};
use windows::core::{
    BOOL, Error, GUID, HRESULT, IUnknown, Interface, PCWSTR, PWSTR, Ref, Result, implement,
};

/// 当前 Credential Provider 的 CLSID。
///
/// 后续 `register_tool` 会把同一个 CLSID 写入系统 Credential Providers 注册表路径。
/// 这个值一旦发布就不应随意修改，否则升级时会出现旧 Provider 残留和新 Provider 并存。
pub const RDP_MFA_PROVIDER_CLSID: GUID = GUID::from_u128(0x92d2cf8d_8e19_49d2_9be3_3f7d9de8c2a1);

/// 当前 DLL 是否可以卸载。
///
/// `windows` 宏生成的 COM 对象内部会维护引用计数。当前骨架阶段没有全局对象缓存，
/// 因此可以让 COM 宿主按需卸载。后续如果引入全局锁或后台线程，需要在这里重新判断。
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    HRESULT(0)
}

/// COM 类工厂入口。
///
/// LogonUI 通过这个函数请求 `IClassFactory`。这里必须只响应本 Provider 的 CLSID，
/// 否则系统可能把其他 COM 类请求错误地交给我们，导致难以定位的登录界面加载失败。
#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    class_id: *const GUID,
    interface_id: *const GUID,
    object: *mut *mut c_void,
) -> HRESULT {
    if class_id.is_null() || interface_id.is_null() || object.is_null() {
        return E_POINTER;
    }

    // 这里先清空输出指针，保证失败路径不会把未初始化指针交还给 COM 调用方。
    unsafe {
        // SAFETY: 上面已经检查 `object` 非空，写入空指针是 COM 失败路径的常规做法。
        *object = std::ptr::null_mut();
    }

    let requested_class = unsafe {
        // SAFETY: 上面已经检查 `class_id` 非空，GUID 是按值复制，不持有外部引用。
        *class_id
    };
    if requested_class != RDP_MFA_PROVIDER_CLSID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    let factory: IClassFactory = RdpMfaClassFactory.into();
    unsafe {
        // SAFETY: `factory` 是刚创建的有效 COM 对象；`query` 会 AddRef 输出接口。
        factory.query(interface_id, object)
    }
}

/// Credential Provider 的类工厂。
///
/// 类工厂只负责创建 Provider 实例，不保存业务状态。业务状态放在 Provider/Credential
/// 对象里，避免多个 LogonUI 枚举周期之间共享脏数据。
#[implement(IClassFactory)]
struct RdpMfaClassFactory;

impl IClassFactory_Impl for RdpMfaClassFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        interface_id: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if !outer.is_null() {
            // Credential Provider 不支持 COM 聚合。拒绝聚合可以避免外部对象接管生命周期。
            return Err(Error::from_hresult(CLASS_E_NOAGGREGATION));
        }
        if interface_id.is_null() || object.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let provider: ICredentialProvider = RdpMfaProvider::default().into();
        let hr = unsafe {
            // SAFETY: `provider` 是有效 COM 对象；`query` 成功时会为输出接口 AddRef。
            provider.query(interface_id, object)
        };
        hr.ok()
    }

    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        // 当前没有 DLL 级全局资源需要锁定。若后续加全局状态，这里要同步引用计数。
        Ok(())
    }
}

/// Credential Provider 内部状态。
#[derive(Debug, Clone)]
pub struct CredentialProviderState {
    /// 二次认证状态决定 `GetSerialization` 是否可以放行原始 RDP 凭证。
    pub mfa_state: MfaState,
    /// 是否已经收到 LogonUI 传入的 RDP 原始凭证序列化数据。
    pub has_inbound_serialization: bool,
    /// 当前使用场景。第一版只支持 RDP 登录常见的 logon/unlock 场景。
    pub usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
}

impl Default for CredentialProviderState {
    fn default() -> Self {
        Self {
            mfa_state: MfaState::Idle,
            has_inbound_serialization: false,
            usage_scenario: CPUS_LOGON,
        }
    }
}

/// 最小 Credential Provider。
///
/// 这里用 `Mutex` 是因为 COM 可能从不同调用栈访问 Provider 状态；后续如果确认 LogonUI
/// 调用线程模型更细，可以再收窄锁范围。不要在持锁时做 IPC 或网络，避免登录界面死锁。
#[implement(ICredentialProvider)]
struct RdpMfaProvider {
    state: Mutex<CredentialProviderState>,
}

impl Default for RdpMfaProvider {
    fn default() -> Self {
        Self {
            state: Mutex::new(CredentialProviderState::default()),
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
        let mut state = self.state.lock().expect("provider state poisoned");
        state.has_inbound_serialization = !serialization.is_null();
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
        Ok(RdpMfaCredential::default().into())
    }
}

/// 最小 Tile 字段数量。
const FIELD_COUNT: u32 = 1;

/// 第一版只显示一个说明性大文本字段。
const FIELD_STATUS: u32 = 0;

/// 最小 Credential 对象。
#[implement(ICredentialProviderCredential)]
struct RdpMfaCredential {
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

/// 保留 DLL 入口，供 Windows 加载 DLL 时调用。
///
/// 这里不做初始化，是为了避免 DLL 被系统探测加载时产生副作用。注册表读取、helper
/// 启动等动作都应延后到明确的 Credential Provider 调用阶段。
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_instance: HINSTANCE, _reason: u32, _reserved: *mut c_void) -> BOOL {
    true.into()
}

fn field_descriptor(index: u32) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    if index != FIELD_STATUS {
        return Err(Error::from_hresult(E_INVALIDARG));
    }

    let descriptor = unsafe {
        // SAFETY: COM 约定要求字段描述符由调用方释放，因此这里使用 CoTaskMemAlloc。
        CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
            as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
    };
    if descriptor.is_null() {
        return Err(Error::from_hresult(E_POINTER));
    }

    let label = match alloc_wide_string("RDP 二次认证") {
        Ok(label) => label,
        Err(error) => {
            unsafe {
                // SAFETY: `descriptor` 来自 CoTaskMemAlloc，标签分配失败时必须释放它。
                CoTaskMemFree(Some(descriptor.cast_const().cast()));
            }
            return Err(error);
        }
    };
    unsafe {
        // SAFETY: `descriptor` 来自 CoTaskMemAlloc，大小正好是目标结构体大小。
        descriptor.write(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: FIELD_STATUS,
            cpft: CPFT_LARGE_TEXT,
            pszLabel: label,
            guidFieldType: GUID::zeroed(),
        });
    }
    Ok(descriptor)
}

fn alloc_wide_string(value: &str) -> Result<PWSTR> {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();
    let buffer = unsafe {
        // SAFETY: CoTaskMemAlloc 返回的内存交给 LogonUI/COM 调用方释放，符合 CP 字符串约定。
        CoTaskMemAlloc(byte_len) as *mut u16
    };
    if buffer.is_null() {
        return Err(Error::from_hresult(E_POINTER));
    }

    unsafe {
        // SAFETY: `buffer` 至少有 `wide.len()` 个 u16 空间，来源和长度都在本函数内控制。
        std::ptr::copy_nonoverlapping(wide.as_ptr(), buffer, wide.len());
    }
    Ok(PWSTR(buffer))
}

#[cfg(test)]
mod tests {
    use super::{CredentialProviderState, RDP_MFA_PROVIDER_CLSID};
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
}
