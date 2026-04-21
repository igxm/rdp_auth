//! COM 类工厂实现。
//!
//! 类工厂只负责按 CLSID 创建 `ICredentialProvider` 实例，不保存业务状态。业务状态放在
//! Provider/Credential 对象中，避免多个 LogonUI 枚举周期之间共享脏数据。

use std::ffi::c_void;

use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_POINTER};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};
use windows::Win32::UI::Shell::ICredentialProvider;
use windows::core::{BOOL, Error, GUID, IUnknown, Interface, Ref, Result, implement};

use crate::provider::RdpMfaProvider;

/// Credential Provider 的类工厂。
#[implement(IClassFactory)]
pub struct RdpMfaClassFactory;

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
