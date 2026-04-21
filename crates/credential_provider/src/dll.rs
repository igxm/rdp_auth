//! DLL 导出入口。
//!
//! Windows/LogonUI 只通过这些导出函数进入本 DLL。这里仅处理类工厂获取和 DLL 生命周期，
//! 不放 Provider 字段枚举、Credential 输入或认证逻辑。

use std::ffi::c_void;

use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_POINTER, HINSTANCE};
use windows::Win32::System::Com::IClassFactory;
use windows::core::{BOOL, GUID, HRESULT, Interface};

use crate::class_factory::{ComClass, RdpMfaClassFactory};
use crate::state::{RDP_MFA_FILTER_CLSID, RDP_MFA_PROVIDER_CLSID};

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
    let class = match requested_class {
        RDP_MFA_PROVIDER_CLSID => ComClass::Provider,
        RDP_MFA_FILTER_CLSID => ComClass::Filter,
        _ => return CLASS_E_CLASSNOTAVAILABLE,
    };

    let factory: IClassFactory = RdpMfaClassFactory::new(class).into();
    unsafe {
        // SAFETY: `factory` 是刚创建的有效 COM 对象；`query` 会 AddRef 输出接口。
        factory.query(interface_id, object)
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
