//! Rust Credential Provider DLL 骨架。
//!
//! 这个 DLL 的长期职责非常窄：接收 LogonUI 通过 `SetSerialization` 传入的 RDP 原始凭证，
//! 展示二次认证 UI，通过本地 helper 完成认证，然后在 `GetSerialization` 中把原始凭证
//! 交还给 LogonUI。网络、注册表和复杂策略都不应放在这里，否则一旦阻塞或崩溃会直接
//! 影响 Windows 登录界面。

use auth_core::MfaState;

/// Windows HRESULT 成功值。
///
/// 这里暂时不用 `windows` crate，是为了先建立可编译的 DLL 骨架。后续实现真实 COM
/// 接口时会替换为 Windows 官方类型，并在每个 unsafe 边界补充中文维护注释。
const S_OK: i32 = 0;

/// 当前 DLL 是否可以卸载。
///
/// 真实实现需要检查 COM 对象引用计数。此处先返回 `S_OK`，代表骨架阶段没有活跃对象。
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> i32 {
    S_OK
}

/// COM 类工厂入口。
///
/// LogonUI 会通过这个导出函数请求 `IClassFactory`。当前阶段尚未实现真实类工厂，所以
/// 返回通用失败码。下一阶段实现时必须小心处理引用计数和 `QueryInterface`，否则容易
/// 导致 LogonUI 进程内存泄漏或加载失败。
#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    _class_id: *const core::ffi::c_void,
    _interface_id: *const core::ffi::c_void,
    _object: *mut *mut core::ffi::c_void,
) -> i32 {
    const E_NOTIMPL: i32 = unchecked_hresult(0x8000_4001);
    E_NOTIMPL
}

/// 将无符号 HRESULT 字面量转换成 Rust 的 `i32`。
///
/// Windows 头文件通常以十六进制无符号形式书写 HRESULT，Rust 直接写入 `i32` 会溢出。
const fn unchecked_hresult(value: u32) -> i32 {
    value as i32
}

/// Credential Provider 内部状态的最小占位结构。
#[derive(Debug, Clone)]
pub struct CredentialProviderState {
    /// 二次认证状态决定 `GetSerialization` 是否可以放行原始 RDP 凭证。
    pub mfa_state: MfaState,
    /// 是否已经收到 LogonUI 传入的 RDP 原始凭证序列化数据。
    pub has_inbound_serialization: bool,
}

impl Default for CredentialProviderState {
    fn default() -> Self {
        Self {
            mfa_state: MfaState::Idle,
            has_inbound_serialization: false,
        }
    }
}
