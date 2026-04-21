//! COM 内存分配工具。
//!
//! Credential Provider 返回给 LogonUI 的字符串和字段描述符需要用 COM 约定分配，
//! 让调用方可以用对应的 COM 释放函数清理。这个模块集中处理分配细节，避免每个
//! 字段或 Credential 方法都手写 `CoTaskMemAlloc`。

use windows::Win32::Foundation::E_POINTER;
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::core::{Error, PWSTR, Result};

/// 分配以 NUL 结尾的 UTF-16 字符串。
///
/// 返回的内存交给 LogonUI/COM 调用方释放，不应在 Rust 侧用 `Vec` 或 `String` 释放。
pub fn alloc_wide_string(value: &str) -> Result<PWSTR> {
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
