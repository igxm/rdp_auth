//! Credential Provider Tile 字段定义。
//!
//! 字段描述符、字段 ID 和字段数量集中在这里维护。后续增加手机号、验证码、二次密码、
//! 提交按钮等字段时，先扩展这个模块，再让 Credential 只处理字段值和用户交互。

use windows::Win32::Foundation::{E_INVALIDARG, E_POINTER};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{CPFT_LARGE_TEXT, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR};
use windows::core::{Error, GUID, Result};

use crate::memory::alloc_wide_string;

/// 最小 Tile 字段数量。
pub const FIELD_COUNT: u32 = 1;

/// 第一版只显示一个说明性大文本字段。
pub const FIELD_STATUS: u32 = 0;

/// 返回指定字段的描述符。
///
/// LogonUI 会释放返回的结构体和标签字符串，所以这里必须使用 COM 分配器。
pub fn field_descriptor(index: u32) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
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
