//! Credential Provider Tile 字段定义。
//!
//! 字段描述符、字段 ID 和字段数量集中在这里维护。Credential Provider 的 UI 字段顺序
//! 会被 LogonUI 缓存和反复查询，因此新增字段必须先在这里明确 ID，再让 Credential
//! 只处理字段值、显示状态和用户交互，避免字段编号散落在多个 COM 回调里。

use windows::Win32::Foundation::{E_INVALIDARG, E_POINTER};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    CPFG_CREDENTIAL_PROVIDER_LABEL, CPFG_STANDALONE_SUBMIT_BUTTON, CPFT_COMBOBOX,
    CPFT_COMMAND_LINK, CPFT_EDIT_TEXT, CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT,
    CPFT_SUBMIT_BUTTON, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_TYPE,
};
use windows::core::{Error, GUID, Result};

use crate::memory::alloc_wide_string;

/// Tile 字段数量。
pub const FIELD_COUNT: u32 = MfaField::COUNT;

/// 二次认证 Tile 中所有字段的稳定编号。
///
/// Windows 会用这些 ID 回调 `GetStringValue`、`SetStringValue`、`GetFieldState` 等方法；
/// 如果维护时随意复用旧 ID，LogonUI 可能把输入值或按钮行为对应到错误字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MfaField {
    Title = 0,
    AuthMethod = 1,
    Phone = 2,
    SmsCode = 3,
    SendSms = 4,
    SecondPassword = 5,
    WechatNotice = 6,
    Submit = 7,
    Cancel = 8,
    Status = 9,
}

impl MfaField {
    pub const COUNT: u32 = 10;

    pub fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::Title),
            1 => Some(Self::AuthMethod),
            2 => Some(Self::Phone),
            3 => Some(Self::SmsCode),
            4 => Some(Self::SendSms),
            5 => Some(Self::SecondPassword),
            6 => Some(Self::WechatNotice),
            7 => Some(Self::Submit),
            8 => Some(Self::Cancel),
            9 => Some(Self::Status),
            _ => None,
        }
    }

    fn descriptor(self) -> (&'static str, CREDENTIAL_PROVIDER_FIELD_TYPE, GUID) {
        match self {
            Self::Title => (
                "RDP 二次认证",
                CPFT_LARGE_TEXT,
                CPFG_CREDENTIAL_PROVIDER_LABEL,
            ),
            Self::AuthMethod => ("认证方式", CPFT_COMBOBOX, GUID::zeroed()),
            Self::Phone => ("", CPFT_SMALL_TEXT, GUID::zeroed()),
            Self::SmsCode => ("短信验证码", CPFT_EDIT_TEXT, GUID::zeroed()),
            Self::SendSms => ("发送验证码", CPFT_COMMAND_LINK, GUID::zeroed()),
            Self::SecondPassword => ("二次密码", CPFT_PASSWORD_TEXT, GUID::zeroed()),
            Self::WechatNotice => ("微信扫码认证", CPFT_SMALL_TEXT, GUID::zeroed()),
            Self::Submit => ("登录", CPFT_SUBMIT_BUTTON, CPFG_STANDALONE_SUBMIT_BUTTON),
            Self::Cancel => ("取消", CPFT_COMMAND_LINK, GUID::zeroed()),
            Self::Status => ("等待二次认证", CPFT_SMALL_TEXT, GUID::zeroed()),
        }
    }
}

/// 返回指定字段的描述符。
///
/// LogonUI 会释放返回的结构体和标签字符串，所以这里必须使用 COM 分配器。
pub fn field_descriptor(index: u32) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let Some(field) = MfaField::from_id(index) else {
        return Err(Error::from_hresult(E_INVALIDARG));
    };
    let (label_text, field_type, field_guid) = field.descriptor();

    let descriptor = unsafe {
        // SAFETY: COM 约定要求字段描述符由调用方释放，因此这里使用 CoTaskMemAlloc。
        CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
            as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
    };
    if descriptor.is_null() {
        return Err(Error::from_hresult(E_POINTER));
    }

    let label = match alloc_wide_string(label_text) {
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
            dwFieldID: index,
            cpft: field_type,
            pszLabel: label,
            guidFieldType: field_guid,
        });
    }
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::{FIELD_COUNT, MfaField};
    use windows::Win32::UI::Shell::CPFT_SMALL_TEXT;

    #[test]
    fn field_ids_cover_declared_count() {
        for index in 0..FIELD_COUNT {
            assert!(MfaField::from_id(index).is_some());
        }
        assert!(MfaField::from_id(FIELD_COUNT).is_none());
    }

    #[test]
    fn phone_field_is_display_text_not_input() {
        let (_, field_type, _) = MfaField::Phone.descriptor();

        assert_eq!(field_type, CPFT_SMALL_TEXT);
    }
}
