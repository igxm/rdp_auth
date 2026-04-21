//! RDP 原始凭证序列化数据的保存与返回。
//!
//! LogonUI 通过 `SetSerialization` 传入的 `rgbSerialization` 只在调用期间有效，不能保存
//! 原始指针。这里将其深拷贝到 `Vec<u8>`，等 `GetSerialization` 放行时再用 COM 分配器
//! 创建新的输出缓冲区交还给 LogonUI。

use windows::Win32::Foundation::{E_OUTOFMEMORY, E_POINTER};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::UI::Shell::CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION;
use windows::core::{Error, GUID, Result};

use crate::state::RDP_MFA_PROVIDER_CLSID;

/// 已深拷贝的 RDP 原始凭证序列化数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSerialization {
    /// Windows 认证包 ID，必须原样交回，否则 LSA 不知道如何解释 `rgbSerialization`。
    pub authentication_package: u32,
    /// 传入时的 Provider CLSID，仅用于诊断和后续兼容性判断，返回时会使用本 Provider CLSID。
    pub source_provider: GUID,
    /// 原始序列化字节。这里绝不能写日志，因为里面可能包含密码或等价凭证材料。
    pub bytes: Vec<u8>,
}

impl InboundSerialization {
    /// 从 LogonUI 传入的结构体深拷贝原始凭证。
    ///
    /// # Safety
    ///
    /// `serialization` 必须是 LogonUI 在 `SetSerialization` 调用期间传入的有效指针。
    pub unsafe fn copy_from_raw(
        serialization: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<Self> {
        if serialization.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let serialization = unsafe {
            // SAFETY: 调用方保证指针来自 LogonUI，本函数已检查非空。
            &*serialization
        };
        if serialization.cbSerialization > 0 && serialization.rgbSerialization.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let bytes = if serialization.cbSerialization == 0 {
            Vec::new()
        } else {
            let slice = unsafe {
                // SAFETY: `cbSerialization > 0` 时已检查 `rgbSerialization` 非空，长度来自系统。
                std::slice::from_raw_parts(
                    serialization.rgbSerialization,
                    serialization.cbSerialization as usize,
                )
            };
            slice.to_vec()
        };

        Ok(Self {
            authentication_package: serialization.ulAuthenticationPackage,
            source_provider: serialization.clsidCredentialProvider,
            bytes,
        })
    }

    /// 将缓存的原始凭证写回 LogonUI 要求的输出结构。
    ///
    /// `rgbSerialization` 用 COM 分配器重新申请，由 LogonUI 在后续流程释放。返回时
    /// `clsidCredentialProvider` 使用本 Provider CLSID，表示本次凭证由当前 Provider 交出；
    /// 认证包和二进制内容保持 RDP 传入时的原始值。
    pub fn write_to(
        &self,
        output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        if output.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        let bytes_ptr = if self.bytes.is_empty() {
            std::ptr::null_mut()
        } else {
            let buffer = unsafe {
                // SAFETY: CoTaskMemAlloc 返回给 LogonUI 接管，大小来自 `Vec` 长度。
                CoTaskMemAlloc(self.bytes.len()) as *mut u8
            };
            if buffer.is_null() {
                return Err(Error::from_hresult(E_OUTOFMEMORY));
            }
            unsafe {
                // SAFETY: `buffer` 至少有 `self.bytes.len()` 字节空间，源切片同样有效。
                std::ptr::copy_nonoverlapping(self.bytes.as_ptr(), buffer, self.bytes.len());
            }
            buffer
        };

        unsafe {
            // SAFETY: `output` 已做非空检查；字段值都由本结构或固定 CLSID 构造。
            output.write(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                ulAuthenticationPackage: self.authentication_package,
                clsidCredentialProvider: RDP_MFA_PROVIDER_CLSID,
                cbSerialization: self.bytes.len() as u32,
                rgbSerialization: bytes_ptr,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::InboundSerialization;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION;
    use windows::core::GUID;

    #[test]
    fn copies_inbound_serialization_bytes() {
        let mut source = vec![1_u8, 2, 3, 4];
        let raw = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
            ulAuthenticationPackage: 7,
            clsidCredentialProvider: GUID::from_u128(0x11111111_2222_3333_4444_555555555555),
            cbSerialization: source.len() as u32,
            rgbSerialization: source.as_mut_ptr(),
        };

        let copied = unsafe { InboundSerialization::copy_from_raw(&raw) }.unwrap();
        source.fill(0);

        assert_eq!(copied.authentication_package, 7);
        assert_eq!(copied.bytes, vec![1_u8, 2, 3, 4]);
    }

    #[test]
    fn writes_serialization_with_new_com_buffer() {
        let cached = InboundSerialization {
            authentication_package: 9,
            source_provider: GUID::zeroed(),
            bytes: vec![8_u8, 6, 7],
        };
        let mut output = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();

        cached.write_to(&mut output).unwrap();

        assert_eq!(output.ulAuthenticationPackage, 9);
        assert_eq!(output.cbSerialization, 3);
        assert!(!output.rgbSerialization.is_null());

        unsafe {
            let bytes = std::slice::from_raw_parts(output.rgbSerialization, 3);
            assert_eq!(bytes, &[8_u8, 6, 7]);
            CoTaskMemFree(Some(output.rgbSerialization.cast_const().cast()));
        }
    }
}
