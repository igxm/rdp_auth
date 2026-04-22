//! RDP 原始凭证序列化数据的保存与返回。
//!
//! LogonUI 通过 `SetSerialization` 传入的 `rgbSerialization` 只在调用期间有效，不能保存
//! 原始指针。这里将其深拷贝到 `Vec<u8>`，等 `GetSerialization` 放行时再用 COM 分配器
//! 创建新的输出缓冲区交还给 LogonUI。

use windows::Win32::Foundation::{E_FAIL, E_OUTOFMEMORY, E_POINTER, HANDLE, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::{
    LSA_STRING, LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage,
    LsaNtStatusToWinError,
};
use windows::Win32::Security::Credentials::{
    CRED_PACK_FLAGS, CredPackAuthenticationBufferW, CredUnPackAuthenticationBufferW,
};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::UI::Shell::CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION;
use windows::core::{Error, GUID, HRESULT, PCWSTR, PSTR, PWSTR, Result};

use crate::diagnostics::log_event;

/// 已深拷贝的 RDP 原始凭证序列化数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSerialization {
    /// Windows 认证包 ID，必须原样交回，否则 LSA 不知道如何解释 `rgbSerialization`。
    pub authentication_package: u32,
    /// 传入时的 Provider CLSID。
    ///
    /// `UpdateRemoteCredential` 为了让 LogonUI 把远程凭证交给本项目 Provider，会临时把
    /// Provider CLSID 改成本项目 CLSID；但 `GetSerialization` 放行时应恢复原始 Provider
    /// CLSID。否则系统可能用错误的 Provider 上下文解释原始密码序列化数据，表现为
    /// 二次认证通过后仍提示用户名或密码错误。
    pub source_provider: GUID,
    /// 原始序列化字节。这里绝不能写日志，因为里面可能包含密码或等价凭证材料。
    pub bytes: Vec<u8>,
}

/// 从 RDP/NLA authentication buffer 中解出的 Windows 一次凭证。
///
/// 这里会短暂保存明文密码，因为后续必须重新打包成 LSA 可接受的登录 serialization。
/// 该结构绝不能派生 `Debug`，日志中也只能记录用户名/域名/密码长度等非敏感统计信息。
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteLogonCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
}

impl std::fmt::Debug for RemoteLogonCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteLogonCredential")
            .field("username_len", &self.username_len())
            .field("domain_len", &self.domain_len())
            .field("password_len", &self.password_len())
            .finish()
    }
}

impl RemoteLogonCredential {
    pub fn username_len(&self) -> usize {
        self.username.chars().count()
    }

    pub fn domain_len(&self) -> usize {
        self.domain.chars().count()
    }

    pub fn password_len(&self) -> usize {
        self.password.chars().count()
    }

    fn packed_username(&self) -> String {
        if self.domain.trim().is_empty()
            || self.username.contains('\\')
            || self.username.contains('@')
        {
            self.username.clone()
        } else {
            format!("{}\\{}", self.domain, self.username)
        }
    }

    /// MFA 通过后，重新打包为 LogonUI/LSA 能消费的 Negotiate 凭证。
    ///
    /// `UpdateRemoteCredential` 传入的 authentication buffer 只是远程登录阶段给系统 Provider
    /// 使用的材料，直接原样返回会得到 `STATUS_LOGON_FAILURE`。这里改为使用解包出的 Windows
    /// 一次凭证重新调用 `CredPackAuthenticationBufferW`，并填入 `Negotiate` authentication package。
    pub fn pack_for_logon(&self, provider_clsid: GUID) -> Result<InboundSerialization> {
        let authentication_package = lookup_negotiate_auth_package()?;
        let username = wide_null(self.packed_username());
        let password = wide_null(&self.password);
        log_event(
            "PackRemoteCredential",
            format!(
                "start username_chars={} domain_chars={} password_chars={} username_has_domain_separator={} username_has_upn_separator={} auth_package={}",
                self.username_len(),
                self.domain_len(),
                self.password_len(),
                self.username.contains('\\'),
                self.username.contains('@'),
                authentication_package
            ),
        );
        let mut size = 0_u32;
        let probe_result = unsafe {
            // SAFETY: 第一次调用按 Windows API 约定传空缓冲区以获取所需字节数。
            CredPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                PCWSTR(username.as_ptr()),
                PCWSTR(password.as_ptr()),
                None,
                &mut size,
            )
        };
        log_event(
            "PackRemoteCredential",
            format!(
                "probe_result={} required_size={}",
                result_label(&probe_result),
                size
            ),
        );
        if size == 0 {
            log_event("PackRemoteCredential", "probe_returned_zero_size");
            return Err(Error::from_hresult(E_FAIL));
        }

        let mut bytes = vec![0_u8; size as usize];
        let pack_result = unsafe {
            // SAFETY: `bytes` 长度来自上一轮 API 返回；用户名和密码宽字符串均以 NUL 结尾。
            CredPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                PCWSTR(username.as_ptr()),
                PCWSTR(password.as_ptr()),
                Some(bytes.as_mut_ptr()),
                &mut size,
            )
        };
        log_event(
            "PackRemoteCredential",
            format!(
                "pack_result={} final_size={}",
                result_label(&pack_result),
                size
            ),
        );
        pack_result?;
        bytes.truncate(size as usize);

        Ok(InboundSerialization {
            authentication_package,
            source_provider: provider_clsid,
            bytes,
        })
    }
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
    /// `rgbSerialization` 用 COM 分配器重新申请，由 LogonUI 在后续流程释放。认证包、
    /// Provider CLSID 和二进制内容都保持 RDP 传入时的原始值。
    pub fn write_to(
        &self,
        output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        self.write_to_with_provider(output, self.source_provider)
    }

    /// 返回传入凭证原本所属的 Provider CLSID。
    pub fn provider_clsid(&self) -> GUID {
        self.source_provider
    }

    /// 尝试把 RDP/NLA 传入的 authentication buffer 解包成 Windows 一次凭证。
    ///
    /// 该函数只在内存里处理明文凭证，不写日志、不落盘；调用方记录诊断信息时只能记录长度。
    pub fn unpack_remote_logon_credential(&self) -> Result<RemoteLogonCredential> {
        let mut username_len = 0_u32;
        let mut domain_len = 0_u32;
        let mut password_len = 0_u32;
        let probe_result = unsafe {
            // SAFETY: 第一次调用传空缓冲区获取长度；源字节来自已经深拷贝的 inbound serialization。
            CredUnPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                self.bytes.as_ptr().cast(),
                self.bytes.len() as u32,
                None,
                &mut username_len,
                None,
                Some(&mut domain_len),
                None,
                &mut password_len,
            )
        };
        log_event(
            "UnpackRemoteCredential",
            format!(
                "probe_result={} username_len={} domain_len={} password_len={} inbound_bytes_len={} inbound_auth_package={}",
                result_label(&probe_result),
                username_len,
                domain_len,
                password_len,
                self.bytes.len(),
                self.authentication_package
            ),
        );
        if username_len == 0 || password_len == 0 {
            log_event("UnpackRemoteCredential", "probe_missing_required_lengths");
            return Err(Error::from_hresult(E_FAIL));
        }

        let mut username = vec![0_u16; username_len as usize];
        let mut domain = vec![0_u16; domain_len.max(1) as usize];
        let mut password = vec![0_u16; password_len as usize];
        let unpack_result = unsafe {
            // SAFETY: 三个缓冲区长度来自 Windows API 返回值，均可写；源字节在调用期间保持有效。
            CredUnPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                self.bytes.as_ptr().cast(),
                self.bytes.len() as u32,
                Some(PWSTR(username.as_mut_ptr())),
                &mut username_len,
                Some(PWSTR(domain.as_mut_ptr())),
                Some(&mut domain_len),
                Some(PWSTR(password.as_mut_ptr())),
                &mut password_len,
            )
        };
        log_event(
            "UnpackRemoteCredential",
            format!(
                "unpack_result={} username_len={} domain_len={} password_len={}",
                result_label(&unpack_result),
                username_len,
                domain_len,
                password_len
            ),
        );
        unpack_result?;

        Ok(RemoteLogonCredential {
            username: wide_buffer_to_string(&username),
            domain: wide_buffer_to_string(&domain),
            password: wide_buffer_to_string(&password),
        })
    }

    /// 将缓存的原始凭证写回，并允许调用方指定输出 Provider CLSID。
    ///
    /// Filter 在 RDP MFA 开启时需要把远程凭证临时重定向到本项目 Provider；关闭 RDP
    /// MFA、应急恢复或认证通过后则需要保持/恢复原 Provider。把两种写法集中在这里，
    /// 可以避免多个模块重复处理 COM 内存分配细节。
    pub fn write_to_with_provider(
        &self,
        output: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        provider_clsid: GUID,
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
            // SAFETY: `output` 已做非空检查；字段值都由本结构或调用方传入的 CLSID 构造。
            output.write(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                ulAuthenticationPackage: self.authentication_package,
                clsidCredentialProvider: provider_clsid,
                cbSerialization: self.bytes.len() as u32,
                rgbSerialization: bytes_ptr,
            });
        }
        Ok(())
    }
}

fn lookup_negotiate_auth_package() -> Result<u32> {
    let mut handle = HANDLE::default();
    let status = unsafe {
        // SAFETY: 输出句柄指向当前栈变量；成功后必须调用 `LsaDeregisterLogonProcess` 释放。
        LsaConnectUntrusted(&mut handle)
    };
    log_event(
        "LookupAuthPackage",
        format!("connect_status={}", ntstatus_label(status)),
    );
    ntstatus_to_result(status)?;

    let mut package_name = negotiate_package_name_bytes();
    let lsa_string = LSA_STRING {
        Length: (package_name.len() - 1) as u16,
        MaximumLength: package_name.len() as u16,
        Buffer: PSTR(package_name.as_mut_ptr()),
    };
    let mut authentication_package = 0_u32;
    let status = unsafe {
        // SAFETY: `handle` 来自 `LsaConnectUntrusted`，`lsa_string` 指向调用期间有效的 ASCII 字节。
        LsaLookupAuthenticationPackage(handle, &lsa_string, &mut authentication_package)
    };
    log_event(
        "LookupAuthPackage",
        format!(
            "lookup_status={} auth_package={}",
            ntstatus_label(status),
            authentication_package
        ),
    );
    let result = ntstatus_to_result(status).map(|_| authentication_package);
    unsafe {
        // SAFETY: handle 来自 LSA，释放失败不影响当前返回的主错误。
        let _ = LsaDeregisterLogonProcess(handle);
    }
    result
}

fn negotiate_package_name_bytes() -> Vec<u8> {
    b"Negotiate\0".to_vec()
}

fn ntstatus_to_result(status: NTSTATUS) -> Result<()> {
    if status.0 == 0 {
        Ok(())
    } else {
        let win32_error = unsafe {
            // SAFETY: 纯转换函数，不访问外部内存。
            LsaNtStatusToWinError(status)
        };
        Err(Error::from_hresult(HRESULT::from_win32(win32_error)))
    }
}

fn ntstatus_label(status: NTSTATUS) -> String {
    format!("0x{:08X}", status.0)
}

fn result_label(result: &Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => format!("{:?}", error.code()),
    }
}

fn wide_null(value: impl AsRef<str>) -> Vec<u16> {
    value
        .as_ref()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_buffer_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

#[cfg(test)]
mod tests {
    use super::{
        InboundSerialization, RemoteLogonCredential, negotiate_package_name_bytes,
        wide_buffer_to_string,
    };
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
        let source_provider = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
        let cached = InboundSerialization {
            authentication_package: 9,
            source_provider,
            bytes: vec![8_u8, 6, 7],
        };
        let mut output = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();

        cached.write_to(&mut output).unwrap();

        assert_eq!(output.ulAuthenticationPackage, 9);
        assert_eq!(output.clsidCredentialProvider, source_provider);
        assert_eq!(output.cbSerialization, 3);
        assert!(!output.rgbSerialization.is_null());

        unsafe {
            let bytes = std::slice::from_raw_parts(output.rgbSerialization, 3);
            assert_eq!(bytes, &[8_u8, 6, 7]);
            CoTaskMemFree(Some(output.rgbSerialization.cast_const().cast()));
        }
    }

    #[test]
    fn builds_domain_qualified_username_for_repack() {
        let credential = RemoteLogonCredential {
            username: "alice".to_owned(),
            domain: "ACME".to_owned(),
            password: "secret".to_owned(),
        };

        assert_eq!(credential.packed_username(), "ACME\\alice");
    }

    #[test]
    fn keeps_upn_username_for_repack() {
        let credential = RemoteLogonCredential {
            username: "alice@example.com".to_owned(),
            domain: "ACME".to_owned(),
            password: "secret".to_owned(),
        };

        assert_eq!(credential.packed_username(), "alice@example.com");
    }

    #[test]
    fn converts_wide_buffer_until_first_nul() {
        assert_eq!(wide_buffer_to_string(&[65, 66, 0, 67]), "AB");
    }

    #[test]
    fn negotiate_package_name_is_nul_terminated_for_lsa() {
        let bytes = negotiate_package_name_bytes();

        assert_eq!(&bytes[..bytes.len() - 1], b"Negotiate");
        assert_eq!(bytes.last(), Some(&0));
    }
}
