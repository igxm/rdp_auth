//! 加密配置文件 envelope。
//!
//! 业务配置不能以明文长期落盘。本模块把“文件格式封装”和“具体加密算法”拆开：
//! envelope 负责版本、格式和密文长度，`ConfigCipher` 负责真正加解密。Windows 默认
//! 实现使用 DPAPI 机器级保护，测试则使用可预测的假 cipher，避免单元测试依赖系统密钥。

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
};
use windows::core::w;

const MAGIC: &[u8; 8] = b"RDPAUTHC";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_LEN: usize = 28;
const ALGORITHM_DPAPI_MACHINE: u16 = 1;
#[cfg(test)]
const ALGORITHM_TEST_XOR: u16 = 0xFFFE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextFormat {
    Toml,
    Json,
}

impl PlaintextFormat {
    fn to_u16(self) -> u16 {
        match self {
            Self::Toml => 1,
            Self::Json => 2,
        }
    }

    fn from_u16(value: u16) -> Result<Self, ConfigProtectionError> {
        match value {
            1 => Ok(Self::Toml),
            2 => Ok(Self::Json),
            other => Err(ConfigProtectionError::UnsupportedPlaintextFormat(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEnvelopeMetadata {
    pub version: u16,
    pub algorithm: u16,
    pub plaintext_format: PlaintextFormat,
    pub created_unix_seconds: u64,
    pub ciphertext_len: usize,
}

pub trait ConfigCipher {
    fn algorithm_id(&self) -> u16;
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError>;
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiMachineConfigCipher;

impl ConfigCipher for DpapiMachineConfigCipher {
    fn algorithm_id(&self) -> u16 {
        ALGORITHM_DPAPI_MACHINE
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
        dpapi_protect_machine(plaintext)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
        dpapi_unprotect(ciphertext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigProtectionError {
    PlaintextTooLarge(usize),
    CiphertextTooLarge(usize),
    InvalidMagic,
    TruncatedEnvelope,
    UnsupportedEnvelopeVersion(u16),
    UnsupportedAlgorithm { expected: u16, actual: u16 },
    UnsupportedPlaintextFormat(u16),
    CiphertextLengthMismatch { expected: usize, actual: usize },
    DpapiProtectFailed(String),
    DpapiUnprotectFailed(String),
}

impl fmt::Display for ConfigProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooLarge(len) => write!(formatter, "配置明文过大: {len} bytes"),
            Self::CiphertextTooLarge(len) => write!(formatter, "配置密文过大: {len} bytes"),
            Self::InvalidMagic => write!(formatter, "配置文件 magic 不匹配"),
            Self::TruncatedEnvelope => write!(formatter, "配置文件 envelope 不完整"),
            Self::UnsupportedEnvelopeVersion(version) => {
                write!(formatter, "不支持的配置 envelope 版本: {version}")
            }
            Self::UnsupportedAlgorithm { expected, actual } => write!(
                formatter,
                "配置加密算法不匹配: expected={expected} actual={actual}"
            ),
            Self::UnsupportedPlaintextFormat(format) => {
                write!(formatter, "不支持的配置明文格式: {format}")
            }
            Self::CiphertextLengthMismatch { expected, actual } => write!(
                formatter,
                "配置密文长度不匹配: expected={expected} actual={actual}"
            ),
            Self::DpapiProtectFailed(error) => write!(formatter, "DPAPI 加密失败: {error}"),
            Self::DpapiUnprotectFailed(error) => write!(formatter, "DPAPI 解密失败: {error}"),
        }
    }
}

impl std::error::Error for ConfigProtectionError {}

pub fn protect_config_bytes(
    plaintext: &[u8],
    plaintext_format: PlaintextFormat,
) -> Result<Vec<u8>, ConfigProtectionError> {
    protect_config_bytes_with(
        plaintext,
        plaintext_format,
        SystemTime::now(),
        &DpapiMachineConfigCipher,
    )
}

pub fn unprotect_config_bytes(
    envelope: &[u8],
) -> Result<(Vec<u8>, ConfigEnvelopeMetadata), ConfigProtectionError> {
    unprotect_config_bytes_with(envelope, &DpapiMachineConfigCipher)
}

fn protect_config_bytes_with(
    plaintext: &[u8],
    plaintext_format: PlaintextFormat,
    created_at: SystemTime,
    cipher: &impl ConfigCipher,
) -> Result<Vec<u8>, ConfigProtectionError> {
    if plaintext.len() > u32::MAX as usize {
        return Err(ConfigProtectionError::PlaintextTooLarge(plaintext.len()));
    }

    let ciphertext = cipher.protect(plaintext)?;
    if ciphertext.len() > u32::MAX as usize {
        return Err(ConfigProtectionError::CiphertextTooLarge(ciphertext.len()));
    }

    let created_unix_seconds = created_at
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    envelope.extend_from_slice(&cipher.algorithm_id().to_le_bytes());
    envelope.extend_from_slice(&plaintext_format.to_u16().to_le_bytes());
    envelope.extend_from_slice(&0_u16.to_le_bytes());
    envelope.extend_from_slice(&created_unix_seconds.to_le_bytes());
    envelope.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn unprotect_config_bytes_with(
    envelope: &[u8],
    cipher: &impl ConfigCipher,
) -> Result<(Vec<u8>, ConfigEnvelopeMetadata), ConfigProtectionError> {
    let metadata = parse_metadata(envelope)?;
    if metadata.algorithm != cipher.algorithm_id() {
        return Err(ConfigProtectionError::UnsupportedAlgorithm {
            expected: cipher.algorithm_id(),
            actual: metadata.algorithm,
        });
    }

    let ciphertext = &envelope[HEADER_LEN..];
    let plaintext = cipher.unprotect(ciphertext)?;
    Ok((plaintext, metadata))
}

fn parse_metadata(envelope: &[u8]) -> Result<ConfigEnvelopeMetadata, ConfigProtectionError> {
    if envelope.len() < HEADER_LEN {
        return Err(ConfigProtectionError::TruncatedEnvelope);
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        return Err(ConfigProtectionError::InvalidMagic);
    }

    let version = read_u16(envelope, 8)?;
    if version != ENVELOPE_VERSION {
        return Err(ConfigProtectionError::UnsupportedEnvelopeVersion(version));
    }
    let algorithm = read_u16(envelope, 10)?;
    let plaintext_format = PlaintextFormat::from_u16(read_u16(envelope, 12)?)?;
    let created_unix_seconds = read_u64(envelope, 16)?;
    let ciphertext_len = read_u32(envelope, 24)? as usize;
    let actual_len = envelope.len() - HEADER_LEN;
    if ciphertext_len != actual_len {
        return Err(ConfigProtectionError::CiphertextLengthMismatch {
            expected: ciphertext_len,
            actual: actual_len,
        });
    }

    Ok(ConfigEnvelopeMetadata {
        version,
        algorithm,
        plaintext_format,
        created_unix_seconds,
        ciphertext_len,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ConfigProtectionError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ConfigProtectionError::TruncatedEnvelope)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ConfigProtectionError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ConfigProtectionError::TruncatedEnvelope)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ConfigProtectionError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ConfigProtectionError::TruncatedEnvelope)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn dpapi_protect_machine(plaintext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
    let mut input = blob_from_slice(plaintext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();

    let result = unsafe {
        // SAFETY: 输入 blob 指向调用期间有效的切片；输出 blob 由 DPAPI 分配，调用成功后
        // 立即复制到 Vec，并用 LocalFree 释放。LOCAL_MACHINE 让服务和 LogonUI 均可解密。
        CryptProtectData(
            &mut input,
            w!("rdp_auth_config"),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };
    result.map_err(|error| ConfigProtectionError::DpapiProtectFailed(error.to_string()))?;
    copy_and_free_blob(output).map_err(ConfigProtectionError::DpapiProtectFailed)
}

fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
    let mut input = blob_from_slice(ciphertext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();

    let result = unsafe {
        // SAFETY: 输入 blob 指向调用期间有效的密文切片；输出 blob 由 DPAPI 分配，复制后
        // 用 LocalFree 释放。描述字符串不用于业务判断，避免把敏感信息放入描述。
        CryptUnprotectData(&mut input, None, None, None, None, 0, &mut output)
    };
    result.map_err(|error| ConfigProtectionError::DpapiUnprotectFailed(error.to_string()))?;
    copy_and_free_blob(output).map_err(ConfigProtectionError::DpapiUnprotectFailed)
}

fn blob_from_slice(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, ConfigProtectionError> {
    if bytes.len() > u32::MAX as usize {
        return Err(ConfigProtectionError::PlaintextTooLarge(bytes.len()));
    }
    Ok(CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    })
}

fn copy_and_free_blob(blob: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, String> {
    if blob.pbData.is_null() {
        return Ok(Vec::new());
    }

    let data = unsafe {
        // SAFETY: DPAPI 返回的 blob 指针在 LocalFree 前有效，长度由 cbData 提供。
        std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec()
    };
    unsafe {
        // SAFETY: DPAPI 文档要求用 LocalFree 释放输出 blob。
        let _ = LocalFree(Some(HLOCAL(blob.pbData.cast())));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{
        ALGORITHM_TEST_XOR, ConfigCipher, ConfigProtectionError, PlaintextFormat,
        protect_config_bytes_with, unprotect_config_bytes_with,
    };
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Debug, Clone, Copy)]
    struct XorCipher;

    impl ConfigCipher for XorCipher {
        fn algorithm_id(&self) -> u16 {
            ALGORITHM_TEST_XOR
        }

        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0xA5).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
            Ok(ciphertext.iter().map(|byte| byte ^ 0xA5).collect())
        }
    }

    #[test]
    fn envelope_roundtrips_without_plaintext_leak() {
        let plaintext = b"serveraddr = \"https://example.invalid\"\nhostuuid = \"abc\"\n";
        let envelope = protect_config_bytes_with(
            plaintext,
            PlaintextFormat::Toml,
            UNIX_EPOCH + Duration::from_secs(42),
            &XorCipher,
        )
        .unwrap();

        assert!(!String::from_utf8_lossy(&envelope).contains("serveraddr"));
        assert!(!String::from_utf8_lossy(&envelope).contains("hostuuid"));

        let (decoded, metadata) = unprotect_config_bytes_with(&envelope, &XorCipher).unwrap();
        assert_eq!(decoded, plaintext);
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.algorithm, ALGORITHM_TEST_XOR);
        assert_eq!(metadata.plaintext_format, PlaintextFormat::Toml);
        assert_eq!(metadata.created_unix_seconds, 42);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut envelope = protect_config_bytes_with(
            b"schema_version = 1",
            PlaintextFormat::Toml,
            UNIX_EPOCH,
            &XorCipher,
        )
        .unwrap();
        envelope[0] = b'X';

        assert_eq!(
            unprotect_config_bytes_with(&envelope, &XorCipher).unwrap_err(),
            ConfigProtectionError::InvalidMagic
        );
    }

    #[test]
    fn rejects_truncated_envelope() {
        assert_eq!(
            unprotect_config_bytes_with(b"short", &XorCipher).unwrap_err(),
            ConfigProtectionError::TruncatedEnvelope
        );
    }
}
