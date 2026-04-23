//! AES 配置文件加解密。
//!
//! 文件格式不再使用 envelope，只保存 `12 字节 nonce + AES-256-GCM 密文`。AES key
//! 来自注册表中的机器码派生值；首次安装由 `machine_code` 模块根据机器信息生成并写入。

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::machine_code::{derive_aes_key_from_machine_code, load_machine_code};

const NONCE_LEN: usize = 12;
const ALGORITHM_NAME: &str = "AES-256-GCM";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFileMetadata {
    pub algorithm: &'static str,
    pub nonce_len: usize,
    pub ciphertext_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigProtectionError {
    MissingMachineCode,
    InvalidCiphertext,
    EncryptFailed,
    DecryptFailed,
}

impl fmt::Display for ConfigProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMachineCode => write!(formatter, "注册表中缺少有效机器码"),
            Self::InvalidCiphertext => write!(formatter, "配置密文格式无效"),
            Self::EncryptFailed => write!(formatter, "AES 加密失败"),
            Self::DecryptFailed => write!(formatter, "AES 解密失败"),
        }
    }
}

impl std::error::Error for ConfigProtectionError {}

pub fn protect_config_bytes(plaintext: &[u8]) -> Result<Vec<u8>, ConfigProtectionError> {
    let machine_code = load_machine_code().ok_or(ConfigProtectionError::MissingMachineCode)?;
    protect_config_bytes_with_machine_code(plaintext, &machine_code)
}

pub fn unprotect_config_bytes(
    protected: &[u8],
) -> Result<(Vec<u8>, ConfigFileMetadata), ConfigProtectionError> {
    let machine_code = load_machine_code().ok_or(ConfigProtectionError::MissingMachineCode)?;
    unprotect_config_bytes_with_machine_code(protected, &machine_code)
}

fn protect_config_bytes_with_machine_code(
    plaintext: &[u8],
    machine_code: &str,
) -> Result<Vec<u8>, ConfigProtectionError> {
    let key_bytes = derive_aes_key_from_machine_code(machine_code);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ConfigProtectionError::EncryptFailed)?;

    let mut protected = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    protected.extend_from_slice(&nonce_bytes);
    protected.extend_from_slice(&ciphertext);
    Ok(protected)
}

fn unprotect_config_bytes_with_machine_code(
    protected: &[u8],
    machine_code: &str,
) -> Result<(Vec<u8>, ConfigFileMetadata), ConfigProtectionError> {
    if protected.len() <= NONCE_LEN {
        return Err(ConfigProtectionError::InvalidCiphertext);
    }

    let (nonce_bytes, ciphertext) = protected.split_at(NONCE_LEN);
    let key_bytes = derive_aes_key_from_machine_code(machine_code);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| ConfigProtectionError::DecryptFailed)?;
    Ok((
        plaintext,
        ConfigFileMetadata {
            algorithm: ALGORITHM_NAME,
            nonce_len: NONCE_LEN,
            ciphertext_len: ciphertext.len(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigProtectionError, NONCE_LEN, protect_config_bytes_with_machine_code,
        unprotect_config_bytes_with_machine_code,
    };

    const MACHINE_CODE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn aes_roundtrips_without_plaintext_leak() {
        let plaintext =
            b"serveraddr = \"https://example.invalid\"\nhostuuid = \"abc\"\nnumber = \"13812348888\"\n";
        let protected = protect_config_bytes_with_machine_code(plaintext, MACHINE_CODE).unwrap();

        assert_eq!(protected.len() > NONCE_LEN, true);
        assert!(!String::from_utf8_lossy(&protected).contains("serveraddr"));
        assert!(!String::from_utf8_lossy(&protected).contains("hostuuid"));
        assert!(!String::from_utf8_lossy(&protected).contains("13812348888"));

        let (decoded, metadata) =
            unprotect_config_bytes_with_machine_code(&protected, MACHINE_CODE).unwrap();
        assert_eq!(decoded, plaintext);
        assert_eq!(metadata.algorithm, "AES-256-GCM");
        assert_eq!(metadata.nonce_len, NONCE_LEN);
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        assert_eq!(
            unprotect_config_bytes_with_machine_code(b"short", MACHINE_CODE).unwrap_err(),
            ConfigProtectionError::InvalidCiphertext
        );
    }

    #[test]
    fn rejects_wrong_machine_code() {
        let protected =
            protect_config_bytes_with_machine_code(b"schema_version = 1", MACHINE_CODE).unwrap();
        let error = unprotect_config_bytes_with_machine_code(
            &protected,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap_err();

        assert_eq!(error, ConfigProtectionError::DecryptFailed);
    }
}
