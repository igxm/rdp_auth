//! 机器码生成和注册表保存。
//!
//! 首次安装时根据机器信息生成稳定机器码并写入注册表，配置文件使用该机器码派生
//! AES-256 key。这个设计满足当前需求，但维护时要记住：机器码存在注册表中，更多
//! 是防止配置文件直接明文落盘，不等同于硬件安全模块级别的密钥保护。

use sha2::{Digest, Sha256};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::login_policy::POLICY_REGISTRY_PATH;

/// AES 配置加密使用的注册表机器码。
pub const VALUE_MACHINE_CODE: &str = "MachineCode";
const MACHINE_GUID_PATH: &str = r"SOFTWARE\Microsoft\Cryptography";
const VALUE_MACHINE_GUID: &str = "MachineGuid";

pub fn ensure_machine_code() -> Result<String, String> {
    if let Some(existing) = load_machine_code() {
        return Ok(existing);
    }

    let machine_code = generate_machine_code();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(POLICY_REGISTRY_PATH)
        .map_err(|error| format!("创建机器码注册表项失败，是否使用管理员运行: {error}"))?;
    key.set_value(VALUE_MACHINE_CODE, &machine_code)
        .map_err(|error| format!("写入机器码失败: {error}"))?;
    Ok(machine_code)
}

pub fn load_machine_code() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(POLICY_REGISTRY_PATH).ok()?;
    let value = key.get_value::<String, _>(VALUE_MACHINE_CODE).ok()?;
    let trimmed = value.trim();
    if is_hex_sha256(trimmed) {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

pub fn derive_aes_key_from_machine_code(machine_code: &str) -> [u8; 32] {
    let digest = Sha256::digest(machine_code.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn generate_machine_code() -> String {
    let mut parts = Vec::new();
    if let Some(machine_guid) = read_machine_guid() {
        parts.push(format!("machine_guid={machine_guid}"));
    }
    for name in [
        "COMPUTERNAME",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(value) = std::env::var_os(name).and_then(|value| value.into_string().ok()) {
            parts.push(format!("{name}={value}"));
        }
    }
    if parts.is_empty() {
        parts.push("rdp_auth_unknown_machine".to_owned());
    }
    hex_sha256(parts.join("|").as_bytes())
}

fn read_machine_guid() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(MACHINE_GUID_PATH).ok()?;
    key.get_value::<String, _>(VALUE_MACHINE_GUID).ok()
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(hex_char(byte >> 4));
        output.push(hex_char(byte & 0x0f));
    }
    output
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble is always <= 15"),
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_aes_key_from_machine_code, hex_sha256, is_hex_sha256};

    #[test]
    fn machine_code_is_sha256_hex() {
        let value = hex_sha256(b"machine");

        assert!(is_hex_sha256(&value));
        assert_eq!(value.len(), 64);
    }

    #[test]
    fn derives_stable_aes_key_from_machine_code() {
        let key_a = derive_aes_key_from_machine_code("abc");
        let key_b = derive_aes_key_from_machine_code("abc");
        let key_c = derive_aes_key_from_machine_code("def");

        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
    }
}
