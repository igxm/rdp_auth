//! GUID 字符串格式化。
//!
//! Windows Credential Provider 注册表路径使用带花括号的大写 CLSID。这个模块只负责格式化，
//! 避免各处手写字符串时出现大小写或分组错误。

use credential_provider::RDP_MFA_PROVIDER_CLSID;

/// 当前 Provider 的 CLSID 字符串，格式为 `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`。
pub fn provider_clsid_string() -> String {
    let guid = RDP_MFA_PROVIDER_CLSID;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

#[cfg(test)]
mod tests {
    use super::provider_clsid_string;

    #[test]
    fn formats_provider_clsid_with_braces() {
        let clsid = provider_clsid_string();
        assert!(clsid.starts_with('{'));
        assert!(clsid.ends_with('}'));
        assert_eq!(clsid.len(), 38);
    }
}
