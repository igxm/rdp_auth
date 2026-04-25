//! RDP 客户端地址采集。
//!
//! 这里专门封装按 session 查询 `WTSClientAddress` 的细节，避免审计模块直接接触
//! Windows Remote Desktop API 的内存布局。采集失败时统一降级为 `unknown`，不能影响 MFA 主链路。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientNetworkError {
    QueryFailed,
    InvalidAddress,
    #[cfg_attr(windows, allow(dead_code))]
    UnsupportedPlatform,
}

pub fn rdp_client_ip_string(session_id: u32) -> String {
    match query_rdp_client_ip(session_id) {
        Ok(ip) => ip.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

pub fn query_rdp_client_ip(session_id: u32) -> Result<IpAddr, ClientNetworkError> {
    let address = query_client_address_bytes(session_id)?;
    parse_client_address(address.family, &address.bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientAddressBytes {
    family: u32,
    bytes: [u8; 20],
}

fn parse_client_address(family: u32, bytes: &[u8; 20]) -> Result<IpAddr, ClientNetworkError> {
    #[cfg(windows)]
    {
        use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        if family == u32::from(AF_INET.0) {
            // WTS_CLIENT_ADDRESS 的 IPv4 形状前两个字节保留，真实地址放在 [2..6]。
            let octets = [bytes[2], bytes[3], bytes[4], bytes[5]];
            if octets == [0, 0, 0, 0] {
                return Err(ClientNetworkError::InvalidAddress);
            }
            return Ok(IpAddr::V4(Ipv4Addr::from(octets)));
        }
        if family == u32::from(AF_INET6.0) {
            let octets: [u8; 16] = bytes[0..16]
                .try_into()
                .map_err(|_| ClientNetworkError::InvalidAddress)?;
            let ip = Ipv6Addr::from(octets);
            if ip.is_unspecified() {
                return Err(ClientNetworkError::InvalidAddress);
            }
            return Ok(IpAddr::V6(ip));
        }
    }

    #[cfg(not(windows))]
    let _ = family;
    Err(ClientNetworkError::InvalidAddress)
}

#[cfg(windows)]
fn query_client_address_bytes(session_id: u32) -> Result<ClientAddressBytes, ClientNetworkError> {
    use windows::Win32::System::RemoteDesktop::{
        WTS_CLIENT_ADDRESS, WTSClientAddress, WTSFreeMemory, WTSQuerySessionInformationW,
    };
    use windows::core::PWSTR;

    let mut buffer = PWSTR::null();
    let mut bytes_returned = 0_u32;
    let status = unsafe {
        // SAFETY: 输出缓冲由 WTS API 分配，成功后必须用 WTSFreeMemory 释放；这里只按固定结构读取。
        WTSQuerySessionInformationW(
            None,
            session_id,
            WTSClientAddress,
            &mut buffer,
            &mut bytes_returned,
        )
    };
    if status.is_err()
        || bytes_returned < std::mem::size_of::<WTS_CLIENT_ADDRESS>() as u32
        || buffer.is_null()
    {
        if !buffer.is_null() {
            unsafe { WTSFreeMemory(buffer.0 as _) };
        }
        return Err(ClientNetworkError::QueryFailed);
    }

    let address = unsafe {
        // SAFETY: `bytes_returned` 已校验足够容纳 `WTS_CLIENT_ADDRESS`，缓冲在本函数释放前有效。
        *(buffer.0 as *const WTS_CLIENT_ADDRESS)
    };
    unsafe { WTSFreeMemory(buffer.0 as _) };

    Ok(ClientAddressBytes {
        family: address.AddressFamily,
        bytes: address.Address,
    })
}

#[cfg(not(windows))]
fn query_client_address_bytes(_session_id: u32) -> Result<ClientAddressBytes, ClientNetworkError> {
    Err(ClientNetworkError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::{ClientNetworkError, parse_client_address};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[cfg(windows)]
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    #[test]
    #[cfg(windows)]
    fn parses_ipv4_client_address_from_wts_layout() {
        let mut bytes = [0_u8; 20];
        bytes[2..6].copy_from_slice(&[10, 20, 30, 40]);

        assert_eq!(
            parse_client_address(AF_INET.0.into(), &bytes),
            Ok(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)))
        );
    }

    #[test]
    #[cfg(windows)]
    fn parses_ipv6_client_address_from_wts_layout() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 7);
        let mut bytes = [0_u8; 20];
        bytes[0..16].copy_from_slice(&ip.octets());

        assert_eq!(
            parse_client_address(AF_INET6.0.into(), &bytes),
            Ok(IpAddr::V6(ip))
        );
    }

    #[test]
    #[cfg(windows)]
    fn rejects_empty_or_unknown_client_address() {
        assert_eq!(
            parse_client_address(AF_INET.0.into(), &[0_u8; 20]),
            Err(ClientNetworkError::InvalidAddress)
        );
        assert_eq!(
            parse_client_address(9999, &[0_u8; 20]),
            Err(ClientNetworkError::InvalidAddress)
        );
    }
}
