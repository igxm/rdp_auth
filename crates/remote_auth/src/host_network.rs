//! helper 本机网络地址采集。
//!
//! 这里的地址只用于后续审计上下文，不参与 Credential Provider 放行判断。采集失败必须降级为
//! `unknown`，不能阻塞 MFA；同时只在 helper 进程内调用 Windows IP Helper，避免 CP 进入网络枚举、
//! 权限和系统 API 差异这些复杂边界。

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostNetworkError {
    QueryFailed(u32),
    #[cfg_attr(windows, allow(dead_code))]
    UnsupportedPlatform,
}

/// 返回可用于审计的本机内网 IP 字符串；失败或没有可用地址时返回 `unknown`。
pub fn host_private_ip_strings() -> Vec<String> {
    match collect_host_private_ips() {
        Ok(addresses) if !addresses.is_empty() => addresses
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
        Ok(_) | Err(_) => vec!["unknown".to_owned()],
    }
}

pub fn collect_host_private_ips() -> Result<Vec<IpAddr>, HostNetworkError> {
    collect_candidate_host_ips().map(filter_host_private_ips)
}

fn filter_host_private_ips(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut unique = BTreeSet::new();
    for address in addresses {
        if is_usable_host_ip(&address) {
            unique.insert(address);
        }
    }
    unique.into_iter().collect()
}

fn is_usable_host_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                && !(address.is_loopback()
                    || address.is_link_local()
                    || address.is_unspecified()
                    || address.is_broadcast()
                    || address.octets()[0] == 0)
        }
        IpAddr::V6(address) => {
            is_unique_local_ipv6(address)
                && !(address.is_loopback()
                    || address.is_unicast_link_local()
                    || address.is_unspecified()
                    || address.is_multicast())
        }
    }
}

fn is_unique_local_ipv6(address: &Ipv6Addr) -> bool {
    // 审计字段名是“本机内网 IP”，这里显式只保留 RFC4193 唯一本地地址。
    // 如果未来要记录公网 IPv6，应放到独立字段并受审计配置控制，避免字段语义漂移。
    (address.octets()[0] & 0xfe) == 0xfc
}

#[cfg(windows)]
fn collect_candidate_host_ips() -> Result<Vec<IpAddr>, HostNetworkError> {
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 15_000_u32;
    let mut buffer = vec![0u8; size as usize];

    let mut result = unsafe {
        // SAFETY: Windows 要求调用方提供可写缓冲区和长度。缓冲区生命周期覆盖整个遍历过程；
        // API 只写入适配器链表结构，不保存指针到调用结束之后。
        GetAdaptersAddresses(
            0,
            flags,
            None,
            Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
            &mut size,
        )
    };
    if result == ERROR_BUFFER_OVERFLOW.0 {
        buffer.resize(size as usize, 0);
        result = unsafe {
            // SAFETY: 第二次调用使用 API 返回的所需长度重新分配缓冲区。
            GetAdaptersAddresses(
                0,
                flags,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut size,
            )
        };
    }
    if result != 0 {
        return Err(HostNetworkError::QueryFailed(result));
    }

    let mut addresses = Vec::new();
    let mut adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        let adapter_ref = unsafe {
            // SAFETY: `adapter` 来自 GetAdaptersAddresses 返回的单向链表；循环中只读当前节点。
            &*adapter
        };
        if adapter_ref.OperStatus == IfOperStatusUp {
            let mut unicast = adapter_ref.FirstUnicastAddress;
            while !unicast.is_null() {
                let unicast_ref = unsafe {
                    // SAFETY: `unicast` 属于当前 adapter 的单向链表，缓冲区仍然有效。
                    &*unicast
                };
                if let Some(address) =
                    unsafe { socket_address_to_ip(unicast_ref.Address.lpSockaddr) }
                {
                    addresses.push(address);
                }
                unicast = unicast_ref.Next;
            }
        }
        adapter = adapter_ref.Next;
    }

    Ok(addresses)
}

#[cfg(windows)]
unsafe fn socket_address_to_ip(
    socket_address: *mut windows::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    if socket_address.is_null() {
        return None;
    }

    let family = unsafe { (*socket_address).sa_family };
    if family == AF_INET {
        let address = unsafe { &*(socket_address.cast::<SOCKADDR_IN>()) };
        let octets = unsafe { address.sin_addr.S_un.S_un_b };
        Some(IpAddr::V4(Ipv4Addr::new(
            octets.s_b1,
            octets.s_b2,
            octets.s_b3,
            octets.s_b4,
        )))
    } else if family == AF_INET6 {
        let address = unsafe { &*(socket_address.cast::<SOCKADDR_IN6>()) };
        let octets = unsafe { address.sin6_addr.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

#[cfg(not(windows))]
fn collect_candidate_host_ips() -> Result<Vec<IpAddr>, HostNetworkError> {
    Err(HostNetworkError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::{filter_host_private_ips, host_private_ip_strings};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn filters_loopback_link_local_and_invalid_addresses() {
        let filtered = filter_host_private_ips(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            IpAddr::V6("fd00::8".parse().unwrap()),
        ]);

        assert_eq!(
            filtered,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
                IpAddr::V6("fd00::8".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn host_private_ip_strings_never_returns_empty() {
        assert!(!host_private_ip_strings().is_empty());
    }
}
