use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use crate::{ApiError, AuthApiClient, Result};

impl AuthApiClient {
    /// 查询 helper 所在主机的公网出口 IP。
    ///
    /// 这里单独放在 `auth_api`，让 helper 只关心“是否拿到了公网 IP / 是否需要降级”，避免把
    /// HTTP 细节和响应兼容逻辑散落进 `remote_auth` 的审计或短信流程。
    pub fn fetch_public_ip(&self) -> Result<String> {
        if self.uses_placeholder_public_ip_service() {
            return Err(ApiError::NotImplemented {
                operation: "fetch_public_ip",
            });
        }

        let response_text = self
            .get_url(self.public_ip_endpoint())?
            .text()
            .map_err(|_| ApiError::ResponseParse)?;

        parse_public_ip_response(&response_text)
    }
}

#[derive(Debug, Deserialize)]
struct PublicIpEnvelope {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    origin: Option<String>,
}

fn parse_public_ip_response(body: &str) -> Result<String> {
    let body = body.trim();
    if body.is_empty() {
        return Err(ApiError::ResponseParse);
    }

    if let Ok(envelope) = serde_json::from_str::<PublicIpEnvelope>(body) {
        let candidate = envelope
            .ip
            .or(envelope.origin)
            .ok_or(ApiError::ResponseParse)?;
        return parse_public_ip_candidate(&candidate);
    }

    parse_public_ip_candidate(body)
}

fn parse_public_ip_candidate(candidate: &str) -> Result<String> {
    // 部分公网 IP 服务会返回 `x.x.x.x, proxy-ip` 这种形式；helper 只取第一个可解析地址，
    // 并且要求它是公网地址，避免把私网/回环地址误记成公网出口。
    let first = candidate
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::ResponseParse)?;
    let ip = first
        .parse::<IpAddr>()
        .map_err(|_| ApiError::ResponseParse)?;
    if is_public_ip(ip) {
        Ok(first.to_owned())
    } else {
        Err(ApiError::ResponseParse)
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_public_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_public_ipv6(ipv6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_unspecified()
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !ip.is_unique_local()
        && !ip.is_unicast_link_local()
}
