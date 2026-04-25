//! helper 审计 IP 处理。
//!
//! 审计上下文里的 IP 既要支持后续真实后端排障，又不能把完整地址无差别打进日志或审计上报。
//! 因此这里集中放置“公网 IP 查询降级”和“full / masked / off”格式化逻辑，避免各调用点各写一套。

use std::net::IpAddr;

use auth_api::{ApiError as AuthApiError, AuthApiClient};
use auth_config::{AuditConfig, IpLoggingMode};
use tracing::info;

pub trait PublicIpApi {
    fn fetch_public_ip(&self) -> Result<String, AuthApiError>;
}

impl PublicIpApi for AuthApiClient {
    fn fetch_public_ip(&self) -> Result<String, AuthApiError> {
        AuthApiClient::fetch_public_ip(self)
    }
}

pub fn resolve_host_public_ip(
    session_id: u32,
    audit: &AuditConfig,
    api: Option<&impl PublicIpApi>,
) -> String {
    if matches!(audit.ip_logging, IpLoggingMode::Off) {
        return "unknown".to_owned();
    }

    match api {
        Some(api) => match api.fetch_public_ip() {
            Ok(ip) => ip,
            Err(AuthApiError::NotImplemented { .. }) => "unknown".to_owned(),
            Err(error) => {
                info!(
                    target: "remote_auth",
                    event = "audit_public_ip_lookup_failed",
                    session_id,
                    reason = error.diagnostic_code(),
                    "helper 获取公网 IP 失败，审计上下文回退 unknown"
                );
                "unknown".to_owned()
            }
        },
        None => "unknown".to_owned(),
    }
}

pub fn format_ip_field(value: &str, mode: IpLoggingMode) -> String {
    let sanitized = sanitize_ip_value(value);
    match mode {
        IpLoggingMode::Full => sanitized,
        IpLoggingMode::Masked => mask_ip_value(&sanitized),
        IpLoggingMode::Off => "unknown".to_owned(),
    }
}

pub fn format_ip_list(values: &[String], mode: IpLoggingMode) -> Vec<String> {
    match mode {
        IpLoggingMode::Off => Vec::new(),
        IpLoggingMode::Full => values
            .iter()
            .map(|value| sanitize_ip_value(value))
            .collect(),
        IpLoggingMode::Masked => values.iter().map(|value| mask_ip_value(value)).collect(),
    }
}

fn sanitize_ip_value(value: &str) -> String {
    let sanitized =
        crate::diagnostics::sanitize_log_value(value).replace("<redacted-secret>", "<redacted>");
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

fn mask_ip_value(value: &str) -> String {
    let sanitized = sanitize_ip_value(value);
    let ip = match sanitized.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return "unknown".to_owned(),
    };

    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.*", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}:*:*:*:*",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use auth_api::ApiError;
    use auth_config::{AuditConfig, IpLoggingMode};

    use super::{PublicIpApi, format_ip_field, format_ip_list, resolve_host_public_ip};

    struct FakePublicIpApi {
        result: Result<String, ApiError>,
    }

    impl FakePublicIpApi {
        fn success(ip: &str) -> Self {
            Self {
                result: Ok(ip.to_owned()),
            }
        }

        fn reject(error: ApiError) -> Self {
            Self { result: Err(error) }
        }
    }

    impl PublicIpApi for FakePublicIpApi {
        fn fetch_public_ip(&self) -> Result<String, ApiError> {
            self.result.clone()
        }
    }

    #[test]
    fn resolve_host_public_ip_uses_api_when_available() {
        let config = AuditConfig {
            ip_logging: IpLoggingMode::Masked,
            post_login_log: true,
        };

        assert_eq!(
            resolve_host_public_ip(7, &config, Some(&FakePublicIpApi::success("8.8.4.4"))),
            "8.8.4.4"
        );
    }

    #[test]
    fn resolve_host_public_ip_falls_back_to_unknown_when_lookup_fails() {
        let config = AuditConfig {
            ip_logging: IpLoggingMode::Masked,
            post_login_log: true,
        };

        assert_eq!(
            resolve_host_public_ip(
                7,
                &config,
                Some(&FakePublicIpApi::reject(ApiError::HttpStatus {
                    status: 503
                }))
            ),
            "unknown"
        );
    }

    #[test]
    fn resolve_host_public_ip_skips_lookup_when_ip_logging_is_off() {
        let config = AuditConfig {
            ip_logging: IpLoggingMode::Off,
            post_login_log: true,
        };

        assert_eq!(
            resolve_host_public_ip(7, &config, Some(&FakePublicIpApi::success("8.8.4.4"))),
            "unknown"
        );
    }

    #[test]
    fn format_ip_field_obeys_logging_mode() {
        assert_eq!(format_ip_field("8.8.4.4", IpLoggingMode::Full), "8.8.4.4");
        assert_eq!(format_ip_field("8.8.4.4", IpLoggingMode::Masked), "8.8.4.*");
        assert_eq!(format_ip_field("8.8.4.4", IpLoggingMode::Off), "unknown");
    }

    #[test]
    fn format_ip_list_masks_each_value_and_filters_off_mode() {
        let values = vec!["192.168.1.8".to_owned(), "2001:4860:4860::8888".to_owned()];

        assert_eq!(
            format_ip_list(&values, IpLoggingMode::Masked),
            vec![
                "192.168.1.*".to_owned(),
                "2001:4860:4860:0:*:*:*:*".to_owned()
            ]
        );
        assert!(format_ip_list(&values, IpLoggingMode::Off).is_empty());
    }
}
