//! 服务端认证 API 封装。
//!
//! 网络访问只允许出现在 helper 侧，Credential Provider DLL 不能直接调用本 crate。这样做是为了避免
//! LogonUI 进程被网络超时、TLS 初始化或服务端异常拖住。当前先稳定 API client 的配置、错误类型和
//! 脱敏日志边界；真实 HTTP transport 会在服务端接口路径确认后接入。
use std::time::Duration;

use auth_config::ApiConfig;
use thiserror::Error;
use tracing::debug;

pub type Result<T> = std::result::Result<T, ApiError>;

/// API 层可匹配错误。Display 文案必须安全，不能包含手机号、验证码、密码、token 或原始响应体。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiError {
    #[error("API 配置无效: {reason}")]
    InvalidConfig { reason: &'static str },
    #[error("API 网络请求失败")]
    Network,
    #[error("API 请求超时")]
    Timeout,
    #[error("API HTTP 状态异常: {status}")]
    HttpStatus { status: u16 },
    #[error("API 服务端拒绝: {code}")]
    ServerRejected { code: String },
    #[error("API 响应解析失败")]
    ResponseParse,
    #[error("API 尚未接入: {operation}")]
    NotImplemented { operation: &'static str },
}

impl ApiError {
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "认证服务配置无效，请联系管理员",
            Self::Network | Self::Timeout | Self::HttpStatus { .. } => {
                "认证服务暂时不可用，请稍后重试或联系管理员"
            }
            Self::ServerRejected { .. } => "二次认证未通过",
            Self::ResponseParse => "认证服务响应异常，请联系管理员",
            Self::NotImplemented { .. } => "认证服务尚未接入，请联系管理员",
        }
    }

    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "api_invalid_config",
            Self::Network => "api_network_error",
            Self::Timeout => "api_timeout",
            Self::HttpStatus { .. } => "api_http_status",
            Self::ServerRejected { .. } => "api_server_rejected",
            Self::ResponseParse => "api_response_parse",
            Self::NotImplemented { .. } => "api_not_implemented",
        }
    }
}

/// 认证 API 客户端配置快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthApiClient {
    base_url: String,
    public_ip_endpoint: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    require_public_ip_for_sms: bool,
}

impl AuthApiClient {
    pub fn new(config: ApiConfig) -> Result<Self> {
        let config = config.normalized_for_api_client();
        if !looks_like_http_url(&config.base_url) {
            return Err(ApiError::InvalidConfig { reason: "base_url" });
        }
        if !looks_like_http_url(&config.public_ip_endpoint) {
            return Err(ApiError::InvalidConfig {
                reason: "public_ip_endpoint",
            });
        }

        Ok(Self {
            base_url: trim_trailing_slash(config.base_url),
            public_ip_endpoint: config.public_ip_endpoint,
            connect_timeout: Duration::from_secs(config.connect_timeout_seconds),
            request_timeout: Duration::from_secs(config.request_timeout_seconds),
            require_public_ip_for_sms: config.require_public_ip_for_sms,
        })
    }

    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn require_public_ip_for_sms(&self) -> bool {
        self.require_public_ip_for_sms
    }

    /// 请求发送短信验证码。当前只返回未接入错误，避免维护人员误以为已经调用真实服务端。
    pub fn send_sms_code(&self, _phone: &str) -> Result<()> {
        debug!(
            target: "auth_api",
            operation = "send_sms_code",
            endpoint = %self.endpoint_url("/api/host_instance/getSSHLoginCode"),
            "真实短信 API 尚未接入"
        );
        Err(ApiError::NotImplemented {
            operation: "send_sms_code",
        })
    }

    /// 校验短信验证码。具体路径未确定前不发起网络请求。
    pub fn verify_sms_code(&self, _phone: &str, _code: &str) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "verify_sms_code",
        })
    }

    /// 校验二次密码。具体路径未确定前不发起网络请求。
    pub fn verify_second_password(&self, _password: &str) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "verify_second_password",
        })
    }

    /// 上报登录日志。审计字段后续由 helper 的 AuditContext 提供。
    pub fn post_login_log(&self) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "post_login_log",
        })
    }
}

trait ApiConfigNormalize {
    fn normalized_for_api_client(self) -> Self;
}

impl ApiConfigNormalize for ApiConfig {
    fn normalized_for_api_client(mut self) -> Self {
        if self.connect_timeout_seconds == 0 {
            self.connect_timeout_seconds = 5;
        }
        if self.request_timeout_seconds == 0 {
            self.request_timeout_seconds = 10;
        }
        self
    }
}

fn looks_like_http_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

fn trim_trailing_slash(value: String) -> String {
    value.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::{ApiError, AuthApiClient};
    use auth_config::ApiConfig;
    use std::time::Duration;

    #[test]
    fn client_uses_configured_timeouts_and_urls() {
        let client = AuthApiClient::new(ApiConfig {
            base_url: "https://auth.example.test/".to_owned(),
            public_ip_endpoint: "https://auth.example.test/ip".to_owned(),
            connect_timeout_seconds: 3,
            request_timeout_seconds: 7,
            require_public_ip_for_sms: true,
        })
        .unwrap();

        assert_eq!(
            client.endpoint_url("/api/host_instance/getSSHLoginCode"),
            "https://auth.example.test/api/host_instance/getSSHLoginCode"
        );
        assert_eq!(client.connect_timeout(), Duration::from_secs(3));
        assert_eq!(client.request_timeout(), Duration::from_secs(7));
        assert!(client.require_public_ip_for_sms());
    }

    #[test]
    fn invalid_url_returns_safe_config_error() {
        let error = AuthApiClient::new(ApiConfig {
            base_url: "not-a-url".to_owned(),
            ..Default::default()
        })
        .unwrap_err();

        assert_eq!(error, ApiError::InvalidConfig { reason: "base_url" });
        assert_eq!(error.user_message(), "认证服务配置无效，请联系管理员");
        assert!(!error.to_string().contains("not-a-url"));
    }

    #[test]
    fn api_error_maps_to_diagnostic_codes_and_user_messages() {
        let cases = [
            ApiError::Network,
            ApiError::Timeout,
            ApiError::HttpStatus { status: 500 },
            ApiError::ServerRejected {
                code: "bad_code".to_owned(),
            },
            ApiError::ResponseParse,
            ApiError::NotImplemented {
                operation: "send_sms_code",
            },
        ];

        for error in cases {
            assert!(!error.user_message().is_empty());
            assert!(error.diagnostic_code().starts_with("api_"));
        }
    }

    #[test]
    fn unimplemented_methods_do_not_log_sensitive_inputs() {
        let client = AuthApiClient::new(ApiConfig::default()).unwrap();

        let error = client.send_sms_code("13812348888").unwrap_err();

        assert_eq!(
            error,
            ApiError::NotImplemented {
                operation: "send_sms_code"
            }
        );
        assert!(!error.to_string().contains("13812348888"));
    }
}
