use std::time::Duration;

use auth_config::ApiConfig;
use reqwest::blocking::Client;

use crate::{ApiError, Result};

/// 认证 API 客户端配置快照。
///
/// 这里专门收拢构造、超时和 endpoint 相关逻辑，避免业务接口实现里混入配置归一化细节。
#[derive(Debug, Clone)]
pub struct AuthApiClient {
    pub(crate) base_url: String,
    pub(crate) public_ip_endpoint: String,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) require_public_ip_for_sms: bool,
    pub(crate) http_client: Client,
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

        let connect_timeout = Duration::from_secs(config.connect_timeout_seconds);
        let request_timeout = Duration::from_secs(config.request_timeout_seconds);
        let http_client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|_| ApiError::InvalidConfig {
                reason: "http_client",
            })?;

        Ok(Self {
            base_url: trim_trailing_slash(config.base_url),
            public_ip_endpoint: config.public_ip_endpoint,
            connect_timeout,
            request_timeout,
            require_public_ip_for_sms: config.require_public_ip_for_sms,
            http_client,
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

    pub fn public_ip_endpoint(&self) -> &str {
        &self.public_ip_endpoint
    }

    pub(crate) fn uses_placeholder_public_ip_service(&self) -> bool {
        self.public_ip_endpoint.contains("example.invalid")
    }

    pub(crate) fn uses_placeholder_service(&self) -> bool {
        self.base_url.contains("example.invalid")
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
