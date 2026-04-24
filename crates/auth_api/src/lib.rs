//! 服务端认证 API 封装。
//!
//! 网络访问只允许出现在 helper 侧，Credential Provider DLL 不能直接调用本 crate。
//! 这里先把真实 HTTP 请求、错误映射和 mock 服务测试链路落稳，避免后续在 helper
//! 层混入请求拼装细节或把敏感字段打进日志。

use std::time::Duration;

use auth_config::ApiConfig;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

pub type Result<T> = std::result::Result<T, ApiError>;
pub type Error = ApiError;

const SEND_SMS_PATH: &str = "/api/host_instance/getSSHLoginCode";
// 当前仓库里只有短信发送接口路径有旧实现线索，校验路径还没有正式后端契约。
// 这里先收敛成独立常量，便于后续和真实后端对齐时只改一处。
const VERIFY_SMS_PATH: &str = "/api/host_instance/verifySSHLoginCode";

/// 发送短信后由服务端返回的 challenge 元数据。
///
/// `challenge_token` 后续会成为 verify_sms 的唯一校验凭据，因此它只能在 helper 内存
/// 和 helper -> 后端链路中出现，不能回流到 IPC、CP 或日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsChallenge {
    pub challenge_token: String,
    pub expires_in_seconds: u64,
    pub resend_after_seconds: u64,
}

/// API 层可匹配错误。Display 文案必须安全，不能包含手机号、验证码、密码、token
/// 或原始响应体。
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
#[derive(Debug, Clone)]
pub struct AuthApiClient {
    base_url: String,
    public_ip_endpoint: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    require_public_ip_for_sms: bool,
    http_client: Client,
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

    /// 请求发送短信验证码。
    ///
    /// 这里保留完整手机号入参，是因为 helper -> 后端仍需要按真实手机号发起发送请求；
    /// `challenge_token` 不会从这里返回到 CP/IPC，只会留在 helper 内存态。
    pub fn send_sms_code(&self, phone: &str) -> Result<SmsChallenge> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "send_sms_code",
            });
        }
        let response = self
            .post_json(
                SEND_SMS_PATH,
                &SendSmsRequest {
                    phone,
                    host_uuid: None,
                },
            )?
            .json::<SendSmsEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if !response.ok {
            return Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "send_sms_rejected".to_owned()),
            });
        }

        let challenge_token = response
            .challenge_token
            .filter(|value| !value.trim().is_empty())
            .ok_or(ApiError::ResponseParse)?;
        let expires_in_seconds = response.expires_in_seconds.ok_or(ApiError::ResponseParse)?;
        let resend_after_seconds = response
            .resend_after_seconds
            .ok_or(ApiError::ResponseParse)?;

        Ok(SmsChallenge {
            challenge_token,
            expires_in_seconds,
            resend_after_seconds,
        })
    }

    /// 校验短信验证码。固定使用 `challenge_token + code`，不再重复把手机号传给后端。
    pub fn verify_sms_code(&self, challenge_token: &str, code: &str) -> Result<()> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "verify_sms_code",
            });
        }
        let response = self
            .post_json(
                VERIFY_SMS_PATH,
                &VerifySmsRequest {
                    challenge_token,
                    code,
                },
            )?
            .json::<BasicResponseEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if response.ok {
            Ok(())
        } else {
            Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "verify_sms_rejected".to_owned()),
            })
        }
    }

    /// 校验二次密码。具体路径未确定前继续 fail closed。
    pub fn verify_second_password(&self, _password: &str) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "verify_second_password",
        })
    }

    /// 上报登录日志。具体请求结构未确定前继续 fail closed。
    pub fn post_login_log(&self) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "post_login_log",
        })
    }

    fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<Response> {
        let endpoint = self.endpoint_url(path);
        debug!(
            target: "auth_api",
            operation = "post_json",
            path,
            endpoint = %endpoint,
            "auth_api 正在发起 HTTP 请求"
        );
        self.http_client
            .post(endpoint)
            .json(body)
            .send()
            .map_err(map_reqwest_error)?
            .error_for_status()
            .map_err(map_reqwest_error)
    }

    fn uses_placeholder_service(&self) -> bool {
        self.base_url.contains("example.invalid")
    }
}

#[derive(Debug, Serialize)]
struct SendSmsRequest<'a> {
    phone: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_uuid: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct VerifySmsRequest<'a> {
    challenge_token: &'a str,
    code: &'a str,
}

#[derive(Debug, Deserialize)]
struct SendSmsEnvelope {
    ok: bool,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    challenge_token: Option<String>,
    #[serde(default)]
    expires_in_seconds: Option<u64>,
    #[serde(default)]
    resend_after_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BasicResponseEnvelope {
    ok: bool,
    #[serde(default)]
    code: Option<String>,
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

fn map_reqwest_error(error: reqwest::Error) -> ApiError {
    if error.is_timeout() {
        ApiError::Timeout
    } else if let Some(status) = error.status() {
        ApiError::HttpStatus {
            status: status.as_u16(),
        }
    } else {
        ApiError::Network
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, AuthApiClient, SmsChallenge};
    use auth_config::ApiConfig;
    use reqwest::StatusCode;
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
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
        assert_eq!(client.public_ip_endpoint(), "https://auth.example.test/ip");
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
        ];

        for error in cases {
            assert!(!error.user_message().is_empty());
            assert!(error.diagnostic_code().starts_with("api_"));
        }
    }

    #[test]
    fn sms_challenge_shape_is_stable_for_helper_memory_state() {
        let challenge = SmsChallenge {
            challenge_token: "opaque-token".to_owned(),
            expires_in_seconds: 300,
            resend_after_seconds: 60,
        };

        assert_eq!(challenge.challenge_token, "opaque-token");
        assert_eq!(challenge.expires_in_seconds, 300);
        assert_eq!(challenge.resend_after_seconds, 60);
    }

    #[test]
    fn send_sms_code_posts_real_json_and_parses_challenge() {
        let server = MockHttpServer::serve_once(
            200,
            json!({
                "ok": true,
                "challenge_token": "opaque-token",
                "expires_in_seconds": 300,
                "resend_after_seconds": 60
            }),
        );
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        let challenge = client.send_sms_code("13812348888").unwrap();
        let request = server.finish();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/host_instance/getSSHLoginCode");
        assert_eq!(request.json_body["phone"], "13812348888");
        assert!(request.json_body.get("host_uuid").is_none());
        assert_eq!(
            challenge,
            SmsChallenge {
                challenge_token: "opaque-token".to_owned(),
                expires_in_seconds: 300,
                resend_after_seconds: 60,
            }
        );
    }

    #[test]
    fn verify_sms_code_posts_real_json_and_accepts_ok_response() {
        let server = MockHttpServer::serve_once(200, json!({ "ok": true }));
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        client.verify_sms_code("opaque-token", "123456").unwrap();
        let request = server.finish();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/host_instance/verifySSHLoginCode");
        assert_eq!(request.json_body["challenge_token"], "opaque-token");
        assert_eq!(request.json_body["code"], "123456");
    }

    #[test]
    fn server_rejected_response_maps_to_safe_error() {
        let server = MockHttpServer::serve_once(
            200,
            json!({
                "ok": false,
                "code": "bad_code"
            }),
        );
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        let error = client.send_sms_code("13812348888").unwrap_err();

        assert_eq!(
            error,
            ApiError::ServerRejected {
                code: "bad_code".to_owned()
            }
        );
        assert_eq!(error.user_message(), "二次认证未通过");
        let request = server.finish();
        assert_eq!(request.path, "/api/host_instance/getSSHLoginCode");
    }

    #[test]
    fn non_success_http_status_maps_to_http_error() {
        let server = MockHttpServer::serve_once(503, json!({ "ok": false }));
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        let error = client
            .verify_sms_code("opaque-token", "123456")
            .unwrap_err();

        assert_eq!(error, ApiError::HttpStatus { status: 503 });
        let request = server.finish();
        assert_eq!(request.path, "/api/host_instance/verifySSHLoginCode");
    }

    #[test]
    fn malformed_response_maps_to_parse_error_without_echoing_phone() {
        let server = MockHttpServer::serve_once_raw(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{"
                .to_owned(),
        );
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        let error = client.send_sms_code("13812348888").unwrap_err();

        assert_eq!(error, ApiError::ResponseParse);
        assert!(!error.to_string().contains("13812348888"));
        let request = server.finish();
        assert_eq!(request.path, "/api/host_instance/getSSHLoginCode");
    }

    #[test]
    fn placeholder_default_service_keeps_mock_fallback_contract() {
        let client = AuthApiClient::new(ApiConfig::default()).unwrap();

        assert_eq!(
            client.send_sms_code("13812348888").unwrap_err(),
            ApiError::NotImplemented {
                operation: "send_sms_code"
            }
        );
        assert_eq!(
            client
                .verify_sms_code("opaque-token", "123456")
                .unwrap_err(),
            ApiError::NotImplemented {
                operation: "verify_sms_code"
            }
        );
    }

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        json_body: Value,
    }

    struct MockHttpServer {
        base_url: String,
        receiver: mpsc::Receiver<CapturedRequest>,
        handle: thread::JoinHandle<()>,
    }

    impl MockHttpServer {
        fn serve_once(status: u16, body: Value) -> Self {
            let body_text = body.to_string();
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_line(status),
                body_text.len(),
                body_text
            );
            Self::serve_once_raw(response)
        }

        fn serve_once_raw(response: String) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, receiver) = mpsc::channel();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let captured = read_request(&mut stream);
                sender.send(captured).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            });

            Self {
                base_url: format!("http://{}", address),
                receiver,
                handle,
            }
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn finish(self) -> CapturedRequest {
            let request = self.receiver.recv().unwrap();
            self.handle.join().unwrap();
            request
        }
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end;
        loop {
            let bytes_read = stream.read(&mut chunk).unwrap();
            buffer.extend_from_slice(&chunk[..bytes_read]);
            if let Some(index) = find_header_end(&buffer) {
                header_end = index;
                break;
            }
        }

        let header_text = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
        let content_length = parse_content_length(&header_text);
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let bytes_read = stream.read(&mut chunk).unwrap();
            if bytes_read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..bytes_read]);
        }

        let request_line = header_text.lines().next().unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap().to_owned();
        let path = parts.next().unwrap().to_owned();
        let body = &buffer[body_start..body_start + content_length];
        let json_body = serde_json::from_slice(body).unwrap();

        CapturedRequest {
            method,
            path,
            json_body,
        }
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn parse_content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let mut parts = line.splitn(2, ':');
                let name = parts.next()?.trim();
                let value = parts.next()?.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    value.parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn status_line(status: u16) -> &'static str {
        match StatusCode::from_u16(status).unwrap() {
            StatusCode::OK => "200 OK",
            StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
            _ => "500 Internal Server Error",
        }
    }
}
