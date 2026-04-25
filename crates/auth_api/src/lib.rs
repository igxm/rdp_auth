//! 服务端认证 API 封装。
//!
//! 网络访问只允许出现在 helper 侧，Credential Provider DLL 不能直接调用本 crate。
//! 这里先把真实 HTTP 请求、错误映射和 mock 服务测试链路落稳，避免后续在 helper
//! 层混入请求拼装细节或把敏感字段打进日志。

mod client;
mod error;
mod models;
mod second_password;
mod sms;
mod transport;

pub use client::AuthApiClient;
pub use error::ApiError;
pub use models::SmsChallenge;

pub type Result<T> = std::result::Result<T, ApiError>;
pub type Error = ApiError;
impl AuthApiClient {
    /// 上报登录日志。具体请求结构未确定前继续 fail closed。
    pub fn post_login_log(&self) -> Result<()> {
        Err(ApiError::NotImplemented {
            operation: "post_login_log",
        })
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
    fn verify_second_password_posts_real_json_and_accepts_ok_response() {
        let server = MockHttpServer::serve_once(200, json!({ "ok": true }));
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        client.verify_second_password("mock-password").unwrap();
        let request = server.finish();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/host_instance/verifySecondPassword");
        assert_eq!(request.json_body["password"], "mock-password");
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
    fn verify_second_password_rejected_response_maps_to_safe_error() {
        let server = MockHttpServer::serve_once(
            200,
            json!({
                "ok": false,
                "code": "bad_password"
            }),
        );
        let client = AuthApiClient::new(ApiConfig {
            base_url: server.base_url(),
            public_ip_endpoint: format!("{}/ip", server.base_url()),
            ..Default::default()
        })
        .unwrap();

        let error = client.verify_second_password("wrong-password").unwrap_err();

        assert_eq!(
            error,
            ApiError::ServerRejected {
                code: "bad_password".to_owned()
            }
        );
        assert_eq!(error.user_message(), "二次认证未通过");
        let request = server.finish();
        assert_eq!(request.path, "/api/host_instance/verifySecondPassword");
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
        assert_eq!(
            client.verify_second_password("mock-password").unwrap_err(),
            ApiError::NotImplemented {
                operation: "verify_second_password"
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
