#![cfg(test)]

use crate::test_support::MockHttpServer;
use crate::{ApiError, AuthApiClient, LoginAuditRecord, SmsChallenge};
use auth_config::ApiConfig;
use serde_json::json;
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
fn post_login_log_posts_real_json_and_accepts_ok_response() {
    let server = MockHttpServer::serve_once(200, json!({ "ok": true }));
    let client = AuthApiClient::new(ApiConfig {
        base_url: server.base_url(),
        public_ip_endpoint: format!("{}/ip", server.base_url()),
        ..Default::default()
    })
    .unwrap();
    let record = LoginAuditRecord {
        request_id: "mfa-7-phone_code".to_owned(),
        session_id: 7,
        client_ip: "unknown".to_owned(),
        host_public_ip: "unknown".to_owned(),
        host_private_ips: vec!["192.168.1.8".to_owned()],
        host_uuid: "host-uuid-001".to_owned(),
        auth_method: "phone_code".to_owned(),
        success: true,
    };

    client.post_login_log(&record).unwrap();
    let request = server.finish();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/host_instance/postSSHLoginLog");
    assert_eq!(request.json_body["request_id"], "mfa-7-phone_code");
    assert_eq!(request.json_body["session_id"], 7);
    assert_eq!(request.json_body["auth_method"], "phone_code");
    assert_eq!(request.json_body["success"], true);
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
fn post_login_log_rejected_response_maps_to_safe_error() {
    let server = MockHttpServer::serve_once(
        200,
        json!({
            "ok": false,
            "code": "audit_rejected"
        }),
    );
    let client = AuthApiClient::new(ApiConfig {
        base_url: server.base_url(),
        public_ip_endpoint: format!("{}/ip", server.base_url()),
        ..Default::default()
    })
    .unwrap();
    let record = LoginAuditRecord {
        request_id: "mfa-7-phone_code".to_owned(),
        session_id: 7,
        client_ip: "unknown".to_owned(),
        host_public_ip: "unknown".to_owned(),
        host_private_ips: vec!["192.168.1.8".to_owned()],
        host_uuid: "host-uuid-001".to_owned(),
        auth_method: "phone_code".to_owned(),
        success: false,
    };

    let error = client.post_login_log(&record).unwrap_err();

    assert_eq!(
        error,
        ApiError::ServerRejected {
            code: "audit_rejected".to_owned()
        }
    );
    assert_eq!(error.user_message(), "二次认证未通过");
}

#[test]
fn placeholder_default_service_keeps_mock_fallback_contract() {
    let client = AuthApiClient::new(ApiConfig::default()).unwrap();
    let record = LoginAuditRecord {
        request_id: "mfa-7-phone_code".to_owned(),
        session_id: 7,
        client_ip: "unknown".to_owned(),
        host_public_ip: "unknown".to_owned(),
        host_private_ips: vec!["192.168.1.8".to_owned()],
        host_uuid: "host-uuid-001".to_owned(),
        auth_method: "phone_code".to_owned(),
        success: true,
    };

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
    assert_eq!(
        client.post_login_log(&record).unwrap_err(),
        ApiError::NotImplemented {
            operation: "post_login_log"
        }
    );
}
