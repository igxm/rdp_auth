//! helper 侧登录审计入口。
//!
//! 审计日志先在 helper 内部统一做脱敏，再决定是写本地诊断日志还是上报到真实服务端，
//! 避免 CP 或 IPC 直接知道审计 HTTP 形状。
use auth_api::{ApiError as AuthApiError, AuthApiClient, LoginAuditRecord};
use auth_config::AppConfig;
use auth_core::AuthMethod;
use auth_ipc::IpcResponse;
use tracing::info;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContext {
    pub request_id: String,
    pub session_id: u32,
    pub client_ip: String,
    pub host_public_ip: String,
    pub host_private_ips: Vec<String>,
    pub host_uuid: String,
    pub method: AuthMethod,
}

impl AuditContext {
    pub fn for_mfa_request(session_id: u32, method: AuthMethod) -> Self {
        Self {
            request_id: request_id_for_session(session_id, method),
            session_id,
            client_ip: "unknown".to_owned(),
            host_public_ip: "unknown".to_owned(),
            host_private_ips: crate::host_network::host_private_ip_strings(),
            host_uuid: "unknown".to_owned(),
            method,
        }
    }

    pub fn sanitized_fields(&self) -> AuditLogFields {
        AuditLogFields {
            request_id: self.request_id.clone(),
            session_id: self.session_id,
            client_ip: sanitize_audit_field(&self.client_ip),
            host_public_ip: sanitize_audit_field(&self.host_public_ip),
            host_private_ips: self
                .host_private_ips
                .iter()
                .map(|value| sanitize_audit_field(value))
                .collect(),
            host_uuid: sanitize_audit_field(&self.host_uuid),
            method: auth_method_name(self.method).to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogFields {
    pub request_id: String,
    pub session_id: u32,
    pub client_ip: String,
    pub host_public_ip: String,
    pub host_private_ips: Vec<String>,
    pub host_uuid: String,
    pub method: String,
}

trait LoginLogApi {
    fn post_login_log(&self, record: &LoginAuditRecord) -> Result<(), AuthApiError>;
}

impl LoginLogApi for AuthApiClient {
    fn post_login_log(&self, record: &LoginAuditRecord) -> Result<(), AuthApiError> {
        AuthApiClient::post_login_log(self, record)
    }
}

pub fn handle_post_login_log(session_id: u32, method: AuthMethod, success: bool) -> IpcResponse {
    let config = auth_config::load_app_config();
    let api_client = match AuthApiClient::new(config.api.clone()) {
        Ok(client) => Some(client),
        Err(error) => {
            info!(
                target: "remote_auth",
                event = "login_log_api_client_invalid",
                session_id,
                reason = error.diagnostic_code(),
                "helper 无法初始化登录日志 API 客户端"
            );
            None
        }
    };
    handle_post_login_log_with_api(session_id, method, success, &config, api_client.as_ref())
}

fn handle_post_login_log_with_api(
    session_id: u32,
    method: AuthMethod,
    success: bool,
    config: &AppConfig,
    api: Option<&impl LoginLogApi>,
) -> IpcResponse {
    let context = AuditContext::for_mfa_request(session_id, method);
    let fields = context.sanitized_fields();
    let result = if success { "success" } else { "failure" };
    if !config.audit.post_login_log {
        info!(
            target: "remote_auth",
            event = "login_log_skipped",
            request_id = %fields.request_id,
            session_id = fields.session_id,
            reason = "audit_disabled",
            "登录日志上报已关闭，helper 跳过远端上报"
        );
        return IpcResponse::success("登录日志已跳过");
    }

    let record = LoginAuditRecord {
        request_id: fields.request_id.clone(),
        session_id: fields.session_id,
        client_ip: fields.client_ip.clone(),
        host_public_ip: fields.host_public_ip.clone(),
        host_private_ips: fields.host_private_ips.clone(),
        host_uuid: fields.host_uuid.clone(),
        auth_method: fields.method.clone(),
        success,
    };

    info!(
        target: "remote_auth",
        event = "login_log_recorded",
        request_id = %fields.request_id,
        session_id = fields.session_id,
        client_ip = %fields.client_ip,
        host_public_ip = %fields.host_public_ip,
        host_private_ips = %fields.host_private_ips.join(","),
        host_uuid = %fields.host_uuid,
        auth_method = %fields.method,
        result,
        "登录日志 mock 已记录"
    );

    match api {
        Some(client) => match client.post_login_log(&record) {
            Ok(()) => IpcResponse::success("登录日志已记录"),
            Err(AuthApiError::NotImplemented { .. }) => IpcResponse::success("登录日志已记录"),
            Err(error) => {
                info!(
                    target: "remote_auth",
                    event = "login_log_upload_failed",
                    request_id = %fields.request_id,
                    session_id = fields.session_id,
                    reason = error.diagnostic_code(),
                    "helper 登录日志远端上报失败"
                );
                IpcResponse::failure(error.user_message())
            }
        },
        None => IpcResponse::failure("认证服务配置无效，请联系管理员"),
    }
}

fn auth_method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::PhoneCode => "phone_code",
        AuthMethod::SecondPassword => "second_password",
        AuthMethod::Wechat => "wechat",
    }
}

fn request_id_for_session(session_id: u32, method: AuthMethod) -> String {
    format!("mfa-{}-{}", session_id, auth_method_name(method))
}

fn sanitize_audit_field(value: &str) -> String {
    let sanitized =
        crate::diagnostics::sanitize_log_value(value).replace("<redacted-secret>", "<redacted>");
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use auth_api::ApiError;
    use auth_config::AppConfig;

    use super::{
        AuditContext, LoginLogApi, auth_method_name, handle_post_login_log,
        handle_post_login_log_with_api,
    };
    use auth_core::AuthMethod;

    #[derive(Clone)]
    struct FakeLoginLogApi {
        calls: Arc<Mutex<Vec<auth_api::LoginAuditRecord>>>,
        result: Result<(), ApiError>,
    }

    impl FakeLoginLogApi {
        fn success() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                result: Ok(()),
            }
        }

        fn reject(result: ApiError) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                result: Err(result),
            }
        }

        fn calls(&self) -> Vec<auth_api::LoginAuditRecord> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl LoginLogApi for FakeLoginLogApi {
        fn post_login_log(
            &self,
            record: &auth_api::LoginAuditRecord,
        ) -> Result<(), auth_api::ApiError> {
            self.calls.lock().unwrap().push(record.clone());
            self.result.clone()
        }
    }

    #[test]
    fn post_login_log_returns_mock_success_without_payload() {
        let response = handle_post_login_log(7, AuthMethod::PhoneCode, true);

        assert!(response.ok);
        assert_eq!(response.message, "登录日志已记录");
        assert_eq!(response.payload, None);
    }

    #[test]
    fn post_login_log_can_be_disabled_by_config() {
        let original = AppConfig::default();
        let disabled = AppConfig {
            audit: auth_config::AuditConfig {
                post_login_log: false,
                ..original.audit.clone()
            },
            ..original
        };
        let response = handle_post_login_log_with_api(
            7,
            AuthMethod::PhoneCode,
            true,
            &disabled,
            None::<&FakeLoginLogApi>,
        );

        assert!(response.ok);
        assert_eq!(response.message, "登录日志已跳过");
    }

    #[test]
    fn post_login_log_uses_auth_api_when_available() {
        let api = FakeLoginLogApi::success();
        let response = handle_post_login_log_with_api(
            7,
            AuthMethod::PhoneCode,
            true,
            &AppConfig::default(),
            Some(&api),
        );

        assert!(response.ok);
        let calls = api.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].request_id, "mfa-7-phone_code");
        assert_eq!(calls[0].auth_method, "phone_code");
        assert!(calls[0].success);
    }

    #[test]
    fn post_login_log_falls_back_to_local_success_when_not_implemented() {
        let api = FakeLoginLogApi::reject(ApiError::NotImplemented {
            operation: "post_login_log",
        });

        let response = handle_post_login_log_with_api(
            7,
            AuthMethod::PhoneCode,
            true,
            &AppConfig::default(),
            Some(&api),
        );

        assert!(response.ok);
        assert_eq!(response.message, "登录日志已记录");
    }

    #[test]
    fn post_login_log_maps_api_errors_to_safe_failure() {
        let api = FakeLoginLogApi::reject(ApiError::HttpStatus { status: 503 });

        let response = handle_post_login_log_with_api(
            7,
            AuthMethod::PhoneCode,
            false,
            &AppConfig::default(),
            Some(&api),
        );

        assert!(!response.ok);
        assert_eq!(
            response.message,
            "认证服务暂时不可用，请稍后重试或联系管理员"
        );
    }

    #[test]
    fn auth_method_names_are_stable_for_audit_logs() {
        assert_eq!(auth_method_name(AuthMethod::PhoneCode), "phone_code");
        assert_eq!(
            auth_method_name(AuthMethod::SecondPassword),
            "second_password"
        );
        assert_eq!(auth_method_name(AuthMethod::Wechat), "wechat");
    }

    #[test]
    fn audit_context_contains_required_fields_without_sensitive_values() {
        let mut context = AuditContext::for_mfa_request(7, AuthMethod::PhoneCode);
        context.client_ip = "10.0.0.8 token=secret".to_owned();
        context.host_public_ip = "203.0.113.9 password=secret".to_owned();
        context.host_private_ips = vec!["192.168.1.8".to_owned(), "code=123456".to_owned()];
        context.host_uuid = "host-uuid-001 serialization=abcdef".to_owned();

        let fields = context.sanitized_fields();
        let serialized = format!("{fields:?}");

        assert_eq!(fields.request_id, "mfa-7-phone_code");
        assert_eq!(fields.session_id, 7);
        assert_eq!(fields.method, "phone_code");
        assert!(serialized.contains("client_ip"));
        assert!(serialized.contains("host_public_ip"));
        assert!(serialized.contains("host_private_ips"));
        assert!(serialized.contains("host_uuid"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("123456"));
        assert!(!serialized.contains("abcdef"));
    }
}
