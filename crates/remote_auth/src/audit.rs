//! helper 侧登录审计入口。
//!
//! 真实 `postSSHLoginLog` 接口接入前，这里先把 IPC 请求收口为一条脱敏结构化日志。这样 CP
//! 可以尽早按同一协议调用 helper，同时真实 HTTP 上报失败策略仍保留在后续 API 任务中实现。
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
            host_private_ips: vec!["unknown".to_owned()],
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

pub fn handle_post_login_log(session_id: u32, method: AuthMethod, success: bool) -> IpcResponse {
    let context = AuditContext::for_mfa_request(session_id, method);
    let fields = context.sanitized_fields();
    let result = if success { "success" } else { "failure" };
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
    IpcResponse::success("登录日志已记录")
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
    use super::{AuditContext, auth_method_name, handle_post_login_log};
    use auth_core::AuthMethod;

    #[test]
    fn post_login_log_returns_mock_success_without_payload() {
        let response = handle_post_login_log(7, AuthMethod::PhoneCode, true);

        assert!(response.ok);
        assert_eq!(response.message, "登录日志已记录");
        assert_eq!(response.payload, None);
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
