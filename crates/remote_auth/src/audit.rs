//! helper 侧登录审计入口。
//!
//! 真实 `postSSHLoginLog` 接口接入前，这里先把 IPC 请求收口为一条脱敏结构化日志。这样 CP
//! 可以尽早按同一协议调用 helper，同时真实 HTTP 上报失败策略仍保留在后续 API 任务中实现。
use auth_core::AuthMethod;
use auth_ipc::IpcResponse;
use tracing::info;

pub fn handle_post_login_log(session_id: u32, method: AuthMethod, success: bool) -> IpcResponse {
    let method_name = auth_method_name(method);
    let result = if success { "success" } else { "failure" };
    info!(
        target: "remote_auth",
        event = "login_log_recorded",
        session_id,
        auth_method = method_name,
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

#[cfg(test)]
mod tests {
    use super::{auth_method_name, handle_post_login_log};
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
}
