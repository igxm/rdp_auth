//! helper IPC 请求路由。
//!
//! 命名管道只负责 transport，业务分发集中在这里。这样 CP 后续接入短超时 IPC 时，请求处理路径可以
//! 在普通单元测试里先稳定下来，避免把 session 状态、策略快照和 IO 监听混在一个大循环里。
use std::time::Instant;

use auth_ipc::{IpcRequest, IpcResponse, IpcResponsePayload, SessionStateResponse};
use tracing::info;

use crate::policy::PolicyContext;
use crate::session_state::SessionAuthState;

pub fn handle_request(
    request: IpcRequest,
    sessions: &mut SessionAuthState,
    now: Instant,
    policy: PolicyContext,
) -> IpcResponse {
    let request_kind = request_kind(&request);
    let session_id = request_session_id(&request);
    let response = match request {
        IpcRequest::GetPolicySnapshot { .. } => IpcResponse::success_with_payload(
            "策略已加载",
            IpcResponsePayload::PolicySnapshot(policy.snapshot),
        ),
        IpcRequest::MarkSessionAuthenticated { session_id } => {
            sessions.mark_authenticated(session_id, now);
            IpcResponse::success("session 已标记")
        }
        IpcRequest::HasAuthenticatedSession { session_id } => {
            let authenticated = sessions.has_authenticated_session(session_id, now);
            let ttl_remaining_seconds = sessions
                .ttl_remaining(session_id, now)
                .map(|duration| duration.as_secs());
            IpcResponse::success_with_payload(
                "session 状态已返回",
                IpcResponsePayload::SessionState(SessionStateResponse {
                    session_id,
                    authenticated,
                    ttl_remaining_seconds,
                }),
            )
        }
        IpcRequest::ClearSessionState { session_id } => {
            sessions.clear_session(session_id);
            IpcResponse::success("session 已清理")
        }
        IpcRequest::SendSms {
            phone_choice_id, ..
        } => crate::mfa::handle_send_sms(&phone_choice_id, &policy),
        IpcRequest::VerifySms {
            phone_choice_id,
            code,
            ..
        } => crate::mfa::handle_verify_sms(&phone_choice_id, &code, &policy),
        IpcRequest::VerifySecondPassword { password, .. } => {
            crate::mfa::handle_verify_second_password(&password)
        }
        IpcRequest::PostLoginLog {
            session_id,
            method,
            success,
        } => crate::audit::handle_post_login_log(session_id, method, success),
    };
    info!(
        target: "remote_auth",
        event = "ipc_request_handled",
        request = request_kind,
        session_id,
        ok = response.ok,
        has_payload = response.payload.is_some(),
        message = %crate::diagnostics::sanitize_log_value(&response.message),
        "helper IPC 请求已处理"
    );
    response
}

fn request_kind(request: &IpcRequest) -> &'static str {
    match request {
        IpcRequest::GetPolicySnapshot { .. } => "get_policy_snapshot",
        IpcRequest::MarkSessionAuthenticated { .. } => "mark_session_authenticated",
        IpcRequest::HasAuthenticatedSession { .. } => "has_authenticated_session",
        IpcRequest::ClearSessionState { .. } => "clear_session_state",
        IpcRequest::SendSms { .. } => "send_sms",
        IpcRequest::VerifySms { .. } => "verify_sms",
        IpcRequest::VerifySecondPassword { .. } => "verify_second_password",
        IpcRequest::PostLoginLog { .. } => "post_login_log",
    }
}

fn request_session_id(request: &IpcRequest) -> u32 {
    match request {
        IpcRequest::GetPolicySnapshot { session_id }
        | IpcRequest::MarkSessionAuthenticated { session_id }
        | IpcRequest::HasAuthenticatedSession { session_id }
        | IpcRequest::ClearSessionState { session_id }
        | IpcRequest::SendSms { session_id, .. }
        | IpcRequest::VerifySms { session_id, .. }
        | IpcRequest::VerifySecondPassword { session_id, .. }
        | IpcRequest::PostLoginLog { session_id, .. } => *session_id,
    }
}

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::policy::policy_context_from_config;
    use crate::session_state::SessionAuthState;
    use auth_config::{AppConfig, PhoneConfig, PhoneSource};
    use auth_ipc::{IpcRequest, IpcResponsePayload};
    use std::time::{Duration, Instant};

    #[test]
    fn routes_policy_snapshot_without_sensitive_phone() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default());

        let response = handle_request(
            IpcRequest::GetPolicySnapshot { session_id: 7 },
            &mut sessions,
            now,
            policy,
        );

        assert!(response.ok);
        assert!(matches!(
            response.payload,
            Some(IpcResponsePayload::PolicySnapshot(_))
        ));
    }

    #[test]
    fn routes_session_mark_and_query() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default());

        let mark = handle_request(
            IpcRequest::MarkSessionAuthenticated { session_id: 7 },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(mark.ok);

        let query = handle_request(
            IpcRequest::HasAuthenticatedSession { session_id: 7 },
            &mut sessions,
            now,
            policy,
        );

        let Some(IpcResponsePayload::SessionState(state)) = query.payload else {
            panic!("expected session state payload");
        };
        assert!(state.authenticated);
        assert_eq!(state.ttl_remaining_seconds, Some(60));
    }

    #[test]
    fn routes_session_clear_after_mark() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default());

        let mark = handle_request(
            IpcRequest::MarkSessionAuthenticated { session_id: 7 },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(mark.ok);

        let clear = handle_request(
            IpcRequest::ClearSessionState { session_id: 7 },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(clear.ok);

        let query = handle_request(
            IpcRequest::HasAuthenticatedSession { session_id: 7 },
            &mut sessions,
            now,
            policy,
        );
        let Some(IpcResponsePayload::SessionState(state)) = query.payload else {
            panic!("expected session state payload");
        };
        assert!(!state.authenticated);
        assert_eq!(state.ttl_remaining_seconds, None);
    }

    #[test]
    fn routes_post_login_log_request() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default());

        let response = handle_request(
            IpcRequest::PostLoginLog {
                session_id: 7,
                method: auth_core::AuthMethod::PhoneCode,
                success: false,
            },
            &mut sessions,
            now,
            policy,
        );

        assert!(response.ok);
        assert_eq!(response.message, "登录日志已记录");
        assert_eq!(response.payload, None);
    }

    #[test]
    fn routes_mock_mfa_requests() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig {
            phone: PhoneConfig {
                source: PhoneSource::Config,
                number: "13812348888".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        });

        let send = handle_request(
            IpcRequest::SendSms {
                session_id: 7,
                phone_choice_id: "phone-0".to_owned(),
            },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(send.ok);

        let verify_sms = handle_request(
            IpcRequest::VerifySms {
                session_id: 7,
                phone_choice_id: "phone-0".to_owned(),
                code: "123456".to_owned(),
            },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(verify_sms.ok);

        let verify_password = handle_request(
            IpcRequest::VerifySecondPassword {
                session_id: 7,
                password: "mock-password".to_owned(),
            },
            &mut sessions,
            now,
            policy,
        );
        assert!(verify_password.ok);
    }
}
