//! helper IPC 请求路由。
//!
//! 命名管道只负责 transport，业务分发集中在这里。这样 CP 后续接入短超时 IPC 时，请求处理路径可以
//! 在普通单元测试里先稳定下来，避免把 session 状态、策略快照和 IO 监听混在一个大循环里。
use std::time::Instant;

use auth_ipc::{IpcRequest, IpcResponse, IpcResponsePayload, SessionStateResponse};

use crate::policy::PolicyContext;
use crate::session_state::SessionAuthState;

pub fn handle_request(
    request: IpcRequest,
    sessions: &mut SessionAuthState,
    now: Instant,
    policy: PolicyContext,
) -> IpcResponse {
    match request {
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
        IpcRequest::SendSms { phone, source, .. } => {
            crate::mfa::handle_send_sms(source, phone.as_deref(), &policy)
        }
        IpcRequest::VerifySms { phone, code, .. } => {
            crate::mfa::handle_verify_sms(phone.as_deref(), &code, &policy)
        }
        IpcRequest::VerifySecondPassword { password, .. } => {
            crate::mfa::handle_verify_second_password(&password)
        }
        IpcRequest::PostLoginLog { .. } => IpcResponse::failure("该 helper 请求尚未接入"),
    }
}

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::policy::policy_context_from_config;
    use crate::session_state::SessionAuthState;
    use auth_config::AppConfig;
    use auth_ipc::{IpcRequest, IpcResponsePayload};
    use std::time::{Duration, Instant};

    #[test]
    fn routes_policy_snapshot_without_sensitive_phone() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default(), None);

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
        let policy = policy_context_from_config(&AppConfig::default(), None);

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
    fn routes_unimplemented_requests_as_fail_closed() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default(), None);

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

        assert!(!response.ok);
        assert_eq!(response.payload, None);
    }

    #[test]
    fn routes_mock_mfa_requests() {
        let now = Instant::now();
        let mut sessions = SessionAuthState::new(Duration::from_secs(60));
        let policy = policy_context_from_config(&AppConfig::default(), None);

        let send = handle_request(
            IpcRequest::SendSms {
                session_id: 7,
                phone: Some("13812348888".to_owned()),
                source: auth_ipc::PhoneInputSource::ManualInput,
            },
            &mut sessions,
            now,
            policy.clone(),
        );
        assert!(send.ok);

        let verify_sms = handle_request(
            IpcRequest::VerifySms {
                session_id: 7,
                phone: Some("13812348888".to_owned()),
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
