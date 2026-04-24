//! Credential Provider 调用 helper 的短超时 IPC 客户端。
//!
//! CP 运行在 LogonUI 相关进程内，任何 helper 调用都只能是短小、可失败、可回退的动作。
//! 这里实现 session 状态相关的最小 IPC：`ReportResult status=0` 后通知 helper 标记当前
//! session，以及缺失 inbound serialization 时查询 helper 是否记得该 session 已认证。

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::thread;
use std::time::{Duration, Instant};

use auth_ipc::{IpcRequest, IpcResponse, IpcResponsePayload, PolicySnapshot, SessionStateResponse};

use crate::diagnostics::log_event;
use crate::session::current_session_id;

const HELPER_PIPE_PATH: &str = r"\\.\pipe\rdp_auth_helper";
const CONNECT_RETRY_SLEEP: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub enum HelperClientError {
    SessionId(windows::core::Error),
    Serialize(auth_ipc::Error),
    Open(std::io::Error),
    Write(std::io::Error),
    Read(std::io::Error),
    Deserialize(auth_ipc::Error),
    EmptyResponse,
    ResponseFailed,
    MissingPayload,
    UnexpectedPayload,
}

impl std::fmt::Display for HelperClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionId(error) => write!(formatter, "query_session_failed hresult={error}"),
            Self::Serialize(error) => write!(formatter, "serialize_request_failed error={error}"),
            Self::Open(error) => write!(formatter, "open_helper_pipe_failed error={error}"),
            Self::Write(error) => write!(formatter, "write_helper_pipe_failed error={error}"),
            Self::Read(error) => write!(formatter, "read_helper_pipe_failed error={error}"),
            Self::Deserialize(error) => {
                write!(formatter, "deserialize_response_failed error={error}")
            }
            Self::EmptyResponse => write!(formatter, "helper_response_empty"),
            Self::ResponseFailed => write!(formatter, "helper_response_failed"),
            Self::MissingPayload => write!(formatter, "helper_response_missing_payload"),
            Self::UnexpectedPayload => write!(formatter, "helper_response_unexpected_payload"),
        }
    }
}

/// 通知 helper 当前 Windows session 已完成 MFA。
pub fn mark_current_session_authenticated(timeout: Duration) -> Result<(), HelperClientError> {
    let session_id = current_session_id().map_err(HelperClientError::SessionId)?;
    send_helper_request(mark_session_authenticated_request(session_id), timeout).map(|_| ())
}

/// 通知 helper 清理当前 Windows session 的内存态认证标记。
///
/// 该请求只携带 session id，不包含用户名、手机号、验证码或 serialization；用于登录失败、
/// 用户取消等 fail closed 路径，避免 helper 内存中残留的成功状态影响后续 LogonUI 判断。
pub fn clear_current_session_state(timeout: Duration) -> Result<(), HelperClientError> {
    let session_id = current_session_id().map_err(HelperClientError::SessionId)?;
    send_helper_request(clear_session_state_request(session_id), timeout).map(|_| ())
}

/// 查询 helper 是否仍持有当前 session 的已认证标记。
///
/// 该结果只能用于选择缺失 serialization 的等待/断开策略，不能作为放行登录的依据；
/// `GetSerialization` 仍必须等 MFA 成功并持有 inbound serialization 后才返回凭证。
pub fn has_current_session_authenticated(
    timeout: Duration,
) -> Result<SessionStateResponse, HelperClientError> {
    let session_id = current_session_id().map_err(HelperClientError::SessionId)?;
    query_session_authenticated_request(session_id, timeout)
}

/// 从 helper 获取 CP 可渲染的脱敏策略快照。
///
/// 策略快照只允许包含认证方式、脱敏手机号、字段可编辑状态和超时配置。CP 不读取配置手机号，
/// 也不接收真实手机号；helper 异常时调用方继续使用本地安全默认值。
pub fn get_current_policy_snapshot(timeout: Duration) -> Result<PolicySnapshot, HelperClientError> {
    let session_id = current_session_id().map_err(HelperClientError::SessionId)?;
    query_policy_snapshot_request(session_id, timeout)
}

fn send_helper_request(
    request: IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, HelperClientError> {
    let request_json = request.to_json().map_err(HelperClientError::Serialize)?;
    let deadline = Instant::now() + timeout;

    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(HELPER_PIPE_PATH)
        {
            Ok(mut pipe) => {
                pipe.write_all(request_json.as_bytes())
                    .and_then(|_| pipe.write_all(b"\n"))
                    .and_then(|_| pipe.flush())
                    .map_err(HelperClientError::Write)?;
                let response = read_response_line(pipe)?;
                if response.ok {
                    return Ok(response);
                }
                return Err(HelperClientError::ResponseFailed);
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(HelperClientError::Open(error));
                }
                thread::sleep(CONNECT_RETRY_SLEEP);
            }
        }
    }
}

fn read_response_line(pipe: std::fs::File) -> Result<IpcResponse, HelperClientError> {
    let mut reader = BufReader::new(pipe);
    let mut response_json = String::new();
    // helper 协议是一条 JSON 响应加换行。CP 不能等待管道 EOF，否则会和
    // helper 的 Flush/Disconnect 时序互相牵制，导致 LogonUI 中短超时 IPC
    // 偶发 fail closed；这里只读取一行并立即返回。
    let bytes_read = reader
        .read_line(&mut response_json)
        .map_err(HelperClientError::Read)?;
    if bytes_read == 0 || response_json.trim().is_empty() {
        return Err(HelperClientError::EmptyResponse);
    }
    IpcResponse::from_json(response_json.trim()).map_err(HelperClientError::Deserialize)
}

fn mark_session_authenticated_request(session_id: u32) -> IpcRequest {
    IpcRequest::MarkSessionAuthenticated { session_id }
}

fn clear_session_state_request(session_id: u32) -> IpcRequest {
    IpcRequest::ClearSessionState { session_id }
}

fn query_session_authenticated_request(
    session_id: u32,
    timeout: Duration,
) -> Result<SessionStateResponse, HelperClientError> {
    let response =
        send_helper_request(IpcRequest::HasAuthenticatedSession { session_id }, timeout)?;
    match response.payload {
        Some(IpcResponsePayload::SessionState(state)) => Ok(state),
        Some(_) => Err(HelperClientError::UnexpectedPayload),
        None => Err(HelperClientError::MissingPayload),
    }
}

fn query_policy_snapshot_request(
    session_id: u32,
    timeout: Duration,
) -> Result<PolicySnapshot, HelperClientError> {
    let response = send_helper_request(IpcRequest::GetPolicySnapshot { session_id }, timeout)?;
    match response.payload {
        Some(IpcResponsePayload::PolicySnapshot(snapshot)) => Ok(snapshot),
        Some(_) => Err(HelperClientError::UnexpectedPayload),
        None => Err(HelperClientError::MissingPayload),
    }
}

/// 记录 helper 通知结果。调用方保持主流程继续，由这里集中保证日志脱敏。
pub fn log_mark_result(result: Result<(), HelperClientError>) {
    match result {
        Ok(()) => log_event("HelperIpc", "mark_session_authenticated_ok"),
        Err(error) => log_event(
            "HelperIpc",
            format!("mark_session_authenticated_failed {error}"),
        ),
    }
}

/// 记录 helper 清理 session 状态结果。清理失败不能改变 CP 的 fail closed 主流程。
pub fn log_clear_result(result: Result<(), HelperClientError>) {
    match result {
        Ok(()) => log_event("HelperIpc", "clear_session_state_ok"),
        Err(error) => log_event("HelperIpc", format!("clear_session_state_failed {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HelperClientError, clear_session_state_request, mark_session_authenticated_request,
    };
    use auth_ipc::{
        IpcRequest, IpcResponse, IpcResponsePayload, PhoneChoiceSnapshot, PolicySnapshot,
        SessionStateResponse,
    };

    #[test]
    fn builds_mark_session_authenticated_request() {
        let request = mark_session_authenticated_request(7);

        assert_eq!(
            request,
            IpcRequest::MarkSessionAuthenticated { session_id: 7 }
        );
        assert!(
            request
                .to_json()
                .unwrap()
                .contains("mark_session_authenticated")
        );
    }

    #[test]
    fn builds_clear_session_state_request() {
        let request = clear_session_state_request(7);

        assert_eq!(request, IpcRequest::ClearSessionState { session_id: 7 });
        assert!(request.to_json().unwrap().contains("clear_session_state"));
        assert_eq!(
            IpcRequest::from_json(&request.to_json().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn builds_has_authenticated_session_request() {
        let request = IpcRequest::HasAuthenticatedSession { session_id: 7 };

        assert!(
            request
                .to_json()
                .unwrap()
                .contains("has_authenticated_session")
        );
        assert_eq!(
            IpcRequest::from_json(&request.to_json().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn builds_get_policy_snapshot_request() {
        let request = IpcRequest::GetPolicySnapshot { session_id: 7 };

        assert!(request.to_json().unwrap().contains("get_policy_snapshot"));
        assert_eq!(
            IpcRequest::from_json(&request.to_json().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn decodes_session_state_response_without_sensitive_payload() {
        let response = IpcResponse::success_with_payload(
            "session 状态已返回",
            IpcResponsePayload::SessionState(SessionStateResponse {
                session_id: 7,
                authenticated: true,
                ttl_remaining_seconds: Some(30),
            }),
        );
        let json = response.to_json().unwrap();

        assert!(json.contains("session_state"));
        assert!(!json.contains("password"));
        assert!(!json.contains("serialization"));
    }

    #[test]
    fn decodes_policy_snapshot_response_without_raw_phone() {
        let response = IpcResponse::success_with_payload(
            "策略已加载",
            IpcResponsePayload::PolicySnapshot(PolicySnapshot {
                auth_methods: vec![auth_core::AuthMethod::PhoneCode],
                phone_source: auth_ipc::PhoneInputSource::Configured,
                masked_phone: Some("138****8888".to_owned()),
                phone_choices: vec![PhoneChoiceSnapshot {
                    id: "phone-0".to_owned(),
                    masked: "138****8888".to_owned(),
                }],
                phone_editable: false,
                mfa_timeout_seconds: 90,
                sms_resend_seconds: 45,
            }),
        );
        let json = response.to_json().unwrap();

        assert!(json.contains("policy_snapshot"));
        assert!(json.contains("138****8888"));
        assert!(!json.contains("13812348888"));
    }

    #[test]
    fn response_errors_do_not_format_sensitive_payloads() {
        assert_eq!(
            HelperClientError::UnexpectedPayload.to_string(),
            "helper_response_unexpected_payload"
        );
        assert_eq!(
            HelperClientError::MissingPayload.to_string(),
            "helper_response_missing_payload"
        );
        assert_eq!(
            HelperClientError::EmptyResponse.to_string(),
            "helper_response_empty"
        );
    }
}
