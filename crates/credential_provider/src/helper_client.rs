//! Credential Provider 调用 helper 的短超时 IPC 客户端。
//!
//! CP 运行在 LogonUI 相关进程内，任何 helper 调用都只能是短小、可失败、可回退的动作。
//! 这里先实现 `ReportResult status=0` 后的 session 已认证通知：helper 不可用时只写脱敏日志，
//! 不影响 Windows 已经完成的登录结果。

use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use auth_ipc::IpcRequest;

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
}

impl std::fmt::Display for HelperClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionId(error) => write!(formatter, "query_session_failed hresult={error}"),
            Self::Serialize(error) => write!(formatter, "serialize_request_failed error={error}"),
            Self::Open(error) => write!(formatter, "open_helper_pipe_failed error={error}"),
            Self::Write(error) => write!(formatter, "write_helper_pipe_failed error={error}"),
        }
    }
}

/// 通知 helper 当前 Windows session 已完成 MFA。
pub fn mark_current_session_authenticated(timeout: Duration) -> Result<(), HelperClientError> {
    let session_id = current_session_id().map_err(HelperClientError::SessionId)?;
    send_helper_notification(mark_session_authenticated_request(session_id), timeout)
}

fn send_helper_notification(
    request: IpcRequest,
    timeout: Duration,
) -> Result<(), HelperClientError> {
    let request_json = request.to_json().map_err(HelperClientError::Serialize)?;
    let deadline = Instant::now() + timeout;

    loop {
        match OpenOptions::new().write(true).open(HELPER_PIPE_PATH) {
            Ok(mut pipe) => {
                pipe.write_all(request_json.as_bytes())
                    .and_then(|_| pipe.write_all(b"\n"))
                    .and_then(|_| pipe.flush())
                    .map_err(HelperClientError::Write)?;
                return Ok(());
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

fn mark_session_authenticated_request(session_id: u32) -> IpcRequest {
    IpcRequest::MarkSessionAuthenticated { session_id }
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

#[cfg(test)]
mod tests {
    use super::mark_session_authenticated_request;
    use auth_ipc::IpcRequest;

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
}
