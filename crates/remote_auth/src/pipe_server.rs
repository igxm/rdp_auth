//! helper 命名管道 transport。
//!
//! 这一层只处理 `\\.\pipe\rdp_auth_helper` 的连接生命周期、单条 JSON 请求读取和单条 JSON 响应写回。
//! session 状态、策略快照和 MFA 业务仍由 `router` 分发，避免把 Windows IO 细节扩散到业务层。

use std::time::Instant;

use auth_ipc::{IpcRequest, IpcResponse};
use tracing::{error, info, warn};

use crate::policy::PolicyContext;
use crate::session_challenge::{
    SharedSmsChallengeState, SmsChallengeState, shared_sms_challenge_state,
};
use crate::session_state::{SessionAuthState, SharedSessionAuthState, shared_session_state};

pub const HELPER_PIPE_PATH: &str = r"\\.\pipe\rdp_auth_helper";
const MAX_REQUEST_BYTES: usize = 64 * 1024;

pub struct PipeServer {
    sessions: SharedSessionAuthState,
    sms_challenges: SharedSmsChallengeState,
    policy: PolicyContext,
}

impl PipeServer {
    pub fn new(
        sessions: SessionAuthState,
        sms_challenges: SmsChallengeState,
        policy: PolicyContext,
    ) -> Self {
        Self {
            sessions: shared_session_state(sessions),
            sms_challenges: shared_sms_challenge_state(sms_challenges),
            policy,
        }
    }

    pub fn sessions(&self) -> SharedSessionAuthState {
        self.sessions.clone()
    }

    fn handle_request_json(&mut self, request_json: &str, now: Instant) -> IpcResponse {
        match IpcRequest::from_json(request_json.trim()) {
            Ok(request) => match (self.sessions.lock(), self.sms_challenges.lock()) {
                (Ok(mut sessions), Ok(mut sms_challenges)) => crate::router::handle_request(
                    request,
                    &mut sessions,
                    &mut sms_challenges,
                    now,
                    self.policy.clone(),
                ),
                (Err(error), _) => {
                    warn!(
                        target: "remote_auth",
                        event = "session_state_lock_failed",
                        error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                        "helper session 状态锁已损坏"
                    );
                    IpcResponse::failure("session 状态不可用")
                }
                (_, Err(error)) => {
                    warn!(
                        target: "remote_auth",
                        event = "sms_challenge_state_lock_failed",
                        error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                        "helper 短信 challenge 状态锁已损坏"
                    );
                    IpcResponse::failure("短信状态不可用")
                }
            },
            Err(error) => {
                warn!(
                    target: "remote_auth",
                    event = "ipc_request_decode_failed",
                    error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                    "helper 收到无法解析的 IPC 请求"
                );
                IpcResponse::failure("IPC 请求格式错误")
            }
        }
    }

    pub fn handle_request_bytes(&mut self, bytes: &[u8], now: Instant) -> IpcResponse {
        if bytes.len() > MAX_REQUEST_BYTES {
            warn!(
                target: "remote_auth",
                event = "ipc_request_too_large",
                bytes_len = bytes.len(),
                "helper 拒绝过大的 IPC 请求"
            );
            return IpcResponse::failure("IPC 请求过大");
        }

        match std::str::from_utf8(bytes) {
            Ok(request_json) => self.handle_request_json(request_json, now),
            Err(error) => {
                warn!(
                    target: "remote_auth",
                    event = "ipc_request_utf8_failed",
                    error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                    "helper 收到非 UTF-8 IPC 请求"
                );
                IpcResponse::failure("IPC 请求编码错误")
            }
        }
    }
}

#[cfg(windows)]
pub fn run_pipe_server(server: &mut PipeServer) -> anyhow::Result<()> {
    use anyhow::anyhow;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{
        FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
        PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows::core::PCWSTR;

    let pipe_name: Vec<u16> = HELPER_PIPE_PATH.encode_utf16().chain(Some(0)).collect();
    info!(
        target: "remote_auth",
        event = "pipe_server_starting",
        pipe = HELPER_PIPE_PATH,
        "helper 命名管道服务开始监听"
    );

    loop {
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                MAX_REQUEST_BYTES as u32,
                MAX_REQUEST_BYTES as u32,
                0,
                None,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            return Err(anyhow!("创建 helper 命名管道失败: {error:?}"));
        }

        let connected = unsafe { ConnectNamedPipe(pipe, None) }.is_ok()
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            let error = unsafe { GetLastError() };
            let _ = unsafe { DisconnectNamedPipe(pipe) };
            let _ = unsafe { CloseHandle(pipe) };
            return Err(anyhow!("连接 helper 命名管道失败: {error:?}"));
        }

        let mut buffer = vec![0u8; MAX_REQUEST_BYTES];
        let mut bytes_read = 0u32;
        let read_ok = unsafe {
            ReadFile(
                pipe,
                Some(buffer.as_mut_slice()),
                Some(&mut bytes_read),
                None,
            )
        };

        let response = match read_ok {
            Ok(()) => server.handle_request_bytes(&buffer[..bytes_read as usize], Instant::now()),
            Err(error) => {
                warn!(
                    target: "remote_auth",
                    event = "pipe_read_failed",
                    error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                    "helper 命名管道读取失败"
                );
                IpcResponse::failure("IPC 请求读取失败")
            }
        };

        let response_json = response
            .to_json()
            .map(|mut json| {
                json.push('\n');
                json
            })
            .unwrap_or_else(|error| {
                error!(
                    target: "remote_auth",
                    event = "ipc_response_encode_failed",
                    error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                    "helper IPC 响应序列化失败"
                );
                "{\"ok\":false,\"message\":\"IPC 响应序列化失败\"}\n".to_owned()
            });

        let mut bytes_written = 0u32;
        let write_result = unsafe {
            WriteFile(
                pipe,
                Some(response_json.as_bytes()),
                Some(&mut bytes_written),
                None,
            )
        };
        if let Err(error) = write_result {
            let last_error = unsafe { GetLastError() };
            if last_error != ERROR_BROKEN_PIPE {
                warn!(
                    target: "remote_auth",
                    event = "pipe_write_failed",
                    error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                    "helper 命名管道写回响应失败"
                );
            }
        } else {
            let _ = unsafe { FlushFileBuffers(pipe) };
        }

        let _ = unsafe { DisconnectNamedPipe(pipe) };
        let _ = unsafe { CloseHandle(pipe) };
    }
}

#[cfg(not(windows))]
pub fn run_pipe_server(_server: &mut PipeServer) -> anyhow::Result<()> {
    anyhow::bail!("helper 命名管道服务仅支持 Windows")
}

#[cfg(test)]
mod tests {
    use super::PipeServer;
    use crate::policy::policy_context_from_config;
    use crate::session_challenge::SmsChallengeState;
    use crate::session_state::SessionAuthState;
    use auth_config::AppConfig;
    use auth_ipc::{IpcRequest, IpcResponsePayload};
    use std::time::{Duration, Instant};

    fn test_server() -> PipeServer {
        PipeServer::new(
            SessionAuthState::new(Duration::from_secs(60)),
            SmsChallengeState::new(Duration::from_secs(120)),
            policy_context_from_config(&AppConfig::default()),
        )
    }

    #[test]
    fn pipe_transport_routes_one_json_request() {
        let mut server = test_server();
        let now = Instant::now();
        let mark = IpcRequest::MarkSessionAuthenticated { session_id: 7 }
            .to_json()
            .unwrap();

        let mark_response = server.handle_request_bytes(mark.as_bytes(), now);
        assert!(mark_response.ok);

        let query = IpcRequest::HasAuthenticatedSession { session_id: 7 }
            .to_json()
            .unwrap();
        let query_response = server.handle_request_bytes(query.as_bytes(), now);
        let Some(IpcResponsePayload::SessionState(state)) = query_response.payload else {
            panic!("expected session state payload");
        };
        assert!(state.authenticated);
    }

    #[test]
    fn pipe_transport_rejects_invalid_request_without_sensitive_echo() {
        let mut server = test_server();

        let response = server.handle_request_bytes(
            b"{\"type\":\"unknown\",\"password\":\"secret\"}",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(!response.to_json().unwrap().contains("secret"));
    }
}
