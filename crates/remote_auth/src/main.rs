//! 本地二次认证 helper 入口。
//!
//! helper 作为 Credential Provider DLL 外部的后台进程运行，负责配置解密、IPC、网络 API、诊断日志和审计。
//! 这些逻辑不能进入 LogonUI 进程；GUI 也不能成为 RDP MFA 登录链路的运行依赖。

mod audit;
mod diagnostics;
mod mfa;
mod pipe_server;
mod policy;
mod remote_config;
mod router;
mod session_state;

use std::time::Duration;

use anyhow::Result;
use auth_ipc::IpcResponse;
use session_state::SessionAuthState;
use tracing::info;

fn main() -> Result<()> {
    let _log_guard = diagnostics::init_diagnostics_logging()?;

    let config = auth_config::load_app_config();
    let sessions = SessionAuthState::new(Duration::from_secs(config.mfa.session_state_ttl_seconds));
    let policy = policy::load_policy_context_from_disk();
    info!(
        target: "remote_auth",
        event = "helper_started",
        config_source = "encrypted_or_default",
        session_state_ttl_seconds = config.mfa.session_state_ttl_seconds,
        auth_method_count = policy.snapshot.auth_methods.len(),
        phone_editable = policy.snapshot.phone_editable,
        "helper 脱敏诊断日志已启动"
    );

    let response = IpcResponse::success("remote_auth helper 已启动");
    println!("{}", response.message);
    let mut server = pipe_server::PipeServer::new(sessions, policy);
    pipe_server::run_pipe_server(&mut server)
}
