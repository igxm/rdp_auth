//! 本地二次认证 helper 入口。
//!
//! helper 后续会作为 Credential Provider DLL 的外部后台进程运行，负责配置解密、IPC、网络 API、
//! 诊断日志和审计。把这些逻辑移出 DLL，是为了让 LogonUI 进程保持轻量、短超时和可恢复。
//! 这里不能承载 Tauri/WebView GUI：GUI 的窗口循环、前端资源和 WebView2 依赖不应成为 RDP MFA
//! 登录链路的前置条件，GUI 崩溃或缺失也不能改变 CP/helper 的 fail closed 策略。
mod audit;
mod diagnostics;
mod mfa;
mod policy;
mod remote_config;
mod router;
mod session_state;

use std::time::{Duration, Instant};

use anyhow::Result;
use auth_ipc::{IpcRequest, IpcResponse};
use session_state::SessionAuthState;
use tracing::info;

fn main() -> Result<()> {
    let _log_guard = diagnostics::init_diagnostics_logging()?;

    // 当前先启动为占位程序，后续阶段会替换为命名管道服务。这里刻意只走一次 router，
    // 让 helper 启动路径提前覆盖策略快照构建和脱敏日志初始化，但不暴露任何敏感配置内容。
    let config = auth_config::load_app_config();
    let mut sessions =
        SessionAuthState::new(Duration::from_secs(config.mfa.session_state_ttl_seconds));
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
    let _ = router::handle_request(
        IpcRequest::GetPolicySnapshot { session_id: 0 },
        &mut sessions,
        Instant::now(),
        policy,
    );
    let response = IpcResponse::success("remote_auth helper 骨架已启动");
    println!("{}", response.message);
    Ok(())
}
