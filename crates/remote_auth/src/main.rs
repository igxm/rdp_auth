//! 本地二次认证 helper 入口。
//!
//! 后续它会作为 Credential Provider DLL 的外部 helper 运行，负责注册表配置、网络 API、
//! 日志和命名管道。把这些逻辑移出 DLL，是为了让 LogonUI 进程保持轻量、可恢复。

mod mfa;
mod policy;
mod router;
mod session_state;

use std::time::{Duration, Instant};

use auth_ipc::{IpcRequest, IpcResponse};
use session_state::SessionAuthState;

fn main() {
    // 当前先启动为占位程序，后续阶段会替换为命名管道服务。
    // 这里保留一条非敏感输出，方便开发阶段确认二进制可以正常运行。
    let config = auth_config::load_app_config();
    let mut sessions =
        SessionAuthState::new(Duration::from_secs(config.mfa.session_state_ttl_seconds));
    let _ = router::handle_request(
        IpcRequest::GetPolicySnapshot { session_id: 0 },
        &mut sessions,
        Instant::now(),
        policy::load_policy_context_from_disk(),
    );
    let response = IpcResponse::success("remote_auth helper 骨架已启动");
    println!("{}", response.message);
}
