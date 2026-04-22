//! 本地二次认证 helper 入口。
//!
//! 后续它会作为 Credential Provider DLL 的外部 helper 运行，负责注册表配置、网络 API、
//! 日志和命名管道。把这些逻辑移出 DLL，是为了让 LogonUI 进程保持轻量、可恢复。

mod session_state;

use auth_ipc::IpcResponse;

fn main() {
    // 当前先启动为占位程序，后续阶段会替换为命名管道服务。
    // 这里保留一条非敏感输出，方便开发阶段确认二进制可以正常运行。
    let response = IpcResponse::success("remote_auth helper 骨架已启动");
    println!("{}", response.message);
}
