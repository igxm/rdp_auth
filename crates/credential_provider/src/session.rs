//! RDP 会话控制工具。
//!
//! 这里集中封装当前会话断开逻辑，避免 Credential UI、超时定时器等多个模块各自直接操作
//! Remote Desktop Services API。失败时由调用方决定是否显示错误；不能让断开失败影响登录界面。

use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSDisconnectSession};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::core::Result;

pub fn disconnect_current_session() -> Result<()> {
    let mut session_id = 0_u32;
    unsafe {
        // SAFETY: 输出指针指向当前栈变量；失败时返回 HRESULT，不使用未初始化 session id。
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)?;
        WTSDisconnectSession(None, session_id, false)
    }
}
