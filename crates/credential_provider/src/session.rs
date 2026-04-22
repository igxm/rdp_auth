//! RDP 会话控制工具。
//!
//! 这里集中封装当前会话判断和断开逻辑，避免 Credential UI、超时定时器等多个模块各自直接操作
//! Remote Desktop Services API。失败时由调用方决定是否显示错误；不能让断开失败影响登录界面。

use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSClientProtocolType, WTSDisconnectSession, WTSFreeMemory,
    WTSQuerySessionInformationW,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::core::PWSTR;
use windows::core::Result;

pub fn disconnect_current_session() -> Result<()> {
    let mut session_id = 0_u32;
    unsafe {
        // SAFETY: 输出指针指向当前栈变量；失败时返回 HRESULT，不使用未初始化 session id。
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)?;
        WTSDisconnectSession(None, session_id, false)
    }
}

pub fn is_current_rdp_session() -> bool {
    let Ok(session_id) = current_session_id() else {
        return false;
    };

    let mut buffer = PWSTR::null();
    let mut bytes_returned = 0_u32;
    if unsafe {
        // SAFETY: 输出指针由 WTS API 填充；成功后必须用 WTSFreeMemory 释放。
        WTSQuerySessionInformationW(
            None,
            session_id,
            WTSClientProtocolType,
            &mut buffer,
            &mut bytes_returned,
        )
    }
    .is_err()
    {
        return false;
    }

    let protocol_type = if bytes_returned >= std::mem::size_of::<u16>() as u32 && !buffer.is_null()
    {
        unsafe { *(buffer.0 as *const u16) }
    } else {
        0
    };

    unsafe {
        // SAFETY: `buffer` 来自 WTSQuerySessionInformationW；即使为空指针也允许交给 WTSFreeMemory。
        WTSFreeMemory(buffer.0 as _)
    };
    protocol_type == 2
}

fn current_session_id() -> Result<u32> {
    let mut session_id = 0_u32;
    unsafe {
        // SAFETY: 输出指针指向当前栈变量；失败时返回 HRESULT，不使用未初始化 session id。
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)?;
    }
    Ok(session_id)
}
