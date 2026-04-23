//! Windows session notification 接入。
//!
//! 这一层只把 Windows 会话事件转换成 helper 内存态事件；不读取用户信息、不写磁盘、不做登录策略判断。

use std::thread::JoinHandle;

use tracing::{info, warn};

use crate::session_state::{SessionEvent, SharedSessionAuthState};

pub fn apply_session_change(
    sessions: &SharedSessionAuthState,
    session_id: u32,
    event: SessionEvent,
) {
    match sessions.lock() {
        Ok(mut sessions) => {
            // session notification 只是清理 helper 内存态的辅助信号，不能把 lock/unlock
            // 直接解释为“允许登录”。真正放行仍必须由 CP 在 MFA 成功后返回 serialization。
            sessions.record_event(session_id, event);
            info!(
                target: "remote_auth",
                event = "session_notification_handled",
                session_id,
                session_event = session_event_name(event),
                "helper 已处理 Windows session notification"
            );
        }
        Err(error) => {
            warn!(
                target: "remote_auth",
                event = "session_notification_lock_failed",
                session_id,
                session_event = session_event_name(event),
                error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                "helper 处理 session notification 时无法获取状态锁"
            );
        }
    }
}

fn session_event_name(event: SessionEvent) -> &'static str {
    match event {
        SessionEvent::Authenticated => "authenticated",
        SessionEvent::Lock => "lock",
        SessionEvent::Unlock => "unlock",
        SessionEvent::Disconnect => "disconnect",
        SessionEvent::Logoff => "logoff",
        SessionEvent::SessionEnd => "session_end",
        SessionEvent::Cleared => "cleared",
    }
}

#[cfg(windows)]
fn map_windows_session_event(event_code: u32) -> Option<SessionEvent> {
    use windows::Win32::UI::WindowsAndMessaging::{
        WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
        WTS_SESSION_TERMINATE, WTS_SESSION_UNLOCK,
    };

    match event_code {
        WTS_SESSION_LOCK => Some(SessionEvent::Lock),
        WTS_SESSION_UNLOCK => Some(SessionEvent::Unlock),
        WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => Some(SessionEvent::Disconnect),
        WTS_SESSION_LOGOFF => Some(SessionEvent::Logoff),
        WTS_SESSION_TERMINATE => Some(SessionEvent::SessionEnd),
        _ => None,
    }
}

#[cfg(not(windows))]
pub fn start_session_notification_listener(
    _sessions: SharedSessionAuthState,
) -> Option<JoinHandle<()>> {
    None
}

#[cfg(windows)]
pub fn start_session_notification_listener(
    sessions: SharedSessionAuthState,
) -> Option<JoinHandle<()>> {
    Some(std::thread::spawn(move || {
        if let Err(error) = run_session_notification_window(sessions) {
            warn!(
                target: "remote_auth",
                event = "session_notification_listener_failed",
                error = %crate::diagnostics::sanitize_log_value(&error.to_string()),
                "helper session notification 监听线程退出"
            );
        }
    }))
}

#[cfg(windows)]
struct NotificationContext {
    sessions: SharedSessionAuthState,
}

#[cfg(windows)]
fn run_session_notification_window(sessions: SharedSessionAuthState) -> anyhow::Result<()> {
    use anyhow::anyhow;
    use windows::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::RemoteDesktop::{
        NOTIFY_FOR_ALL_SESSIONS, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, HWND_MESSAGE, MSG, RegisterClassW,
        SetWindowLongPtrW, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_NCCREATE,
        WM_NCDESTROY, WM_WTSSESSION_CHANGE, WNDCLASSW,
    };
    use windows::core::PCWSTR;

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_NCCREATE => {
                let create = lparam.0 as *const CREATESTRUCTW;
                if !create.is_null() {
                    let context = unsafe { (*create).lpCreateParams as *mut NotificationContext };
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, context as isize) };
                }
                LRESULT(1)
            }
            WM_WTSSESSION_CHANGE => {
                let context =
                    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const NotificationContext };
                if !context.is_null() {
                    if let Some(event) = map_windows_session_event(wparam.0 as u32) {
                        apply_session_change(
                            unsafe { &(*context).sessions },
                            lparam.0 as u32,
                            event,
                        );
                    }
                }
                LRESULT(0)
            }
            WM_NCDESTROY => {
                let context =
                    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut NotificationContext };
                if !context.is_null() {
                    unsafe {
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                        drop(Box::from_raw(context));
                    }
                }
                unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
            }
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    let class_name: Vec<u16> = "RdpAuthSessionNotificationWindow"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let window_name: Vec<u16> = "rdp_auth_session_notification"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let window_class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..unsafe { std::mem::zeroed() }
    };

    let atom = unsafe { RegisterClassW(&window_class) };
    if atom == 0 {
        let error = unsafe { GetLastError() };
        return Err(anyhow!(
            "注册 session notification 隐藏窗口类失败: {error:?}"
        ));
    }

    let context = Box::into_raw(Box::new(NotificationContext { sessions }));
    let hwnd = match unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(window_name.as_ptr()),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            Some(context.cast()),
        )
    } {
        Ok(hwnd) => hwnd,
        Err(error) => {
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(error.into());
        }
    };

    // Windows 的 session notification 只能投递到窗口句柄。helper 没有 UI，所以使用
    // message-only window 承接 WM_WTSSESSION_CHANGE；窗口上下文里只保存共享 session 状态，
    // 不放用户名、手机号、密码或 serialization，避免系统事件路径携带敏感数据。
    if let Err(error) = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_ALL_SESSIONS) } {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(error.into());
    }
    info!(
        target: "remote_auth",
        event = "session_notification_listener_started",
        "helper 已注册 Windows session notification"
    );

    let mut message = MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 == -1 {
            let error = unsafe { GetLastError() };
            let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };
            let _ = unsafe { DestroyWindow(hwnd) };
            return Err(anyhow!("session notification 消息循环失败: {error:?}"));
        }
        if !result.as_bool() {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };
    let _ = unsafe { DestroyWindow(hwnd) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply_session_change;
    use crate::session_state::{SessionAuthState, SessionEvent, shared_session_state};
    use std::time::{Duration, Instant};

    #[test]
    fn notification_disconnect_clears_authenticated_session() {
        let now = Instant::now();
        let sessions = shared_session_state(SessionAuthState::new(Duration::from_secs(60)));
        sessions.lock().unwrap().mark_authenticated(7, now);

        apply_session_change(&sessions, 7, SessionEvent::Disconnect);

        assert!(!sessions.lock().unwrap().has_authenticated_session(7, now));
    }

    #[test]
    fn notification_lock_keeps_authenticated_session() {
        let now = Instant::now();
        let sessions = shared_session_state(SessionAuthState::new(Duration::from_secs(60)));
        sessions.lock().unwrap().mark_authenticated(7, now);

        apply_session_change(&sessions, 7, SessionEvent::Lock);

        assert!(sessions.lock().unwrap().has_authenticated_session(7, now));
    }

    #[cfg(windows)]
    #[test]
    fn maps_windows_session_events_to_state_events() {
        use super::map_windows_session_event;
        use windows::Win32::UI::WindowsAndMessaging::{
            WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
            WTS_SESSION_TERMINATE, WTS_SESSION_UNLOCK,
        };

        assert_eq!(
            map_windows_session_event(WTS_SESSION_LOCK),
            Some(SessionEvent::Lock)
        );
        assert_eq!(
            map_windows_session_event(WTS_SESSION_UNLOCK),
            Some(SessionEvent::Unlock)
        );
        assert_eq!(
            map_windows_session_event(WTS_CONSOLE_DISCONNECT),
            Some(SessionEvent::Disconnect)
        );
        assert_eq!(
            map_windows_session_event(WTS_REMOTE_DISCONNECT),
            Some(SessionEvent::Disconnect)
        );
        assert_eq!(
            map_windows_session_event(WTS_SESSION_LOGOFF),
            Some(SessionEvent::Logoff)
        );
        assert_eq!(
            map_windows_session_event(WTS_SESSION_TERMINATE),
            Some(SessionEvent::SessionEnd)
        );
        assert_eq!(map_windows_session_event(9999), None);
    }
}
