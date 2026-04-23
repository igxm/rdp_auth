//! Credential Provider 诊断日志。
//!
//! 这里保留为 `auth_logging` 的极薄封装，让 LogonUI 进程内代码仍然只做同步追加写入。
//! 所有磁盘错误都会被吞掉，避免日志目录权限、磁盘或杀毒软件拦截影响 Windows 登录主流程。

use auth_logging::{
    COMPONENT_CREDENTIAL_PROVIDER, CREDENTIAL_PROVIDER_LOG_FILE, DiagnosticRecord,
    append_diagnostic_record,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::GetCurrentProcessId;

/// 写入一条脱敏诊断日志。
pub fn log_event(stage: &str, message: impl AsRef<str>) {
    let session = current_session_label();
    let _ = append_diagnostic_record(
        CREDENTIAL_PROVIDER_LOG_FILE,
        DiagnosticRecord {
            component: COMPONENT_CREDENTIAL_PROVIDER,
            stage,
            message: message.as_ref(),
            pid: Some(std::process::id()),
            session: Some(&session),
        },
    );
}

fn current_session_label() -> String {
    let mut session_id = 0_u32;
    let result = unsafe {
        // SAFETY: 输出指针指向当前栈变量；失败时只记录 unknown，不影响登录流程。
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)
    };
    if result.is_ok() {
        session_id.to_string()
    } else {
        "unknown".to_owned()
    }
}
