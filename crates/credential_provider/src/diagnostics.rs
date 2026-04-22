//! Credential Provider 诊断日志。
//!
//! 这里的日志只用于 VM 排障，必须严格避免写入用户名、密码、验证码、token 或
//! `rgbSerialization` 字节内容。当前只记录阶段、PID、session、Provider GUID、长度和错误码，
//! 方便定位 RDP pass-through 链路断在哪里。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::GetCurrentProcessId;

const LOG_FILE_NAME: &str = "credential_provider.log";

/// 写入一条脱敏诊断日志。
///
/// 诊断日志运行在 LogonUI 相关进程内，所以这里故意吞掉所有 IO 错误，避免日志目录权限、
/// 磁盘或杀毒软件拦截影响 Windows 登录主流程。
pub fn log_event(stage: &str, message: impl AsRef<str>) {
    let _ = write_log_event(stage, message.as_ref());
}

fn write_log_event(stage: &str, message: &str) -> std::io::Result<()> {
    let log_path = log_file_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(
        file,
        "ts_ms={} pid={} session={} stage={} {}",
        unix_time_millis(),
        std::process::id(),
        current_session_label(),
        stage,
        sanitize_message(message)
    )
}

fn log_file_path() -> PathBuf {
    program_data_dir().join("logs").join(LOG_FILE_NAME)
}

#[cfg(not(test))]
fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("rdp_auth")
}

#[cfg(test)]
fn program_data_dir() -> PathBuf {
    std::env::temp_dir().join("rdp_auth_credential_provider_tests")
}

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
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

fn sanitize_message(message: &str) -> String {
    message
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '\t' => ' ',
            _ => character,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sanitize_message;

    #[test]
    fn sanitizes_multiline_message() {
        assert_eq!(sanitize_message("a\nb\rc\td"), "a b c d");
    }
}
