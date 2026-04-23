//! helper 脱敏诊断日志。
//!
//! `remote_auth` 是普通后台进程，可以使用 `auth_logging` 中统一封装的 tracing 文件日志。
//! 所有进入 tracing 字段的值都必须先通过统一脱敏函数处理。

use anyhow::Result;
use auth_logging::{REMOTE_AUTH_LOG_PREFIX, TracingWorkerGuard};

pub fn init_diagnostics_logging() -> Result<Option<TracingWorkerGuard>> {
    auth_logging::init_tracing_file(REMOTE_AUTH_LOG_PREFIX)
}

pub fn sanitize_log_value(value: &str) -> String {
    auth_logging::sanitize_log_value(value)
}

#[cfg(test)]
mod tests {
    use super::sanitize_log_value;

    #[test]
    fn sanitizes_phone_code_password_and_multiline_values() {
        let sanitized =
            sanitize_log_value("phone=13812348888\ncode=123456 password=mock-password token=abc");

        assert!(!sanitized.contains("13812348888"));
        assert!(!sanitized.contains("123456"));
        assert!(!sanitized.contains("mock-password"));
        assert!(!sanitized.contains("token=abc"));
        assert!(!sanitized.contains('\n'));
    }
}
