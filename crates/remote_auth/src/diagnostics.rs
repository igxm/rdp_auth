//! helper 脱敏诊断日志。
//!
//! helper 是普通后台进程，可以使用 `tracing` 写结构化日志；Credential Provider DLL 不引入这些
//! 运行时依赖，避免 LogonUI 进程被日志初始化、文件轮转或第三方依赖拖慢。这里所有日志字段都必须先脱敏，
//! 不允许直接记录手机号、验证码、密码、token 或 RDP serialization。
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;

const LOG_FILE_PREFIX: &str = "remote_auth.log";

pub fn init_diagnostics_logging() -> Result<Option<WorkerGuard>> {
    let log_dir = logs_dir();
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("创建 helper 日志目录 `{}` 失败", log_dir.display()))?;

    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE_PREFIX);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(non_blocking)
        .finish();

    match tracing::subscriber::set_global_default(subscriber) {
        Ok(()) => Ok(Some(guard)),
        Err(_) => Ok(None),
    }
}

pub fn logs_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("rdp_auth")
        .join("logs")
}

pub fn sanitize_log_value(value: &str) -> String {
    let normalized = value.replace(['\r', '\n', '\t'], " ");
    mask_long_digit_runs(&normalized)
        .split_whitespace()
        .map(mask_secret_like_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn mask_long_digit_runs(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut run = String::new();
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            run.push(ch);
            continue;
        }
        flush_digit_run(&mut output, &mut run);
        output.push(ch);
    }
    flush_digit_run(&mut output, &mut run);
    output
}

fn flush_digit_run(output: &mut String, run: &mut String) {
    if run.len() >= 6 {
        output.push_str("<redacted-number>");
    } else {
        output.push_str(run);
    }
    run.clear();
}

fn mask_secret_like_token(token: &str) -> &str {
    let lower = token.to_ascii_lowercase();
    if lower.contains("password")
        || lower.contains("token")
        || lower.contains("code")
        || lower.contains("serialization")
    {
        "<redacted-secret>"
    } else {
        token
    }
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
