//! 统一日志基础库。
//!
//! Credential Provider 运行在 LogonUI 相关进程内，只能使用轻量同步文件追加；helper 可以使用
//! `tracing` 和 rolling appender。两条路径共享目录、文件名和脱敏规则，避免后续接统一日志时
//! 出现不同程序格式不一致或敏感字段遗漏脱敏。
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const COMPONENT_CREDENTIAL_PROVIDER: &str = "credential_provider";
pub const COMPONENT_REMOTE_AUTH: &str = "remote_auth";
pub const COMPONENT_REGISTER_TOOL: &str = "register_tool";

pub const CREDENTIAL_PROVIDER_LOG_FILE: &str = "credential_provider.log";
pub const REMOTE_AUTH_LOG_PREFIX: &str = "remote_auth.log";
pub const REGISTER_TOOL_LOG_FILE: &str = "register_tool.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticRecord<'a> {
    pub component: &'a str,
    pub stage: &'a str,
    pub message: &'a str,
    pub pid: Option<u32>,
    pub session: Option<&'a str>,
}

pub fn program_data_dir() -> PathBuf {
    program_data_root().join("rdp_auth")
}

pub fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}

pub fn append_diagnostic_record(
    file_name: &str,
    record: DiagnosticRecord<'_>,
) -> std::io::Result<()> {
    let log_path = logs_dir().join(file_name);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(
        file,
        "ts_ms={} component={} pid={} session={} stage={} message={}",
        unix_time_millis(),
        sanitize_token(record.component),
        record
            .pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        record.session.unwrap_or("unknown"),
        sanitize_token(record.stage),
        sanitize_log_value(record.message)
    )
}

pub fn sanitize_log_value(value: &str) -> String {
    let normalized = value.replace(['\r', '\n', '\t'], " ");
    mask_long_digit_runs(&normalized)
        .split_whitespace()
        .map(mask_secret_like_token)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn is_known_diagnostic_log_file(file_name: &str) -> bool {
    file_name.contains(CREDENTIAL_PROVIDER_LOG_FILE)
        || file_name.contains(REMOTE_AUTH_LOG_PREFIX)
        || file_name.contains(REGISTER_TOOL_LOG_FILE)
}

#[cfg(feature = "tracing")]
pub type TracingWorkerGuard = tracing_appender::non_blocking::WorkerGuard;

#[cfg(feature = "tracing")]
pub fn init_tracing_file(log_file_prefix: &str) -> anyhow::Result<Option<TracingWorkerGuard>> {
    let log_dir = logs_dir();
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| anyhow::anyhow!("创建日志目录 `{}` 失败: {error}", log_dir.display()))?;

    let file_appender = tracing_appender::rolling::daily(&log_dir, log_file_prefix);
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

#[cfg(not(test))]
fn program_data_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

#[cfg(test)]
fn program_data_root() -> PathBuf {
    std::env::temp_dir().join("rdp_auth_logging_tests")
}

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
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
    use super::{
        COMPONENT_CREDENTIAL_PROVIDER, CREDENTIAL_PROVIDER_LOG_FILE, DiagnosticRecord,
        append_diagnostic_record, is_known_diagnostic_log_file, logs_dir, sanitize_log_value,
    };

    #[test]
    fn sanitizes_multiline_numbers_and_secret_like_tokens() {
        let sanitized =
            sanitize_log_value("phone=13812348888\ncode=123456 password=mock token=abc");

        assert!(!sanitized.contains("13812348888"));
        assert!(!sanitized.contains("123456"));
        assert!(!sanitized.contains("mock"));
        assert!(!sanitized.contains("token=abc"));
        assert!(!sanitized.contains('\n'));
    }

    #[test]
    fn writes_canonical_diagnostic_line_without_sensitive_content() {
        let _ = std::fs::remove_dir_all(logs_dir());

        append_diagnostic_record(
            CREDENTIAL_PROVIDER_LOG_FILE,
            DiagnosticRecord {
                component: COMPONENT_CREDENTIAL_PROVIDER,
                stage: "SetSerialization",
                message: "serialization=abcdef phone=13812348888",
                pid: Some(42),
                session: Some("7"),
            },
        )
        .unwrap();

        let content =
            std::fs::read_to_string(logs_dir().join(CREDENTIAL_PROVIDER_LOG_FILE)).unwrap();
        assert!(content.contains("component=credential_provider"));
        assert!(content.contains("stage=SetSerialization"));
        assert!(content.contains("pid=42"));
        assert!(content.contains("session=7"));
        assert!(!content.contains("13812348888"));
        assert!(!content.contains("abcdef"));
    }

    #[test]
    fn recognizes_known_diagnostic_log_files() {
        assert!(is_known_diagnostic_log_file("credential_provider.log"));
        assert!(is_known_diagnostic_log_file("remote_auth.log.2026-04-23"));
        assert!(is_known_diagnostic_log_file("register_tool.log"));
        assert!(!is_known_diagnostic_log_file("notes.txt"));
    }
}
