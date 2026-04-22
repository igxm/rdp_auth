//! ProgramData 运行目录初始化。
//!
//! Credential Provider 和 helper 后续都会把脱敏日志、二维码缓存和诊断信息放到
//! `C:\ProgramData\rdp_auth` 下。注册工具负责创建目录，但不写敏感数据。

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// 日志目录健康状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDirectoryStatus {
    pub path: PathBuf,
    pub exists: bool,
    pub latest_file: Option<LogFileStatus>,
}

/// 最近诊断日志文件的脱敏元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFileStatus {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<u64>,
}

impl fmt::Display for LogDirectoryStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "日志目录: {}", self.path.display())?;
        writeln!(
            formatter,
            "日志目录状态: {}",
            if self.exists { "存在" } else { "缺失" }
        )?;
        if let Some(file) = &self.latest_file {
            writeln!(formatter, "最近诊断日志: {}", file.path.display())?;
            writeln!(formatter, "最近诊断日志大小: {} bytes", file.size_bytes)?;
            if let Some(modified) = file.modified_unix_seconds {
                write!(formatter, "最近诊断日志修改时间: unix_seconds={modified}")?;
            } else {
                write!(formatter, "最近诊断日志修改时间: unknown")?;
            }
        } else {
            write!(formatter, "最近诊断日志: 未找到")?;
        }
        Ok(())
    }
}

/// 应用机器级运行目录。
pub fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("rdp_auth")
}

/// 日志目录。
pub fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}

/// 创建运行目录和日志目录。
pub fn ensure_runtime_dirs() -> Result<(), String> {
    for path in [program_data_dir(), logs_dir()] {
        std::fs::create_dir_all(&path)
            .map_err(|error| format!("创建目录 `{}` 失败: {error}", path.display()))?;
    }
    Ok(())
}

/// 检查运行目录是否存在。
pub fn runtime_dirs_status() -> String {
    let data = program_data_dir();
    let logs = logs_dir();
    format!(
        "ProgramData: {} [{}]\nLogs: {} [{}]",
        data.display(),
        if data.is_dir() { "存在" } else { "缺失" },
        logs.display(),
        if logs.is_dir() { "存在" } else { "缺失" },
    )
}

/// 检查日志目录和最近日志文件。只返回路径、大小和修改时间，不读取日志内容。
pub fn log_directory_status() -> LogDirectoryStatus {
    log_directory_status_for_path(logs_dir())
}

fn log_directory_status_for_path(path: PathBuf) -> LogDirectoryStatus {
    let exists = path.is_dir();
    let latest_file = if exists { latest_log_file(&path) } else { None };

    LogDirectoryStatus {
        path,
        exists,
        latest_file,
    }
}

fn latest_log_file(path: &Path) -> Option<LogFileStatus> {
    std::fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if !file_name.contains("remote_auth.log")
                && !file_name.contains("credential_provider.log")
            {
                return None;
            }
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            Some(LogFileStatus {
                path: entry.path(),
                size_bytes: metadata.len(),
                modified_unix_seconds,
            })
        })
        .max_by_key(|file| file.modified_unix_seconds.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::log_directory_status_for_path;
    use std::fs;

    #[test]
    fn reports_missing_log_directory_without_error() {
        let dir =
            std::env::temp_dir().join(format!("rdp_auth_missing_logs_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let status = log_directory_status_for_path(dir);

        assert!(!status.exists);
        assert_eq!(status.latest_file, None);
    }

    #[test]
    fn reports_latest_diagnostic_log_metadata_without_reading_content() {
        let dir = std::env::temp_dir().join(format!("rdp_auth_logs_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("remote_auth.log.2026-04-22"), "phone=13812348888").unwrap();
        fs::write(dir.join("ignored.txt"), "not a diagnostic log").unwrap();

        let status = log_directory_status_for_path(dir.clone());

        assert!(status.exists);
        let latest = status.latest_file.as_ref().unwrap();
        assert!(latest.path.ends_with("remote_auth.log.2026-04-22"));
        assert!(latest.size_bytes > 0);
        assert!(!status.to_string().contains("13812348888"));

        let _ = fs::remove_dir_all(&dir);
    }
}
