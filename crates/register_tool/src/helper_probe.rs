//! helper 启动探测。
//!
//! `HelperPath` 写入注册表只说明安装工具知道 helper 在哪里，不代表它真的能被系统账户或管理员
//! 启动。health 在这里做一次短启动探测，尽早暴露路径、权限、运行时 DLL 或日志初始化问题。
use std::fmt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperProbeStatus {
    NotConfigured,
    Missing,
    Started { exit_code: Option<i32> },
    Failed { reason: String },
    TimedOut { timeout_ms: u64 },
}

impl fmt::Display for HelperProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(formatter, "未配置"),
            Self::Missing => write!(formatter, "缺失"),
            Self::Started { exit_code } => match exit_code {
                Some(code) => write!(formatter, "可启动，退出码 {code}"),
                None => write!(formatter, "可启动，进程已退出"),
            },
            Self::Failed { reason } => write!(formatter, "启动失败: {reason}"),
            Self::TimedOut { timeout_ms } => {
                write!(
                    formatter,
                    "启动后未在 {timeout_ms} ms 内退出，已终止探测进程"
                )
            }
        }
    }
}

pub fn probe_helper_startup(helper_path: Option<&Path>, timeout: Duration) -> HelperProbeStatus {
    let Some(helper_path) = helper_path else {
        return HelperProbeStatus::NotConfigured;
    };
    if !helper_path.is_file() {
        return HelperProbeStatus::Missing;
    }

    let mut child = match Command::new(helper_path)
        .arg("--health-probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return HelperProbeStatus::Failed {
                reason: error.to_string(),
            };
        }
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return HelperProbeStatus::Started {
                    exit_code: status.code(),
                };
            }
            Ok(None) if Instant::now() < deadline => sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return HelperProbeStatus::TimedOut {
                    timeout_ms: timeout.as_millis() as u64,
                };
            }
            Err(error) => {
                return HelperProbeStatus::Failed {
                    reason: error.to_string(),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HelperProbeStatus, probe_helper_startup};
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn reports_unconfigured_helper() {
        assert_eq!(
            probe_helper_startup(None, Duration::from_millis(10)),
            HelperProbeStatus::NotConfigured
        );
    }

    #[test]
    fn reports_missing_helper() {
        assert_eq!(
            probe_helper_startup(
                Some(Path::new(r"C:\missing\remote_auth.exe")),
                Duration::from_millis(10)
            ),
            HelperProbeStatus::Missing
        );
    }
}
