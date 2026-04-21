//! ProgramData 运行目录初始化。
//!
//! Credential Provider 和 helper 后续都会把脱敏日志、二维码缓存和诊断信息放到
//! `C:\ProgramData\rdp_auth` 下。注册工具负责创建目录，但不写敏感数据。

use std::path::PathBuf;

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
