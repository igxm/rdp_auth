//! 路径校验和规范化。
//!
//! 注册表里的 `InprocServer32` 必须是稳定的绝对 DLL 路径。这里集中校验路径，避免注册
//! 一个相对路径或拼错路径，导致 LogonUI 加载失败且排查困难。helper 路径也在这里做
//! 显式参数校验，避免管理员把 GUI 或脚本路径误写成核心后台 helper。

use std::path::PathBuf;

/// 规范化 Credential Provider DLL 路径。
pub fn normalize_dll_path(path: PathBuf) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("无法读取当前目录: {error}"))?
            .join(path)
    };

    let canonical = absolute
        .canonicalize()
        .map_err(|error| format!("DLL 路径无效或不存在 `{}`: {error}", absolute.display()))?;

    if !canonical.is_file() {
        return Err(format!("DLL 路径不是文件: {}", canonical.display()));
    }

    let is_dll = canonical
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"));
    if !is_dll {
        return Err(format!(
            "Credential Provider 路径必须是 .dll 文件: {}",
            canonical.display()
        ));
    }

    Ok(canonical)
}

/// 规范化显式传入的 helper EXE 路径。
pub fn normalize_helper_path(path: PathBuf) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("无法读取当前目录: {error}"))?
            .join(path)
    };

    let canonical = absolute
        .canonicalize()
        .map_err(|error| format!("helper 路径无效或不存在 `{}`: {error}", absolute.display()))?;

    if !canonical.is_file() {
        return Err(format!("helper 路径不是文件: {}", canonical.display()));
    }

    let is_exe = canonical
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"));
    if !is_exe {
        return Err(format!(
            "helper 路径必须是 .exe 文件: {}",
            canonical.display()
        ));
    }

    Ok(canonical)
}
