//! Credential Provider 注册表写入和删除。
//!
//! 这里只处理本 Provider 的固定注册表路径。安装工具必须保持克制，不修改系统默认
//! Credential Provider，也不写 Filter 项；Filter 要等主链路 VM 验证稳定后单独实现。

use std::fmt;
use std::path::PathBuf;

use auth_config::{
    ConfigSnapshot, LoginPolicy, ensure_default_app_config_file, ensure_default_login_policy,
    load_app_config_snapshot, load_login_policy,
};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::dirs::{
    LogDirectoryStatus, ensure_runtime_dirs, log_directory_status, runtime_dirs_status,
};
use crate::guid::{filter_clsid_string, provider_clsid_string};

const PROVIDER_NAME: &str = "RDP Auth MFA Provider";
const THREADING_MODEL: &str = "Apartment";
const CREDENTIAL_PROVIDERS_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
const CREDENTIAL_PROVIDER_FILTERS_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters";
const MACHINE_CLASSES_ROOT: &str = r"SOFTWARE\Classes";

/// 一次安装所需的注册信息。
#[derive(Debug, Clone)]
pub struct ProviderRegistration {
    /// 带花括号的 CLSID 字符串。
    pub clsid: String,
    /// 带花括号的 Filter CLSID 字符串。
    pub filter_clsid: String,
    /// 将写入 `InprocServer32` 默认值的 DLL 绝对路径。
    pub dll_path: PathBuf,
}

impl ProviderRegistration {
    pub fn new(dll_path: PathBuf) -> Result<Self, String> {
        Ok(Self {
            clsid: provider_clsid_string(),
            filter_clsid: filter_clsid_string(),
            dll_path,
        })
    }

    fn credential_provider_key(&self) -> String {
        format!(r"{CREDENTIAL_PROVIDERS_ROOT}\{}", self.clsid)
    }

    fn credential_provider_filter_key(&self) -> String {
        format!(r"{CREDENTIAL_PROVIDER_FILTERS_ROOT}\{}", self.filter_clsid)
    }

    fn provider_clsid_key(&self) -> String {
        self.clsid_key(&self.clsid)
    }

    fn filter_clsid_key(&self) -> String {
        self.clsid_key(&self.filter_clsid)
    }

    fn clsid_key(&self, clsid: &str) -> String {
        format!(r"{MACHINE_CLASSES_ROOT}\CLSID\{clsid}")
    }

    fn provider_inproc_server_key(&self) -> String {
        format!(r"{}\InprocServer32", self.provider_clsid_key())
    }

    fn filter_inproc_server_key(&self) -> String {
        format!(r"{}\InprocServer32", self.filter_clsid_key())
    }
}

/// 健康检查报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub status: RegistrationStatus,
    pub enum_registered: bool,
    pub filter_registered: bool,
    pub dll_exists: bool,
    pub login_policy: LoginPolicy,
    pub app_config: ConfigSnapshot,
    pub runtime_dirs: String,
    pub log_status: LogDirectoryStatus,
}

impl fmt::Display for HealthReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{}", self.status)?;
        writeln!(
            formatter,
            "LogonUI 枚举入口: {}",
            if self.enum_registered {
                "存在"
            } else {
                "缺失/已禁用"
            }
        )?;
        writeln!(
            formatter,
            "Credential Provider Filter: {}",
            if self.filter_registered {
                "存在"
            } else {
                "缺失/已禁用"
            }
        )?;
        writeln!(
            formatter,
            "DLL 文件: {}",
            if self.dll_exists { "存在" } else { "缺失" }
        )?;
        writeln!(formatter, "登录策略:\n{}", self.login_policy)?;
        writeln!(formatter, "业务配置:\n{}", self.app_config)?;
        writeln!(formatter, "{}", self.runtime_dirs)?;
        write!(formatter, "{}", self.log_status)
    }
}

/// 当前注册状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationStatus {
    NotInstalled,
    Installed {
        dll_path: String,
        threading_model: String,
    },
}

impl fmt::Display for RegistrationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => write!(formatter, "未注册 RDP 二次认证 Credential Provider"),
            Self::Installed {
                dll_path,
                threading_model,
            } => {
                write!(
                    formatter,
                    "已注册 RDP 二次认证 Credential Provider\nDLL: {dll_path}\nThreadingModel: {threading_model}"
                )
            }
        }
    }
}

/// 写入 Credential Provider 注册表项。
pub fn register_provider(registration: &ProviderRegistration) -> Result<(), String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    ensure_runtime_dirs()?;
    ensure_default_login_policy()?;
    ensure_default_app_config_file()?;

    // LogonUI 通过这个路径枚举 Credential Provider。默认值只作为显示/诊断名称。
    let (provider_key, _) = hklm
        .create_subkey(registration.credential_provider_key())
        .map_err(|error| {
            format!("写入 Credential Provider 枚举项失败，是否使用管理员运行: {error}")
        })?;
    provider_key
        .set_value("", &PROVIDER_NAME)
        .map_err(|error| format!("写入 Provider 名称失败: {error}"))?;
    let (filter_key, _) = hklm
        .create_subkey(registration.credential_provider_filter_key())
        .map_err(|error| {
            format!("写入 Credential Provider Filter 枚举项失败，是否使用管理员运行: {error}")
        })?;
    filter_key
        .set_value("", &format!("{PROVIDER_NAME} Filter"))
        .map_err(|error| format!("写入 Filter 名称失败: {error}"))?;

    // COM 通过机器级 HKLM\SOFTWARE\Classes\CLSID 找到 DLL。这里不写 HKCU，避免
    // 用户级注册在 LogonUI/RDP 登录场景不可见。
    let (provider_clsid_key, _) = hklm
        .create_subkey(registration.provider_clsid_key())
        .map_err(|error| format!("写入 Provider COM CLSID 项失败，是否使用管理员运行: {error}"))?;
    provider_clsid_key
        .set_value("", &PROVIDER_NAME)
        .map_err(|error| format!("写入 Provider COM 名称失败: {error}"))?;

    let (provider_inproc_key, _) = hklm
        .create_subkey(registration.provider_inproc_server_key())
        .map_err(|error| format!("写入 Provider InprocServer32 项失败: {error}"))?;
    provider_inproc_key
        .set_value("", &registration.dll_path.display().to_string())
        .map_err(|error| format!("写入 Provider DLL 路径失败: {error}"))?;
    provider_inproc_key
        .set_value("ThreadingModel", &THREADING_MODEL)
        .map_err(|error| format!("写入 Provider ThreadingModel 失败: {error}"))?;

    let (filter_clsid_key, _) = hklm
        .create_subkey(registration.filter_clsid_key())
        .map_err(|error| format!("写入 Filter COM CLSID 项失败，是否使用管理员运行: {error}"))?;
    filter_clsid_key
        .set_value("", &format!("{PROVIDER_NAME} Filter"))
        .map_err(|error| format!("写入 Filter COM 名称失败: {error}"))?;
    let (filter_inproc_key, _) = hklm
        .create_subkey(registration.filter_inproc_server_key())
        .map_err(|error| format!("写入 Filter InprocServer32 项失败: {error}"))?;
    filter_inproc_key
        .set_value("", &registration.dll_path.display().to_string())
        .map_err(|error| format!("写入 Filter DLL 路径失败: {error}"))?;
    filter_inproc_key
        .set_value("ThreadingModel", &THREADING_MODEL)
        .map_err(|error| format!("写入 Filter ThreadingModel 失败: {error}"))?;

    Ok(())
}

/// 删除本 Provider 的注册表项。
pub fn unregister_provider() -> Result<(), String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    delete_subkey_tree_if_exists(&hklm, &registration.credential_provider_key())?;
    delete_subkey_tree_if_exists(&hklm, &registration.credential_provider_filter_key())?;
    delete_subkey_tree_if_exists(&hklm, &registration.provider_clsid_key())?;
    delete_subkey_tree_if_exists(&hklm, &registration.filter_clsid_key())?;
    Ok(())
}

/// 应急禁用 LogonUI 枚举入口。
///
/// 这里只删除 Credential Providers 枚举项，保留 COM CLSID 和 InprocServer32，方便后续
/// `health` 排查 DLL 路径，也能用 `enable` 快速恢复。真正完全清理用 `uninstall`。
pub fn disable_provider() -> Result<(), String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    delete_subkey_tree_if_exists(&hklm, &registration.credential_provider_key())?;
    delete_subkey_tree_if_exists(&hklm, &registration.credential_provider_filter_key())
}

/// 重新启用 LogonUI 枚举入口。
pub fn enable_provider() -> Result<(), String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if hklm
        .open_subkey(registration.provider_inproc_server_key())
        .is_err()
    {
        return Err("无法启用：COM InprocServer32 尚未注册，请先执行 install".to_owned());
    }

    let (provider_key, _) = hklm
        .create_subkey(registration.credential_provider_key())
        .map_err(|error| format!("创建 Provider 枚举项失败，是否使用管理员运行: {error}"))?;
    provider_key
        .set_value("", &PROVIDER_NAME)
        .map_err(|error| format!("写入 Provider 名称失败: {error}"))?;
    let (filter_key, _) = hklm
        .create_subkey(registration.credential_provider_filter_key())
        .map_err(|error| format!("创建 Filter 枚举项失败，是否使用管理员运行: {error}"))?;
    filter_key
        .set_value("", &format!("{PROVIDER_NAME} Filter"))
        .map_err(|error| format!("写入 Filter 名称失败: {error}"))?;
    Ok(())
}

/// 查询当前 Provider 是否已注册。
pub fn query_status() -> Result<RegistrationStatus, String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(inproc_key) = hklm.open_subkey(registration.provider_inproc_server_key()) else {
        return Ok(RegistrationStatus::NotInstalled);
    };

    let dll_path: String = inproc_key.get_value("").unwrap_or_default();
    let threading_model: String = inproc_key
        .get_value("ThreadingModel")
        .unwrap_or_else(|_| "<未设置>".to_owned());
    Ok(RegistrationStatus::Installed {
        dll_path,
        threading_model,
    })
}

/// 查询当前登录策略。注册表缺失时返回安全默认值。
pub fn query_login_policy() -> LoginPolicy {
    load_login_policy()
}

/// 查询当前统一业务配置快照。文件不可用时返回内置安全默认值和诊断来源。
pub fn query_app_config() -> ConfigSnapshot {
    load_app_config_snapshot()
}

/// 执行只读健康检查。
pub fn health_check() -> Result<HealthReport, String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let enum_registered = hklm
        .open_subkey(registration.credential_provider_key())
        .is_ok();
    let filter_registered = hklm
        .open_subkey(registration.credential_provider_filter_key())
        .is_ok();
    let status = query_status()?;
    let dll_exists = match &status {
        RegistrationStatus::Installed { dll_path, .. } => PathBuf::from(dll_path).is_file(),
        RegistrationStatus::NotInstalled => false,
    };

    Ok(HealthReport {
        status,
        enum_registered,
        filter_registered,
        dll_exists,
        login_policy: query_login_policy(),
        app_config: load_app_config_snapshot(),
        runtime_dirs: runtime_dirs_status(),
        log_status: log_directory_status(),
    })
}

fn delete_subkey_tree_if_exists(root: &RegKey, path: &str) -> Result<(), String> {
    match root.delete_subkey_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "删除注册表项 `{path}` 失败，是否使用管理员运行: {error}"
        )),
    }
}
