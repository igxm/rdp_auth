//! Credential Provider 注册表写入和删除。
//!
//! 这里只处理本 Provider 的固定注册表路径。安装工具必须保持克制，不修改系统默认
//! Credential Provider，也不写 Filter 项；Filter 要等主链路 VM 验证稳定后单独实现。

use std::fmt;
use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::guid::provider_clsid_string;

const PROVIDER_NAME: &str = "RDP Auth MFA Provider";
const THREADING_MODEL: &str = "Apartment";
const CREDENTIAL_PROVIDERS_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
const MACHINE_CLASSES_ROOT: &str = r"SOFTWARE\Classes";

/// 一次安装所需的注册信息。
#[derive(Debug, Clone)]
pub struct ProviderRegistration {
    /// 带花括号的 CLSID 字符串。
    pub clsid: String,
    /// 将写入 `InprocServer32` 默认值的 DLL 绝对路径。
    pub dll_path: PathBuf,
}

impl ProviderRegistration {
    pub fn new(dll_path: PathBuf) -> Result<Self, String> {
        Ok(Self {
            clsid: provider_clsid_string(),
            dll_path,
        })
    }

    fn credential_provider_key(&self) -> String {
        format!(r"{CREDENTIAL_PROVIDERS_ROOT}\{}", self.clsid)
    }

    fn clsid_key(&self) -> String {
        format!(r"{MACHINE_CLASSES_ROOT}\CLSID\{}", self.clsid)
    }

    fn inproc_server_key(&self) -> String {
        format!(r"{}\InprocServer32", self.clsid_key())
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

    // LogonUI 通过这个路径枚举 Credential Provider。默认值只作为显示/诊断名称。
    let (provider_key, _) = hklm
        .create_subkey(registration.credential_provider_key())
        .map_err(|error| {
            format!("写入 Credential Provider 枚举项失败，是否使用管理员运行: {error}")
        })?;
    provider_key
        .set_value("", &PROVIDER_NAME)
        .map_err(|error| format!("写入 Provider 名称失败: {error}"))?;

    // COM 通过机器级 HKLM\SOFTWARE\Classes\CLSID 找到 DLL。这里不写 HKCU，避免
    // 用户级注册在 LogonUI/RDP 登录场景不可见。
    let (clsid_key, _) = hklm
        .create_subkey(registration.clsid_key())
        .map_err(|error| format!("写入 COM CLSID 项失败，是否使用管理员运行: {error}"))?;
    clsid_key
        .set_value("", &PROVIDER_NAME)
        .map_err(|error| format!("写入 COM 名称失败: {error}"))?;

    let (inproc_key, _) = hklm
        .create_subkey(registration.inproc_server_key())
        .map_err(|error| format!("写入 InprocServer32 项失败: {error}"))?;
    inproc_key
        .set_value("", &registration.dll_path.display().to_string())
        .map_err(|error| format!("写入 DLL 路径失败: {error}"))?;
    inproc_key
        .set_value("ThreadingModel", &THREADING_MODEL)
        .map_err(|error| format!("写入 ThreadingModel 失败: {error}"))?;

    Ok(())
}

/// 删除本 Provider 的注册表项。
pub fn unregister_provider() -> Result<(), String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    delete_subkey_tree_if_exists(&hklm, &registration.credential_provider_key())?;
    delete_subkey_tree_if_exists(&hklm, &registration.clsid_key())?;
    Ok(())
}

/// 查询当前 Provider 是否已注册。
pub fn query_status() -> Result<RegistrationStatus, String> {
    let registration = ProviderRegistration::new(PathBuf::new())?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(inproc_key) = hklm.open_subkey(registration.inproc_server_key()) else {
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

fn delete_subkey_tree_if_exists(root: &RegKey, path: &str) -> Result<(), String> {
    match root.delete_subkey_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "删除注册表项 `{path}` 失败，是否使用管理员运行: {error}"
        )),
    }
}
