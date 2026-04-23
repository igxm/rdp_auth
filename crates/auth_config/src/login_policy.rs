//! 注册表最小引导项读取。
//!
//! 这里仅处理 Windows 集成所必需的机器级策略：是否启用 RDP MFA、本地控制台 MFA、
//! 应急禁用开关和统一配置文件路径。业务配置不得继续散落到注册表中。

use std::fmt;
use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::error::{Error, Result};
use crate::file_config::default_config_path;
use crate::machine_code::ensure_machine_code;

/// 本项目自己的策略配置注册表路径。
///
/// 这个路径只保存登录流程策略，不保存服务端 token、验证码、二次密码等敏感内容。
/// Filter 在 LogonUI 进程内只能做极轻量判断，因此这里必须保持字段少、默认值清晰。
/// 删除整个键会回退到代码内置安全默认值和默认配置路径；它不会删除加密配置文件。
pub const POLICY_REGISTRY_PATH: &str = r"SOFTWARE\rdp_auth\config";
/// 是否启用 RDP/NLA 场景二次认证。
///
/// 缺失时默认启用。误删该值不会绕过 RDP MFA，但手工置 0 会让 RDP 暂时不进入二次认证。
pub const VALUE_ENABLE_RDP_MFA: &str = "EnableRdpMfa";
/// 是否启用本地控制台登录二次认证。
///
/// 缺失时默认关闭，避免测试阶段把本地维护入口锁住。置 1 前必须确认 VM 快照和恢复手段。
pub const VALUE_ENABLE_CONSOLE_MFA: &str = "EnableConsoleMfa";
/// 应急禁用开关。置为 1 时 Filter 和后续 Provider 逻辑都应尽量放开，避免锁死机器。
///
/// 这是最高优先级恢复开关。删除该值等价于关闭应急禁用；遇到登录异常时应置 1 而不是
/// 盲目删除系统 Credential Provider 注册项。
pub const VALUE_DISABLE_MFA: &str = "DisableMfa";
/// 统一配置文件路径。注册表只保存这个引导路径，不保存业务策略细节。
///
/// 删除后回退到 `C:\ProgramData\rdp_auth\config\rdp_auth.toml.enc`。路径错误会导致
/// 运行期使用安全默认配置，但不会读取长期明文 TOML。
pub const VALUE_CONFIG_PATH: &str = "ConfigPath";
/// 核心 helper 启动路径。
///
/// 该值只记录无 UI 后台 helper 的固定 EXE 路径，Credential Provider 后续只能按短超时
/// IPC 调用 helper，不能把 Tauri GUI 或用户目录中的临时程序写到这里。
pub const VALUE_HELPER_PATH: &str = "HelperPath";

/// 登录场景策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginPolicy {
    /// RDP / NLA 远程登录是否需要进入二次认证。
    pub enable_rdp_mfa: bool,
    /// 本地控制台登录是否需要进入二次认证。默认关闭，避免影响现场维护。
    pub enable_console_mfa: bool,
    /// 应急禁用。这个值优先级最高，用于 VM 或生产机器无法登录时快速恢复。
    pub disable_mfa: bool,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self {
            enable_rdp_mfa: true,
            enable_console_mfa: false,
            disable_mfa: false,
        }
    }
}

impl LoginPolicy {
    /// 判断是否允许 Filter 在本地登录/解锁界面隐藏系统默认 Provider。
    pub fn should_filter_console(self) -> bool {
        self.enable_console_mfa && !self.disable_mfa
    }

    /// 判断是否允许 Filter 接管 RDP/NLA 传入的远程凭证。
    pub fn should_route_rdp(self) -> bool {
        self.enable_rdp_mfa && !self.disable_mfa
    }
}

impl fmt::Display for LoginPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "RDP 二次认证: {}",
            if self.enable_rdp_mfa {
                "启用"
            } else {
                "关闭"
            }
        )?;
        writeln!(
            formatter,
            "本地控制台二次认证: {}",
            if self.enable_console_mfa {
                "启用"
            } else {
                "关闭"
            }
        )?;
        write!(
            formatter,
            "应急禁用开关: {}",
            if self.disable_mfa { "启用" } else { "关闭" }
        )
    }
}

/// 读取登录场景策略。
///
/// 注册表键或单个值缺失时使用安全默认值：RDP 默认启用，本地默认不启用。这样既能
/// 保持远程访问的二次认证目标，也避免因为策略未写入导致本地控制台被意外接管。
pub fn load_login_policy() -> LoginPolicy {
    let default_policy = LoginPolicy::default();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey(POLICY_REGISTRY_PATH) else {
        return default_policy;
    };

    login_policy_from_registry_values(
        key.get_value::<u32, _>(VALUE_ENABLE_RDP_MFA).ok(),
        key.get_value::<u32, _>(VALUE_ENABLE_CONSOLE_MFA).ok(),
        key.get_value::<u32, _>(VALUE_DISABLE_MFA).ok(),
    )
}

/// 写入默认登录场景策略。
///
/// 安装工具调用这个函数，集中管理默认值，避免后续 register_tool 和 Filter 对默认策略
/// 理解不一致。这里不覆盖已有值，方便管理员先手工调整策略后重新安装 DLL。
pub fn ensure_default_login_policy() -> Result<LoginPolicy> {
    let default_policy = LoginPolicy::default();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(POLICY_REGISTRY_PATH)
        .map_err(|error| Error::registry("创建登录策略注册表项失败", error))?;

    write_bool_value_if_missing(&key, VALUE_ENABLE_RDP_MFA, default_policy.enable_rdp_mfa)?;
    write_bool_value_if_missing(
        &key,
        VALUE_ENABLE_CONSOLE_MFA,
        default_policy.enable_console_mfa,
    )?;
    write_bool_value_if_missing(&key, VALUE_DISABLE_MFA, default_policy.disable_mfa)?;
    write_string_value_if_missing(
        &key,
        VALUE_CONFIG_PATH,
        &default_config_path().display().to_string(),
    )?;
    ensure_machine_code()?;

    Ok(load_login_policy())
}

/// 读取注册表中记录的 helper 路径。空字符串视为未配置。
pub fn load_helper_path() -> Option<PathBuf> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(POLICY_REGISTRY_PATH).ok()?;
    key.get_value::<String, _>(VALUE_HELPER_PATH)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// 安装时记录 helper 启动路径。已有值不覆盖，避免管理员指向服务化安装位置后被重装污染。
pub fn ensure_helper_path(helper_path: &Path) -> Result<PathBuf> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(POLICY_REGISTRY_PATH)
        .map_err(|error| Error::registry("创建 helper 路径注册表项失败", error))?;
    write_string_value_if_missing(&key, VALUE_HELPER_PATH, &helper_path.display().to_string())?;
    Ok(load_helper_path().unwrap_or_else(|| helper_path.to_path_buf()))
}

fn login_policy_from_registry_values(
    enable_rdp_mfa: Option<u32>,
    enable_console_mfa: Option<u32>,
    disable_mfa: Option<u32>,
) -> LoginPolicy {
    let default_policy = LoginPolicy::default();
    LoginPolicy {
        enable_rdp_mfa: bool_from_registry_value(enable_rdp_mfa, default_policy.enable_rdp_mfa),
        enable_console_mfa: bool_from_registry_value(
            enable_console_mfa,
            default_policy.enable_console_mfa,
        ),
        disable_mfa: bool_from_registry_value(disable_mfa, default_policy.disable_mfa),
    }
}

fn bool_from_registry_value(value: Option<u32>, default_value: bool) -> bool {
    value.map(|value| value != 0).unwrap_or(default_value)
}

fn write_bool_value_if_missing(key: &RegKey, name: &str, value: bool) -> Result<()> {
    if key.get_value::<u32, _>(name).is_ok() {
        return Ok(());
    }

    let dword_value = if value { 1_u32 } else { 0_u32 };
    key.set_value(name, &dword_value)
        .map_err(|error| Error::registry("写入登录策略失败", error))
}

fn write_string_value_if_missing(key: &RegKey, name: &str, value: &str) -> Result<()> {
    if key.get_value::<String, _>(name).is_ok() {
        return Ok(());
    }

    key.set_value(name, &value)
        .map_err(|error| Error::registry("写入登录策略失败", error))
}

#[cfg(test)]
mod tests {
    use super::{LoginPolicy, login_policy_from_registry_values};

    #[test]
    fn missing_registry_values_use_safe_login_defaults() {
        let policy = login_policy_from_registry_values(None, None, None);

        assert_eq!(policy, LoginPolicy::default());
        assert!(policy.should_route_rdp());
        assert!(!policy.should_filter_console());
    }

    #[test]
    fn registry_dword_zero_disables_corresponding_policy() {
        let policy = login_policy_from_registry_values(Some(0), Some(0), Some(0));

        assert!(!policy.enable_rdp_mfa);
        assert!(!policy.enable_console_mfa);
        assert!(!policy.disable_mfa);
        assert!(!policy.should_route_rdp());
    }

    #[test]
    fn registry_nonzero_values_are_treated_as_enabled() {
        let policy = login_policy_from_registry_values(Some(2), Some(1), Some(1));

        assert!(policy.enable_rdp_mfa);
        assert!(policy.enable_console_mfa);
        assert!(policy.disable_mfa);
        assert!(!policy.should_route_rdp());
        assert!(!policy.should_filter_console());
    }
}
