//! 本机配置读取模块。
//!
//! 真实实现会读取 `SOFTWARE\dexunyun.com\DexunGuard` 以及 `reginfo.ini`。这里先保留
//! 结构体和占位读取函数，后续接 Windows 注册表时必须继续保持脱敏日志，不允许把
//! host 令牌、验证码或二次密码写入日志。

use std::fmt;

use auth_core::AuthError;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

/// 本项目自己的策略配置注册表路径。
///
/// 这个路径只保存登录流程策略，不保存服务端 token、验证码、二次密码等敏感内容。
/// Filter 在 LogonUI 进程内只能做极轻量判断，因此这里必须保持字段少、默认值清晰。
pub const POLICY_REGISTRY_PATH: &str = r"SOFTWARE\rdp_auth\config";
/// 是否启用 RDP/NLA 场景二次认证。
pub const VALUE_ENABLE_RDP_MFA: &str = "EnableRdpMfa";
/// 是否启用本地控制台登录二次认证。
pub const VALUE_ENABLE_CONSOLE_MFA: &str = "EnableConsoleMfa";
/// 应急禁用开关。置为 1 时 Filter 和后续 Provider 逻辑都应尽量放开，避免锁死机器。
pub const VALUE_DISABLE_MFA: &str = "DisableMfa";

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

    LoginPolicy {
        enable_rdp_mfa: read_bool_value(&key, VALUE_ENABLE_RDP_MFA, default_policy.enable_rdp_mfa),
        enable_console_mfa: read_bool_value(
            &key,
            VALUE_ENABLE_CONSOLE_MFA,
            default_policy.enable_console_mfa,
        ),
        disable_mfa: read_bool_value(&key, VALUE_DISABLE_MFA, default_policy.disable_mfa),
    }
}

/// 写入默认登录场景策略。
///
/// 安装工具调用这个函数，集中管理默认值，避免后续 register_tool 和 Filter 对默认策略
/// 理解不一致。这里不覆盖已有值，方便管理员先手工调整策略后重新安装 DLL。
pub fn ensure_default_login_policy() -> Result<LoginPolicy, String> {
    let default_policy = LoginPolicy::default();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(POLICY_REGISTRY_PATH)
        .map_err(|error| format!("创建登录策略注册表项失败，是否使用管理员运行: {error}"))?;

    write_bool_value_if_missing(&key, VALUE_ENABLE_RDP_MFA, default_policy.enable_rdp_mfa)?;
    write_bool_value_if_missing(
        &key,
        VALUE_ENABLE_CONSOLE_MFA,
        default_policy.enable_console_mfa,
    )?;
    write_bool_value_if_missing(&key, VALUE_DISABLE_MFA, default_policy.disable_mfa)?;

    Ok(load_login_policy())
}

fn read_bool_value(key: &RegKey, name: &str, default_value: bool) -> bool {
    key.get_value::<u32, _>(name)
        .map(|value| value != 0)
        .unwrap_or(default_value)
}

fn write_bool_value_if_missing(key: &RegKey, name: &str, value: bool) -> Result<(), String> {
    if key.get_value::<u32, _>(name).is_ok() {
        return Ok(());
    }

    let dword_value = if value { 1_u32 } else { 0_u32 };
    key.set_value(name, &dword_value)
        .map_err(|error| format!("写入登录策略 `{name}` 失败: {error}"))
}

/// RDP 二次认证 helper 所需的本机配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConfig {
    /// 主机唯一标识，对应现有资料中的 `hostuuid`。
    pub host_uuid: String,
    /// 认证服务端地址，对应现有资料中的 `serveraddr`。
    pub server_addr: String,
    /// 客户端 IP 或策略判断所需 IP 字段。
    pub client_ip: Option<String>,
    /// 来源 IP 范围策略。
    pub remote_ip_range: Option<String>,
    /// 登录时间范围策略。
    pub remote_time_range: Option<String>,
    /// 地域策略。
    pub remote_region: Option<String>,
}

/// 读取本机配置。
///
/// 当前阶段只提供明确错误，避免调用方误以为已经接入真实注册表读取。
pub fn load_local_config() -> Result<LocalConfig, AuthError> {
    Err(AuthError::ConfigMissing(
        "尚未实现注册表和 reginfo.ini 配置读取".to_owned(),
    ))
}
