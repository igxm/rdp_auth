//! 本机配置读取模块。
//!
//! 真实实现会读取 `SOFTWARE\dexunyun.com\DexunGuard` 以及 `reginfo.ini`。这里先保留
//! 结构体和占位读取函数，后续接 Windows 注册表时必须继续保持脱敏日志，不允许把
//! host 令牌、验证码或二次密码写入日志。

use auth_core::AuthError;

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
