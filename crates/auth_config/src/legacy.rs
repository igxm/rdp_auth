//! 旧版配置兼容占位。
//!
//! 旧版 `reginfo.ini`、手机号文件和历史字段只允许由 helper 读取和迁移。Credential
//! Provider 不应直接打开这些文件，避免 LogonUI 被 IO、权限或解析错误拖住。

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
