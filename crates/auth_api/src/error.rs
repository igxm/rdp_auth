use thiserror::Error;

/// API 层可匹配错误。Display 文案必须安全，不能包含手机号、验证码、密码、token
/// 或原始响应体；这样 helper 记录诊断码时不会把敏感值顺手带进日志。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiError {
    #[error("API 配置无效: {reason}")]
    InvalidConfig { reason: &'static str },
    #[error("API 网络请求失败")]
    Network,
    #[error("API 请求超时")]
    Timeout,
    #[error("API HTTP 状态异常: {status}")]
    HttpStatus { status: u16 },
    #[error("API 服务端拒绝: {code}")]
    ServerRejected { code: String },
    #[error("API 响应解析失败")]
    ResponseParse,
    #[error("API 尚未接入: {operation}")]
    NotImplemented { operation: &'static str },
}

impl ApiError {
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "认证服务配置无效，请联系管理员",
            Self::Network | Self::Timeout | Self::HttpStatus { .. } => {
                "认证服务暂时不可用，请稍后重试或联系管理员"
            }
            Self::ServerRejected { .. } => "二次认证未通过",
            Self::ResponseParse => "认证服务响应异常，请联系管理员",
            Self::NotImplemented { .. } => "认证服务尚未接入，请联系管理员",
        }
    }

    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "api_invalid_config",
            Self::Network => "api_network_error",
            Self::Timeout => "api_timeout",
            Self::HttpStatus { .. } => "api_http_status",
            Self::ServerRejected { .. } => "api_server_rejected",
            Self::ResponseParse => "api_response_parse",
            Self::NotImplemented { .. } => "api_not_implemented",
        }
    }
}
