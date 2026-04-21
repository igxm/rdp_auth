//! 服务端认证 API 封装。
//!
//! 网络访问只允许出现在 helper 侧，Credential Provider DLL 不能直接调用本 crate。
//! 这样做是为了避免 LogonUI 进程被网络超时、TLS 初始化或服务端异常拖住。

use auth_config::LocalConfig;
use auth_core::AuthError;

/// 认证 API 客户端配置。
#[derive(Debug, Clone)]
pub struct AuthApiClient {
    config: LocalConfig,
}

impl AuthApiClient {
    /// 创建 API 客户端。
    pub fn new(config: LocalConfig) -> Self {
        Self { config }
    }

    /// 请求发送短信验证码。
    ///
    /// 后续会调用 `/api/host_instance/getSSHLoginCode`。当前先返回未实现错误，确保
    /// mock 链路和真实 API 链路不会被维护人员混淆。
    pub fn send_sms_code(&self, _phone: &str) -> Result<(), AuthError> {
        let _server_addr = &self.config.server_addr;
        Err(AuthError::VerificationRejected(
            "尚未接入真实短信验证码 API".to_owned(),
        ))
    }
}
