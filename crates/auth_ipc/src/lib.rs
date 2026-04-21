//! Credential Provider 与本地 helper 之间的 IPC 协议定义。
//!
//! 第一版计划使用命名管道承载 JSON 请求。这里先定义稳定的请求/响应模型，后续再在
//! `remote_auth` 中实现服务端，在 `credential_provider` 中实现客户端。这样做是为了让
//! LogonUI 进程内的 DLL 只处理短小、可控的 IPC 调用，不直接承担网络访问。

use auth_core::AuthMethod;

/// helper 支持的请求类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcRequest {
    /// 请求服务端发送短信验证码。
    SendSms { phone: String },
    /// 校验短信验证码。
    VerifySms { phone: String, code: String },
    /// 校验二次密码。
    VerifySecondPassword { password: String },
    /// 上报登录日志，后续会扩展来源 IP、RDP 用户、认证方式等字段。
    PostLoginLog { method: AuthMethod, success: bool },
}

/// helper 返回给 Credential Provider 的统一响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcResponse {
    /// 是否允许 Credential Provider 继续放行。
    pub ok: bool,
    /// 用户可见文案必须简短，敏感诊断信息只能写入 helper 的脱敏日志。
    pub message: String,
}

impl IpcResponse {
    /// 构造成功响应。
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }

    /// 构造失败响应。
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }
}
