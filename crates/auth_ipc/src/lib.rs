//! Credential Provider 与本地 helper 之间的 IPC 协议定义。
//!
//! 第一版计划使用命名管道承载 JSON 请求。这里定义稳定的请求/响应模型和 JSON
//! 序列化入口，让 `remote_auth` 服务端和 `credential_provider` 客户端共享同一套
//! 协议。LogonUI 进程内的 DLL 只应该发起短小、可控的 IPC 调用，不直接承担网络访问。

use auth_core::AuthMethod;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, IpcCodecError>;
pub type Error = IpcCodecError;

/// helper 支持的请求类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    /// 请求 helper 返回 CP 可渲染的脱敏策略快照。
    GetPolicySnapshot { session_id: u32 },
    /// Credential Provider 在 `ReportResult status=0` 后通知 helper 标记当前 session。
    MarkSessionAuthenticated { session_id: u32 },
    /// RDP 无 inbound serialization 时查询该 session 是否曾完成 MFA。
    HasAuthenticatedSession { session_id: u32 },
    /// 清理指定 session 的内存状态，用于断开、注销或异常恢复。
    ClearSessionState { session_id: u32 },
    /// 请求服务端发送短信验证码。手机号只能由 helper 从加密配置读取，IPC 不携带真实号码。
    SendSms { session_id: u32 },
    /// 校验短信验证码。验证码仍属于敏感输入，后续应只走短超时 IPC 且不得写日志。
    VerifySms { session_id: u32, code: String },
    /// 校验二次密码。
    VerifySecondPassword { session_id: u32, password: String },
    /// 上报登录日志，后续会扩展来源 IP、RDP 用户、认证方式等字段。
    PostLoginLog {
        session_id: u32,
        method: AuthMethod,
        success: bool,
    },
}

/// CP 传给 helper 的手机号来源标记。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneInputSource {
    /// 旧协议兼容值；helper 策略不再下发可编辑手机号，CP 不应发送真实手机号。
    ManualInput,
    /// helper 自己从加密配置读取真实手机号，CP 不传真实手机号。
    #[serde(alias = "configured_file")]
    Configured,
}

/// helper 返回给 Credential Provider 的统一响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcResponse {
    /// 是否允许 Credential Provider 继续当前动作。
    pub ok: bool,
    /// 用户可见文案必须简短，敏感诊断信息只能写入 helper 的脱敏日志。
    pub message: String,
    /// 可选的结构化数据。不同请求按 `IpcResponsePayload` 解释。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<IpcResponsePayload>,
}

/// helper 响应中的结构化非敏感数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponsePayload {
    PolicySnapshot(PolicySnapshot),
    SessionState(SessionStateResponse),
}

/// helper 下发给 CP 的单个手机号选择项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneChoiceSnapshot {
    pub id: String,
    pub masked: String,
}

/// helper 下发给 CP 的脱敏策略快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub auth_methods: Vec<AuthMethod>,
    pub phone_source: PhoneInputSource,
    pub masked_phone: Option<String>,
    #[serde(default)]
    pub phone_choices: Vec<PhoneChoiceSnapshot>,
    pub phone_editable: bool,
    pub mfa_timeout_seconds: u64,
    pub sms_resend_seconds: u32,
}

/// session 状态查询结果，只包含非敏感字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStateResponse {
    pub session_id: u32,
    pub authenticated: bool,
    pub ttl_remaining_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpcCodecError {
    #[error("IPC JSON 序列化失败: {0}")]
    Serialize(String),
    #[error("IPC JSON 解析失败: {0}")]
    Deserialize(String),
}

impl IpcRequest {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|error| IpcCodecError::Serialize(error.to_string()))
    }

    pub fn from_json(value: &str) -> Result<Self> {
        serde_json::from_str(value).map_err(|error| IpcCodecError::Deserialize(error.to_string()))
    }
}

impl IpcResponse {
    /// 构造成功响应。
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            payload: None,
        }
    }

    pub fn success_with_payload(message: impl Into<String>, payload: IpcResponsePayload) -> Self {
        Self {
            ok: true,
            message: message.into(),
            payload: Some(payload),
        }
    }

    /// 构造失败响应。
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            payload: None,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|error| IpcCodecError::Serialize(error.to_string()))
    }

    pub fn from_json(value: &str) -> Result<Self> {
        serde_json::from_str(value).map_err(|error| IpcCodecError::Deserialize(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IpcRequest, IpcResponse, IpcResponsePayload, PhoneChoiceSnapshot, PhoneInputSource,
        PolicySnapshot, SessionStateResponse,
    };
    use auth_core::AuthMethod;

    #[test]
    fn serializes_session_state_requests() {
        let request = IpcRequest::MarkSessionAuthenticated { session_id: 42 };
        let json = request.to_json().unwrap();

        assert!(json.contains("mark_session_authenticated"));
        assert_eq!(IpcRequest::from_json(&json).unwrap(), request);

        let clear = IpcRequest::ClearSessionState { session_id: 42 };
        let json = clear.to_json().unwrap();
        assert!(json.contains("clear_session_state"));
        assert_eq!(IpcRequest::from_json(&json).unwrap(), clear);
    }

    #[test]
    fn serializes_policy_snapshot_response_without_sensitive_phone() {
        let response = IpcResponse::success_with_payload(
            "策略已加载",
            IpcResponsePayload::PolicySnapshot(PolicySnapshot {
                auth_methods: vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword],
                phone_source: PhoneInputSource::Configured,
                masked_phone: Some("138****8888".to_owned()),
                phone_choices: vec![
                    PhoneChoiceSnapshot {
                        id: "phone-0".to_owned(),
                        masked: "138****8888".to_owned(),
                    },
                    PhoneChoiceSnapshot {
                        id: "phone-1".to_owned(),
                        masked: "139****9999".to_owned(),
                    },
                ],
                phone_editable: false,
                mfa_timeout_seconds: 120,
                sms_resend_seconds: 60,
            }),
        );
        let json = response.to_json().unwrap();

        assert!(json.contains("138****8888"));
        assert!(json.contains("phone-0"));
        assert!(!json.contains("13812348888"));
        assert_eq!(IpcResponse::from_json(&json).unwrap(), response);
    }

    #[test]
    fn serializes_has_authenticated_session_response() {
        let response = IpcResponse::success_with_payload(
            "session 命中",
            IpcResponsePayload::SessionState(SessionStateResponse {
                session_id: 42,
                authenticated: true,
                ttl_remaining_seconds: Some(300),
            }),
        );

        assert_eq!(
            IpcResponse::from_json(&response.to_json().unwrap()).unwrap(),
            response
        );
    }

    #[test]
    fn rejects_unknown_request_json() {
        let error = IpcRequest::from_json(r#"{"type":"unknown"}"#).unwrap_err();
        assert!(error.to_string().contains("IPC JSON"));
    }

    #[test]
    fn sms_requests_do_not_carry_phone_number() {
        let send = IpcRequest::SendSms { session_id: 7 }.to_json().unwrap();
        let verify = IpcRequest::VerifySms {
            session_id: 7,
            code: "123456".to_owned(),
        }
        .to_json()
        .unwrap();

        assert!(!send.contains("phone"));
        assert!(!verify.contains("phone"));
        assert_eq!(
            IpcRequest::from_json(&send).unwrap(),
            IpcRequest::SendSms { session_id: 7 }
        );
    }
}
