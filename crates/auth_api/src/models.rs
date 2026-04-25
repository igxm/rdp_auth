use serde::Deserialize;

/// 发送短信后由服务端返回的 challenge 元数据。
///
/// `challenge_token` 后续会成为 verify_sms 的唯一校验凭据，因此它只能在 helper 内存
/// 和 helper -> 后端链路中出现，不能回流到 IPC、CP 或日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsChallenge {
    pub challenge_token: String,
    pub expires_in_seconds: u64,
    pub resend_after_seconds: u64,
}

/// helper 传给 `auth_api` 的脱敏登录审计记录。
///
/// 这里刻意只允许放脱敏后的上下文，避免 helper 在调用真实上报接口时顺手把验证码、
/// 完整手机号或其它敏感输入带到请求模型里。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAuditRecord {
    pub request_id: String,
    pub session_id: u32,
    pub client_ip: String,
    pub host_public_ip: String,
    pub host_private_ips: Vec<String>,
    pub host_uuid: String,
    pub auth_method: String,
    pub success: bool,
}

/// helper 传给短信 API 的脱敏上下文。
///
/// 这里不包含完整手机号、验证码或 challenge_token；这些敏感值分别只留在 helper 的手机号映射、
/// verify 请求体和 challenge 内存态里，避免把短信请求骨架变成新的泄漏面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsAuditContext {
    pub request_id: String,
    pub session_id: u32,
    pub client_ip: String,
    pub host_public_ip: String,
    pub host_private_ips: Vec<String>,
    pub host_uuid: String,
}

/// 基础布尔响应 envelope 先抽成稳定模型，后续短信校验、二次密码、登录日志都可以复用，
/// 避免每个接口各自复制一份 `ok + code` 解析结构。
#[derive(Debug, Deserialize)]
pub(crate) struct BasicResponseEnvelope {
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) code: Option<String>,
}
