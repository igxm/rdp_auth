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

/// 基础布尔响应 envelope 先抽成稳定模型，后续短信校验、二次密码、登录日志都可以复用，
/// 避免每个接口各自复制一份 `ok + code` 解析结构。
#[derive(Debug, Deserialize)]
pub(crate) struct BasicResponseEnvelope {
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) code: Option<String>,
}
