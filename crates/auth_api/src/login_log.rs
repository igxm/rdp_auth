use serde::Serialize;

use crate::models::{BasicResponseEnvelope, LoginAuditRecord};
use crate::{ApiError, AuthApiClient, Result};

const POST_LOGIN_LOG_PATH: &str = "/api/host_instance/postSSHLoginLog";

impl AuthApiClient {
    /// 上报脱敏后的登录日志。
    ///
    /// `auth_api` 只接收 helper 已清洗过的上下文，避免这个 crate 反向知道 CP 状态、
    /// 原始认证输入或本地审计实现细节。
    pub fn post_login_log(&self, record: &LoginAuditRecord) -> Result<()> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "post_login_log",
            });
        }

        let response = self
            .post_json(
                POST_LOGIN_LOG_PATH,
                &PostLoginLogRequest::from_record(record),
            )?
            .json::<BasicResponseEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if response.ok {
            Ok(())
        } else {
            Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "post_login_log_rejected".to_owned()),
            })
        }
    }
}

#[derive(Debug, Serialize)]
struct PostLoginLogRequest {
    request_id: String,
    session_id: u32,
    client_ip: String,
    host_public_ip: String,
    host_private_ips: Vec<String>,
    host_uuid: String,
    auth_method: String,
    success: bool,
}

impl PostLoginLogRequest {
    fn from_record(record: &LoginAuditRecord) -> Self {
        Self {
            request_id: record.request_id.clone(),
            session_id: record.session_id,
            client_ip: record.client_ip.clone(),
            host_public_ip: record.host_public_ip.clone(),
            host_private_ips: record.host_private_ips.clone(),
            host_uuid: record.host_uuid.clone(),
            auth_method: record.auth_method.clone(),
            success: record.success,
        }
    }
}
