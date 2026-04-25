use serde::{Deserialize, Serialize};

use crate::{ApiError, AuthApiClient, Result, SmsChallenge};
use crate::models::BasicResponseEnvelope;

const SEND_SMS_PATH: &str = "/api/host_instance/getSSHLoginCode";
// 当前仓库里只有短信发送接口路径有旧实现线索，校验路径还没有正式后端契约。
// 这里先收敛成独立常量，便于后续和真实后端对齐时只改一处。
const VERIFY_SMS_PATH: &str = "/api/host_instance/verifySSHLoginCode";

impl AuthApiClient {
    /// 请求发送短信验证码。
    ///
    /// 这里保留完整手机号入参，是因为 helper -> 后端仍需要按真实手机号发起发送请求；
    /// `challenge_token` 不会从这里返回到 CP/IPC，只会留在 helper 内存态。
    pub fn send_sms_code(&self, phone: &str) -> Result<SmsChallenge> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "send_sms_code",
            });
        }
        let response = self
            .post_json(
                SEND_SMS_PATH,
                &SendSmsRequest {
                    phone,
                    host_uuid: None,
                },
            )?
            .json::<SendSmsEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if !response.ok {
            return Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "send_sms_rejected".to_owned()),
            });
        }

        let challenge_token = response
            .challenge_token
            .filter(|value| !value.trim().is_empty())
            .ok_or(ApiError::ResponseParse)?;
        let expires_in_seconds = response.expires_in_seconds.ok_or(ApiError::ResponseParse)?;
        let resend_after_seconds = response
            .resend_after_seconds
            .ok_or(ApiError::ResponseParse)?;

        Ok(SmsChallenge {
            challenge_token,
            expires_in_seconds,
            resend_after_seconds,
        })
    }

    /// 校验短信验证码。固定使用 `challenge_token + code`，不再重复把手机号传给后端。
    pub fn verify_sms_code(&self, challenge_token: &str, code: &str) -> Result<()> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "verify_sms_code",
            });
        }
        let response = self
            .post_json(
                VERIFY_SMS_PATH,
                &VerifySmsRequest {
                    challenge_token,
                    code,
                },
            )?
            .json::<BasicResponseEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if response.ok {
            Ok(())
        } else {
            Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "verify_sms_rejected".to_owned()),
            })
        }
    }
}

#[derive(Debug, Serialize)]
struct SendSmsRequest<'a> {
    phone: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_uuid: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct VerifySmsRequest<'a> {
    challenge_token: &'a str,
    code: &'a str,
}

#[derive(Debug, Deserialize)]
struct SendSmsEnvelope {
    ok: bool,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    challenge_token: Option<String>,
    #[serde(default)]
    expires_in_seconds: Option<u64>,
    #[serde(default)]
    resend_after_seconds: Option<u64>,
}
