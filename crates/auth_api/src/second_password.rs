use serde::Serialize;

use crate::models::BasicResponseEnvelope;
use crate::{ApiError, AuthApiClient, Result};

// 二次密码接口在旧文档里只有“发起校验请求”的抽象描述，尚无正式服务端契约。
// 这里先按 helper -> auth_api 的受控边界约定独立路径，后续联调时只需要替换这一处常量。
const VERIFY_SECOND_PASSWORD_PATH: &str = "/api/host_instance/verifySecondPassword";

impl AuthApiClient {
    /// 校验二次密码。具体路径未确定前继续 fail closed。
    pub fn verify_second_password(&self, password: &str) -> Result<()> {
        if self.uses_placeholder_service() {
            return Err(ApiError::NotImplemented {
                operation: "verify_second_password",
            });
        }
        let response = self
            .post_json(
                VERIFY_SECOND_PASSWORD_PATH,
                &VerifySecondPasswordRequest { password },
            )?
            .json::<BasicResponseEnvelope>()
            .map_err(|_| ApiError::ResponseParse)?;

        if response.ok {
            Ok(())
        } else {
            Err(ApiError::ServerRejected {
                code: response
                    .code
                    .unwrap_or_else(|| "verify_second_password_rejected".to_owned()),
            })
        }
    }
}

#[derive(Debug, Serialize)]
struct VerifySecondPasswordRequest<'a> {
    password: &'a str,
}
