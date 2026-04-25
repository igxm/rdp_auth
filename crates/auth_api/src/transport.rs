use reqwest::blocking::Response;
use serde::Serialize;
use tracing::debug;

use crate::{ApiError, AuthApiClient, Result};

impl AuthApiClient {
    /// 通用 POST JSON transport 只负责 HTTP 收发和错误映射。
    ///
    /// 业务接口只关心“发到哪个 path、解析什么 envelope”，避免把 reqwest 细节复制到
    /// 每个 API 方法里，后续补统一 header、审计上下文或超时诊断时也只需要改这一层。
    pub(crate) fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<Response> {
        let endpoint = self.endpoint_url(path);
        debug!(
            target: "auth_api",
            operation = "post_json",
            path,
            endpoint = %endpoint,
            "auth_api 正在发起 HTTP 请求"
        );
        self.http_client
            .post(endpoint)
            .json(body)
            .send()
            .map_err(map_reqwest_error)?
            .error_for_status()
            .map_err(map_reqwest_error)
    }

    /// 公网 IP 查询使用独立 endpoint，因此这里补一个通用 GET 能力，避免业务模块各自复制
    /// timeout / HTTP 状态映射细节。
    pub(crate) fn get_url(&self, endpoint: &str) -> Result<Response> {
        debug!(
            target: "auth_api",
            operation = "get_url",
            endpoint = %endpoint,
            "auth_api 正在发起 HTTP GET 请求"
        );
        self.http_client
            .get(endpoint)
            .send()
            .map_err(map_reqwest_error)?
            .error_for_status()
            .map_err(map_reqwest_error)
    }
}

fn map_reqwest_error(error: reqwest::Error) -> ApiError {
    if error.is_timeout() {
        ApiError::Timeout
    } else if let Some(status) = error.status() {
        ApiError::HttpStatus {
            status: status.as_u16(),
        }
    } else {
        ApiError::Network
    }
}
