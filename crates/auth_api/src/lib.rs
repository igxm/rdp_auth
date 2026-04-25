//! 服务端认证 API 封装。
//!
//! 网络访问只允许出现在 helper 侧，Credential Provider DLL 不能直接调用本 crate。
//! 这里先把真实 HTTP 请求、错误映射和 mock 服务测试链路落稳，避免后续在 helper
//! 层混入请求拼装细节或把敏感字段打进日志。

mod client;
mod error;
mod login_log;
mod models;
mod public_ip;
mod second_password;
mod sms;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
mod transport;

pub use client::AuthApiClient;
pub use error::ApiError;
pub use models::{LoginAuditRecord, SmsAuditContext, SmsChallenge};

pub type Result<T> = std::result::Result<T, ApiError>;
pub type Error = ApiError;
