//! 远程配置响应解析与校验。
//!
//! 网络拉取和加密缓存后续再接入；本模块先固定 helper 接收远程配置时必须校验的 envelope。
//! 远程配置缺少版本、更新时间、TTL 或签名时不得覆盖本地有效配置。
#![allow(dead_code)]

use auth_config::{AppConfig, AuthMethodsConfig};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemoteConfigError {
    #[error("远程配置 JSON 解析失败")]
    Parse,
    #[error("远程配置缺少完整性字段: {field}")]
    MissingIntegrityField { field: &'static str },
    #[error("远程配置认证方式非法")]
    InvalidAuthMethods,
}

#[derive(Debug, Deserialize)]
struct RemoteConfigEnvelope {
    version: String,
    updated_at_unix: u64,
    ttl_seconds: u64,
    signature: String,
    #[serde(default)]
    policy: RemotePolicy,
}

#[derive(Debug, Default, Deserialize)]
struct RemotePolicy {
    auth_methods: Option<AuthMethodsConfig>,
}

pub fn apply_remote_config_json(
    local: &AppConfig,
    value: &str,
) -> Result<AppConfig, RemoteConfigError> {
    let envelope: RemoteConfigEnvelope =
        serde_json::from_str(value).map_err(|_| RemoteConfigError::Parse)?;
    validate_envelope(&envelope)?;

    let mut merged = local.clone();
    if let Some(auth_methods) = envelope.policy.auth_methods {
        if !has_any_auth_method(&auth_methods) {
            return Err(RemoteConfigError::InvalidAuthMethods);
        }
        merged.auth_methods = auth_methods;
    }

    Ok(merged.normalized())
}

fn validate_envelope(envelope: &RemoteConfigEnvelope) -> Result<(), RemoteConfigError> {
    if envelope.version.trim().is_empty() {
        return Err(RemoteConfigError::MissingIntegrityField { field: "version" });
    }
    if envelope.updated_at_unix == 0 {
        return Err(RemoteConfigError::MissingIntegrityField {
            field: "updated_at_unix",
        });
    }
    if envelope.ttl_seconds == 0 {
        return Err(RemoteConfigError::MissingIntegrityField {
            field: "ttl_seconds",
        });
    }
    if envelope.signature.trim().is_empty() {
        return Err(RemoteConfigError::MissingIntegrityField { field: "signature" });
    }
    Ok(())
}

fn has_any_auth_method(auth_methods: &AuthMethodsConfig) -> bool {
    auth_methods.phone_code || auth_methods.second_password || auth_methods.wechat
}

#[cfg(test)]
mod tests {
    use super::{RemoteConfigError, apply_remote_config_json};
    use auth_config::AppConfig;
    use auth_core::AuthMethod;

    #[test]
    fn parses_remote_config_with_integrity_fields() {
        let local = AppConfig::default();

        let merged = apply_remote_config_json(
            &local,
            r#"
{
  "version": "v1",
  "updated_at_unix": 1770000000,
  "ttl_seconds": 300,
  "signature": "test-signature",
  "policy": {
    "auth_methods": {
      "phone_code": false,
      "second_password": true,
      "wechat": false
    }
  }
}
"#,
        )
        .unwrap();

        assert_eq!(
            merged.auth_methods.enabled_methods(),
            vec![AuthMethod::SecondPassword]
        );
    }

    #[test]
    fn missing_integrity_fields_do_not_override_local_config() {
        let local = AppConfig::default();

        let error = apply_remote_config_json(
            &local,
            r#"
{
  "version": "v1",
  "updated_at_unix": 1770000000,
  "ttl_seconds": 300,
  "signature": "",
  "policy": {
    "auth_methods": {
      "phone_code": false,
      "second_password": true,
      "wechat": false
    }
  }
}
"#,
        )
        .unwrap_err();

        assert_eq!(
            error,
            RemoteConfigError::MissingIntegrityField { field: "signature" }
        );
        assert_eq!(
            local.auth_methods.enabled_methods(),
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
    }

    #[test]
    fn remote_config_cannot_disable_all_auth_methods() {
        let local = AppConfig::default();

        let error = apply_remote_config_json(
            &local,
            r#"
{
  "version": "v1",
  "updated_at_unix": 1770000000,
  "ttl_seconds": 300,
  "signature": "test-signature",
  "policy": {
    "auth_methods": {
      "phone_code": false,
      "second_password": false,
      "wechat": false
    }
  }
}
"#,
        )
        .unwrap_err();

        assert_eq!(error, RemoteConfigError::InvalidAuthMethods);
        assert_eq!(
            local.auth_methods.enabled_methods(),
            vec![AuthMethod::PhoneCode, AuthMethod::SecondPassword]
        );
    }
}
