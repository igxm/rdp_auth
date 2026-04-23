//! 统一配置错误类型。
//!
//! auth_config 是注册表引导项、AES 配置文件和 TOML schema 的汇聚层。这里集中定义
//! 可向上返回的错误，避免各模块拼接字符串时把机器码、解密后配置或其它敏感值带入
//! Display 文案。路径和操作名可以用于管理员排查，真实配置内容仍然禁止进入错误文本。

use std::path::PathBuf;
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::protected_file::ConfigProtectionError;

pub type Result<T> = std::result::Result<T, Error>;

/// 配置层可匹配错误。Display 文案必须安全，不包含机器码、完整手机号、API token 或明文配置。
#[derive(Debug, Error)]
pub enum Error {
    #[error("{action}，是否使用管理员运行")]
    Registry {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{action}: {path}")]
    File {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("配置保护失败: {0}")]
    Protection(#[from] ConfigProtectionError),
    #[error("配置明文不是 UTF-8")]
    Utf8(#[source] FromUtf8Error),
    #[error("TOML 配置解析失败")]
    TomlDeserialize(#[source] toml::de::Error),
    #[error("生成标准 TOML 失败")]
    TomlSerialize(#[source] toml::ser::Error),
    #[error("写入新加密配置失败，已尝试恢复备份: {path}")]
    ReplaceFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub(crate) fn registry(action: &'static str, source: std::io::Error) -> Self {
        Self::Registry { action, source }
    }

    pub(crate) fn file(
        action: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::File {
            action,
            path: path.into(),
            source,
        }
    }
}
