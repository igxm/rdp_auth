//! Rust Credential Provider DLL 的最小 COM 加载骨架。
//!
//! 这个 crate 按 Windows Credential Provider 的职责拆分模块：DLL 入口、COM 类工厂、
//! Provider 枚举、Credential Tile、字段描述符、COM 内存工具和共享状态分别维护。
//! 这种分层能避免后续把 `SetSerialization`、UI 状态机、IPC 调用都塞进一个大文件。

mod class_factory;
mod credential;
mod dll;
mod fields;
mod memory;
mod provider;
mod serialization;
mod state;

pub use dll::{DllCanUnloadNow, DllGetClassObject, DllMain};
pub use state::{CredentialProviderState, RDP_MFA_PROVIDER_CLSID};
