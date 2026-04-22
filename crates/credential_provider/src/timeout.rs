//! MFA 超时断开控制。
//!
//! LogonUI 不会主动轮询我们的状态，所以“2 分钟内未完成认证自动断开”不能只在按钮点击或
//! `GetSerialization` 里检查。这里启动一个受控的一次性定时器：每次收到新的 RDP serialization
//! 都生成新的 generation，旧定时器醒来后发现 generation 已变化就退出，避免误断开新会话。

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use auth_core::MfaState;

use crate::diagnostics::log_event;
use crate::session::disconnect_current_session;
use crate::state::CredentialProviderState;

pub fn start_mfa_timeout_timer(state: Arc<Mutex<CredentialProviderState>>) {
    let (generation, timeout_seconds) = {
        let mut state = state.lock().expect("provider state poisoned");
        state.timeout_generation = state.timeout_generation.wrapping_add(1);
        if state.timeout_generation == 0 {
            state.timeout_generation = 1;
        }
        (state.timeout_generation, state.mfa_timeout_seconds)
    };

    log_event(
        "MfaTimeout",
        format!("timer_started generation={generation} timeout_seconds={timeout_seconds}"),
    );

    let spawn_result = thread::Builder::new()
        .name("rdp_auth_mfa_timeout".to_owned())
        .spawn(move || {
            thread::sleep(Duration::from_secs(timeout_seconds));
            let should_disconnect = {
                let mut state = state.lock().expect("provider state poisoned");
                if state.timeout_generation != generation {
                    log_event(
                        "MfaTimeout",
                        format!(
                            "timer_stale generation={} current_generation={}",
                            generation, state.timeout_generation
                        ),
                    );
                    false
                } else if state.mfa_state.allows_serialization() {
                    log_event(
                        "MfaTimeout",
                        format!("timer_completed_after_verified generation={generation}"),
                    );
                    false
                } else {
                    state.mfa_state = MfaState::Failed("二次认证超时，已断开 RDP 连接".to_owned());
                    state.status_message = "二次认证超时，已断开 RDP 连接".to_owned();
                    log_event(
                        "MfaTimeout",
                        format!("timer_expired_disconnect generation={generation}"),
                    );
                    true
                }
            };

            if should_disconnect {
                match disconnect_current_session() {
                    Ok(()) => log_event(
                        "MfaTimeout",
                        format!("disconnect_ok generation={generation}"),
                    ),
                    Err(error) => log_event(
                        "MfaTimeout",
                        format!("disconnect_failed generation={generation} error={error}"),
                    ),
                }
            }
        });

    if let Err(error) = spawn_result {
        log_event(
            "MfaTimeout",
            format!("timer_spawn_failed generation={generation} error={error}"),
        );
    }
}

pub fn start_missing_serialization_disconnect_timer(state: Arc<Mutex<CredentialProviderState>>) {
    let (generation, grace_seconds, disconnect_when_missing_serialization) = {
        let mut state = state.lock().expect("provider state poisoned");
        state.timeout_generation = state.timeout_generation.wrapping_add(1);
        if state.timeout_generation == 0 {
            state.timeout_generation = 1;
        }
        (
            state.timeout_generation,
            state.missing_serialization_grace_seconds,
            state.disconnect_when_missing_serialization,
        )
    };

    if !disconnect_when_missing_serialization {
        log_event(
            "MissingSerialization",
            format!("timer_skipped_by_config generation={generation}"),
        );
        return;
    }

    log_event(
        "MissingSerialization",
        format!("timer_started generation={generation} grace_seconds={grace_seconds}"),
    );

    let spawn_result = thread::Builder::new()
        .name("rdp_auth_missing_serialization".to_owned())
        .spawn(move || {
            thread::sleep(Duration::from_secs(grace_seconds));
            let should_disconnect = {
                let mut state = state.lock().expect("provider state poisoned");
                if state.timeout_generation != generation {
                    log_event(
                        "MissingSerialization",
                        format!(
                            "timer_stale generation={} current_generation={}",
                            generation, state.timeout_generation
                        ),
                    );
                    false
                } else if state.has_inbound_serialization {
                    log_event(
                        "MissingSerialization",
                        format!("inbound_arrived generation={generation}"),
                    );
                    false
                } else {
                    state.mfa_state =
                        MfaState::Failed("未收到 RDP 原始凭证，已断开连接".to_owned());
                    state.status_message = "未收到 RDP 原始凭证，已断开连接".to_owned();
                    log_event(
                        "MissingSerialization",
                        format!("disconnect_missing_inbound generation={generation}"),
                    );
                    true
                }
            };

            if should_disconnect {
                match disconnect_current_session() {
                    Ok(()) => log_event(
                        "MissingSerialization",
                        format!("disconnect_ok generation={generation}"),
                    ),
                    Err(error) => log_event(
                        "MissingSerialization",
                        format!("disconnect_failed generation={generation} error={error}"),
                    ),
                }
            }
        });

    if let Err(error) = spawn_result {
        log_event(
            "MissingSerialization",
            format!("timer_spawn_failed generation={generation} error={error}"),
        );
    }
}
