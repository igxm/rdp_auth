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
use crate::helper_client::has_current_session_authenticated;
use crate::session::disconnect_current_session;
use crate::state::CredentialProviderState;

pub fn start_mfa_timeout_timer(state: Arc<Mutex<CredentialProviderState>>) {
    let timeout_seconds = {
        let state = state.lock().expect("provider state poisoned");
        state.mfa_timeout_seconds
    };
    start_mfa_timeout_timer_with_timeout(state, timeout_seconds);
}

pub fn start_mfa_timeout_timer_with_timeout(
    state: Arc<Mutex<CredentialProviderState>>,
    timeout_seconds: u64,
) {
    let generation = next_mfa_timeout_generation(&state);

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
                if state.mfa_timeout_generation != generation {
                    log_event(
                        "MfaTimeout",
                        format!(
                            "timer_stale generation={} current_generation={}",
                            generation, state.mfa_timeout_generation
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

fn next_mfa_timeout_generation(state: &Arc<Mutex<CredentialProviderState>>) -> u64 {
    let mut state = state.lock().expect("provider state poisoned");
    state.mfa_timeout_generation = state.mfa_timeout_generation.wrapping_add(1);
    if state.mfa_timeout_generation == 0 {
        state.mfa_timeout_generation = 1;
    }
    state.mfa_timeout_generation
}

fn next_missing_serialization_generation(
    state: &Arc<Mutex<CredentialProviderState>>,
) -> (u64, u64, u64, bool) {
    let mut state = state.lock().expect("provider state poisoned");
    state.missing_serialization_generation = state.missing_serialization_generation.wrapping_add(1);
    if state.missing_serialization_generation == 0 {
        state.missing_serialization_generation = 1;
    }
    (
        state.missing_serialization_generation,
        state.missing_serialization_grace_seconds,
        state.helper_ipc_timeout_ms,
        state.disconnect_when_missing_serialization,
    )
}

pub fn start_missing_serialization_disconnect_timer(state: Arc<Mutex<CredentialProviderState>>) {
    let (generation, grace_seconds, helper_ipc_timeout_ms, disconnect_when_missing_serialization) =
        next_missing_serialization_generation(&state);

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
            let should_query_helper = {
                let state = state.lock().expect("provider state poisoned");
                if state.missing_serialization_generation != generation {
                    log_event(
                        "MissingSerialization",
                        format!(
                            "timer_stale generation={} current_generation={}",
                            generation, state.missing_serialization_generation
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
                    true
                }
            };

            if !should_query_helper {
                return;
            }

            // helper 查询只能辅助判断“这是已认证会话返回 LogonUI，还是首次登录 serialization 慢到”。
            // 查询失败、超时或非法响应都不能放行；这里统一继续 fail closed 断开。
            let helper_status =
                has_current_session_authenticated(Duration::from_millis(helper_ipc_timeout_ms));
            match helper_status {
                Ok(session) => log_event(
                    "MissingSerialization",
                    format!(
                        "helper_session_state authenticated={} ttl_remaining_seconds={:?}",
                        session.authenticated, session.ttl_remaining_seconds
                    ),
                ),
                Err(error) => log_event(
                    "MissingSerialization",
                    format!("helper_session_state_failed error={error}"),
                ),
            }

            let should_disconnect = {
                let mut state = state.lock().expect("provider state poisoned");
                if state.missing_serialization_generation != generation {
                    log_event(
                        "MissingSerialization",
                        format!(
                            "timer_stale_after_helper generation={} current_generation={}",
                            generation, state.missing_serialization_generation
                        ),
                    );
                    false
                } else if state.has_inbound_serialization {
                    log_event(
                        "MissingSerialization",
                        format!("inbound_arrived_after_helper generation={generation}"),
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

pub fn restart_missing_serialization_disconnect_timer_with_timeout(
    state: Arc<Mutex<CredentialProviderState>>,
    grace_seconds: u64,
) {
    let (generation, helper_ipc_timeout_ms, disconnect_when_missing_serialization) = {
        let mut state = state.lock().expect("provider state poisoned");
        state.missing_serialization_generation =
            state.missing_serialization_generation.wrapping_add(1);
        if state.missing_serialization_generation == 0 {
            state.missing_serialization_generation = 1;
        }
        (
            state.missing_serialization_generation,
            state.helper_ipc_timeout_ms,
            state.disconnect_when_missing_serialization,
        )
    };

    if !disconnect_when_missing_serialization {
        log_event(
            "MissingSerialization",
            format!(
                "timer_restart_skipped_by_config generation={} grace_seconds={}",
                generation, grace_seconds
            ),
        );
        return;
    }

    log_event(
        "MissingSerialization",
        format!(
            "timer_restarted generation={} grace_seconds={}",
            generation, grace_seconds
        ),
    );

    let spawn_result = thread::Builder::new()
        .name("rdp_auth_missing_serialization".to_owned())
        .spawn(move || {
            thread::sleep(Duration::from_secs(grace_seconds));
            let should_query_helper = {
                let state = state.lock().expect("provider state poisoned");
                if state.missing_serialization_generation != generation {
                    log_event(
                        "MissingSerialization",
                        format!(
                            "timer_stale generation={} current_generation={}",
                            generation, state.missing_serialization_generation
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
                    true
                }
            };

            if !should_query_helper {
                return;
            }

            let helper_status =
                has_current_session_authenticated(Duration::from_millis(helper_ipc_timeout_ms));
            match helper_status {
                Ok(session) => log_event(
                    "MissingSerialization",
                    format!(
                        "helper_session_state authenticated={} ttl_remaining_seconds={:?}",
                        session.authenticated, session.ttl_remaining_seconds
                    ),
                ),
                Err(error) => log_event(
                    "MissingSerialization",
                    format!("helper_session_state_failed error={error}"),
                ),
            }

            let should_disconnect = {
                let mut state = state.lock().expect("provider state poisoned");
                if state.missing_serialization_generation != generation {
                    log_event(
                        "MissingSerialization",
                        format!(
                            "timer_stale_after_helper generation={} current_generation={}",
                            generation, state.missing_serialization_generation
                        ),
                    );
                    false
                } else if state.has_inbound_serialization {
                    log_event(
                        "MissingSerialization",
                        format!("inbound_arrived_after_helper generation={generation}"),
                    );
                    false
                } else {
                    state.mfa_state = MfaState::Failed(
                        "浜屾璁よ瘉绛夊緟瓒呮椂锛屽凡鏂紑 RDP 杩炴帴".to_owned(),
                    );
                    state.status_message =
                        "浜屾璁よ瘉绛夊緟瓒呮椂锛屽凡鏂紑 RDP 杩炴帴".to_owned();
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
