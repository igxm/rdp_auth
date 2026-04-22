//! helper 内存态 session 认证状态。
//!
//! 锁屏后立即断开 RDP 的关键判断不能写注册表或状态文件，否则 session id 复用、
//! 机器重启和异常退出都可能让旧认证状态污染新登录。这里先实现纯内存状态表；
//! 后续 Windows session notification 只负责调用本模块的标记和清理接口。

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthRecord {
    pub session_id: u32,
    pub authenticated_at: Instant,
    pub last_event: SessionEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SessionEvent {
    Authenticated,
    Lock,
    Unlock,
    Disconnect,
    Logoff,
    Cleared,
}

#[derive(Debug)]
pub struct SessionAuthState {
    ttl: Duration,
    records: HashMap<u32, SessionAuthRecord>,
}

impl SessionAuthState {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            records: HashMap::new(),
        }
    }

    pub fn mark_authenticated(&mut self, session_id: u32, now: Instant) {
        self.records.insert(
            session_id,
            SessionAuthRecord {
                session_id,
                authenticated_at: now,
                last_event: SessionEvent::Authenticated,
            },
        );
    }

    pub fn has_authenticated_session(&mut self, session_id: u32, now: Instant) -> bool {
        self.prune_expired(now);
        self.records.contains_key(&session_id)
    }

    pub fn ttl_remaining(&mut self, session_id: u32, now: Instant) -> Option<Duration> {
        self.prune_expired(now);
        let record = self.records.get(&session_id)?;
        let elapsed = now.saturating_duration_since(record.authenticated_at);
        Some(self.ttl.saturating_sub(elapsed))
    }

    #[allow(dead_code)]
    pub fn record_event(&mut self, session_id: u32, event: SessionEvent) {
        match event {
            SessionEvent::Disconnect | SessionEvent::Logoff | SessionEvent::Cleared => {
                self.records.remove(&session_id);
            }
            SessionEvent::Lock | SessionEvent::Unlock | SessionEvent::Authenticated => {
                if let Some(record) = self.records.get_mut(&session_id) {
                    record.last_event = event;
                }
            }
        }
    }

    pub fn clear_session(&mut self, session_id: u32) {
        self.records.remove(&session_id);
    }

    pub fn prune_expired(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.records
            .retain(|_, record| now.saturating_duration_since(record.authenticated_at) <= ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionAuthState, SessionEvent};
    use std::time::{Duration, Instant};

    #[test]
    fn marks_and_queries_authenticated_session() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);

        assert!(state.has_authenticated_session(7, now));
        assert!(!state.has_authenticated_session(8, now));
    }

    #[test]
    fn expires_authenticated_session_after_ttl() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(5));

        state.mark_authenticated(7, now);

        assert!(!state.has_authenticated_session(7, now + Duration::from_secs(6)));
    }

    #[test]
    fn disconnect_and_logoff_clear_session_state() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);
        state.record_event(7, SessionEvent::Disconnect);
        assert!(!state.has_authenticated_session(7, now));

        state.mark_authenticated(8, now);
        state.record_event(8, SessionEvent::Logoff);
        assert!(!state.has_authenticated_session(8, now));
    }

    #[test]
    fn lock_and_unlock_update_event_without_clearing_state() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);
        state.record_event(7, SessionEvent::Lock);
        assert!(state.has_authenticated_session(7, now));
        assert_eq!(
            state.records.get(&7).map(|record| record.last_event),
            Some(SessionEvent::Lock)
        );

        state.record_event(7, SessionEvent::Unlock);
        assert_eq!(
            state.records.get(&7).map(|record| record.last_event),
            Some(SessionEvent::Unlock)
        );
    }

    #[test]
    fn explicit_clear_removes_session_state() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);
        state.clear_session(7);

        assert!(!state.has_authenticated_session(7, now));
    }

    #[test]
    fn cleared_event_removes_session_state() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);
        state.record_event(7, SessionEvent::Cleared);

        assert!(!state.has_authenticated_session(7, now));
    }

    #[test]
    fn reports_ttl_remaining_without_sensitive_context() {
        let now = Instant::now();
        let mut state = SessionAuthState::new(Duration::from_secs(60));

        state.mark_authenticated(7, now);

        assert_eq!(
            state.ttl_remaining(7, now + Duration::from_secs(10)),
            Some(Duration::from_secs(50))
        );
    }
}
