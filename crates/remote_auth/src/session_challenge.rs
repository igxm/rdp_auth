//! helper 内存态短信 challenge 状态。
//!
//! 这里专门保存 send_sms 之后到 verify_sms 之前的短生命周期 challenge 上下文。
//! challenge_token 后续会由后端返回，属于敏感凭据；因此它只能留在 helper 进程内存里，
//! 不能混入 session 认证状态、IPC 响应、策略快照、日志或落盘缓存。
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type SharedSmsChallengeState = Arc<Mutex<SmsChallengeState>>;

pub fn shared_sms_challenge_state(state: SmsChallengeState) -> SharedSmsChallengeState {
    Arc::new(Mutex::new(state))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmsChallengeStatus {
    Pending,
    Verified,
}

pub struct SmsChallengeRecord {
    pub session_id: u32,
    pub phone_choice_id: String,
    pub challenge_token: String,
    pub issued_at: Instant,
    pub ttl: Duration,
    pub status: SmsChallengeStatus,
}

pub struct SmsChallengeState {
    ttl: Duration,
    next_token_counter: u64,
    records: HashMap<u32, SmsChallengeRecord>,
}

impl SmsChallengeState {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            next_token_counter: 1,
            records: HashMap::new(),
        }
    }

    pub fn issue_mock_challenge(
        &mut self,
        session_id: u32,
        phone_choice_id: &str,
        now: Instant,
    ) -> Duration {
        self.prune_expired(now);
        let token = self.next_mock_token(session_id);
        self.records.insert(
            session_id,
            SmsChallengeRecord {
                session_id,
                phone_choice_id: phone_choice_id.to_owned(),
                challenge_token: token,
                issued_at: now,
                ttl: self.ttl,
                status: SmsChallengeStatus::Pending,
            },
        );
        self.ttl
    }

    pub fn verify_pending_challenge(
        &mut self,
        session_id: u32,
        phone_choice_id: &str,
        now: Instant,
    ) -> Result<(), VerifyChallengeError> {
        self.prune_expired(now);
        let record = self
            .records
            .get(&session_id)
            .ok_or(VerifyChallengeError::Missing)?;
        if record.session_id != session_id || record.challenge_token.is_empty() {
            return Err(VerifyChallengeError::Missing);
        }
        if record.phone_choice_id != phone_choice_id {
            return Err(VerifyChallengeError::ChoiceChanged);
        }
        if record.status != SmsChallengeStatus::Pending {
            return Err(VerifyChallengeError::Missing);
        }
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        session_id: u32,
        now: Instant,
    ) -> Result<(), VerifyChallengeError> {
        self.prune_expired(now);
        let record = self
            .records
            .get_mut(&session_id)
            .ok_or(VerifyChallengeError::Missing)?;
        record.status = SmsChallengeStatus::Verified;
        Ok(())
    }

    pub fn clear_session(&mut self, session_id: u32) {
        self.records.remove(&session_id);
    }

    #[cfg(test)]
    pub fn ttl_remaining(&mut self, session_id: u32, now: Instant) -> Option<Duration> {
        self.prune_expired(now);
        let record = self.records.get(&session_id)?;
        Some(
            record
                .ttl
                .saturating_sub(now.saturating_duration_since(record.issued_at)),
        )
    }

    #[cfg(test)]
    pub fn status(&mut self, session_id: u32, now: Instant) -> Option<SmsChallengeStatus> {
        self.prune_expired(now);
        self.records.get(&session_id).map(|record| record.status)
    }

    fn prune_expired(&mut self, now: Instant) {
        self.records.retain(|_, record| {
            if now.saturating_duration_since(record.issued_at) > record.ttl {
                false
            } else {
                true
            }
        });
    }

    fn next_mock_token(&mut self, session_id: u32) -> String {
        // mock challenge token 只在 helper 内存里使用，仍然按“不可出进程”处理。
        let token = format!("mock-challenge-{session_id}-{}", self.next_token_counter);
        self.next_token_counter = self.next_token_counter.saturating_add(1);
        token
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyChallengeError {
    Missing,
    ChoiceChanged,
}

#[cfg(test)]
mod tests {
    use super::{SmsChallengeState, SmsChallengeStatus, VerifyChallengeError};
    use std::time::{Duration, Instant};

    #[test]
    fn issue_and_verify_pending_challenge() {
        let now = Instant::now();
        let mut state = SmsChallengeState::new(Duration::from_secs(120));

        let ttl = state.issue_mock_challenge(7, "phone-0", now);

        assert_eq!(ttl, Duration::from_secs(120));
        assert_eq!(state.status(7, now), Some(SmsChallengeStatus::Pending));
        assert_eq!(state.ttl_remaining(7, now), Some(Duration::from_secs(120)));
        assert_eq!(state.verify_pending_challenge(7, "phone-0", now), Ok(()));
    }

    #[test]
    fn verify_rejects_changed_choice_id() {
        let now = Instant::now();
        let mut state = SmsChallengeState::new(Duration::from_secs(120));

        state.issue_mock_challenge(7, "phone-0", now);

        assert_eq!(
            state.verify_pending_challenge(7, "phone-1", now),
            Err(VerifyChallengeError::ChoiceChanged)
        );
    }

    #[test]
    fn verify_rejects_missing_or_expired_challenge() {
        let now = Instant::now();
        let mut state = SmsChallengeState::new(Duration::from_secs(5));

        assert_eq!(
            state.verify_pending_challenge(7, "phone-0", now),
            Err(VerifyChallengeError::Missing)
        );

        state.issue_mock_challenge(7, "phone-0", now);

        assert_eq!(
            state.verify_pending_challenge(7, "phone-0", now + Duration::from_secs(6)),
            Err(VerifyChallengeError::Missing)
        );
        assert_eq!(state.status(7, now + Duration::from_secs(6)), None);
    }

    #[test]
    fn verified_challenge_is_not_treated_as_pending_again() {
        let now = Instant::now();
        let mut state = SmsChallengeState::new(Duration::from_secs(120));

        state.issue_mock_challenge(7, "phone-0", now);
        state.mark_verified(7, now).unwrap();

        assert_eq!(state.status(7, now), Some(SmsChallengeStatus::Verified));
        assert_eq!(
            state.verify_pending_challenge(7, "phone-0", now),
            Err(VerifyChallengeError::Missing)
        );
    }

    #[test]
    fn clear_session_removes_challenge() {
        let now = Instant::now();
        let mut state = SmsChallengeState::new(Duration::from_secs(120));

        state.issue_mock_challenge(7, "phone-0", now);
        state.clear_session(7);

        assert_eq!(state.status(7, now), None);
    }
}
