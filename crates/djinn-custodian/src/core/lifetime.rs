// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use std::time::{Duration, Instant, SystemTime};

/// Monotonic bound plus a calendar bound: suspend must not add extra days,
/// and moving the calendar backwards must not renew an existing unlock.
#[derive(Clone, Copy)]
pub(super) struct UnlockDeadline {
    pub instant: Instant,
    wall: SystemTime,
    last_wall: SystemTime,
}

impl UnlockDeadline {
    pub fn new(now: Instant, wall: SystemTime, duration: Duration) -> Option<Self> {
        Some(Self {
            instant: now.checked_add(duration)?,
            wall: wall.checked_add(duration)?,
            last_wall: wall,
        })
    }

    pub fn expired(&mut self, now: Instant, wall: SystemTime) -> bool {
        let expired = now >= self.instant || wall >= self.wall || wall < self.last_wall;
        self.last_wall = wall;
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_and_calendar_rollback_cannot_extend_the_authorization() {
        let now = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let week = Duration::from_secs(604_800);
        let mut sleep = UnlockDeadline::new(now, wall, week).unwrap();
        assert!(sleep.expired(now + Duration::from_secs(5), wall + week));
        let mut rollback = UnlockDeadline::new(now, wall, week).unwrap();
        assert!(!rollback.expired(now + Duration::from_secs(5), wall + Duration::from_secs(5)));
        assert!(rollback.expired(now + Duration::from_secs(6), wall + Duration::from_secs(4)));
        let mut monotonic = UnlockDeadline::new(now, wall, week).unwrap();
        assert!(monotonic.expired(now + week, wall + Duration::from_secs(5)));
    }
}
