use std::time::{SystemTime, UNIX_EPOCH};

use shin::connection::Clock;

#[derive(Debug, Clone, Copy)]
pub enum WallClock {
    System,
    FixedMillis(u64),
}

impl Clock for WallClock {
    fn now_ms(&self) -> u64 {
        match self {
            Self::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_millis() as u64),
            Self::FixedMillis(milliseconds) => *milliseconds,
        }
    }
}
