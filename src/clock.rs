use std::time;

use shin::connection;

#[derive(Debug, Clone, Copy)]
pub enum Clock {
    System,
    FixedMillis(u64),
}

impl connection::Clock for Clock {
    fn now_ms(&self) -> u64 {
        match self {
            Self::System => match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
                Ok(duration) => duration.as_millis() as u64,
                Err(_) => 0,
            },
            Self::FixedMillis(milliseconds) => *milliseconds,
        }
    }
}
