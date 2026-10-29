use rustls::{pki_types::UnixTime, time_provider::TimeProvider};

#[derive(Debug)]
pub struct Absent;

impl TimeProvider for Absent {
    fn current_time(&self) -> Option<UnixTime> {
        None
    }
}

#[derive(Debug)]
pub struct Fixed(pub UnixTime);

impl TimeProvider for Fixed {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}
