use std::time::{SystemTime, UNIX_EPOCH};

// NOTE: we don't really expect to work with times before epoch, but is this safe enough?
pub fn utime(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs()
}
