use std::time::{SystemTime, UNIX_EPOCH};

pub fn utime(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs()
        .try_into()
        .unwrap()
}
