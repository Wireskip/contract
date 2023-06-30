/// Timestamp is a Unix epoch time.
pub type Timestamp = i64;

/// Something `Timestamped` has a timestamp. That's it.
pub trait Timestamped {
    fn timestamp(&self) -> Timestamp;
}
