use std::cmp::Ordering;
use std::ops::Deref;

use super::timestamp::Timestamped;

/// Wrapping something `Timestamped` in a `ChronoSort` ensures chronological order (sooner to
/// later) when in a sorted collection. via implementing `PartialEq`, `Eq`, `PartialOrd`, `Ord`.
/// The converse is easy to obtain with `std::cmp::Reverse` therefore it is not implemented here.
#[derive(Clone)]
pub struct ChronoSort<T: Timestamped>(pub T);

// signed types are themselves for practical purposes
impl<T> Deref for ChronoSort<T>
where
    T: Timestamped,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> PartialEq for ChronoSort<T>
where
    T: Timestamped,
{
    fn eq(&self, other: &Self) -> bool {
        i64::eq(&self.0.timestamp(), &other.0.timestamp())
    }
}

impl<T> Eq for ChronoSort<T> where T: Timestamped {}

impl<T> PartialOrd for ChronoSort<T>
where
    T: Timestamped,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        i64::partial_cmp(&self.0.timestamp(), &other.0.timestamp())
    }
}

impl<T> Ord for ChronoSort<T>
where
    T: Timestamped,
{
    fn cmp(&self, other: &Self) -> Ordering {
        Ordering::reverse(i64::cmp(&self.0.timestamp(), &other.0.timestamp()))
    }
}
