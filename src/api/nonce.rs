use rand::{distributions::Alphanumeric, thread_rng, Rng};

/// Generate a random alphanumeric nonce of size len.
/// Uses the thread-local RNG.
pub fn mk_nonce(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
