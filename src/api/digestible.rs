pub trait Digestible {
    fn digest(&self) -> String;
    fn digest_with_sig(&self) -> String {
        self.digest()
    }
}

impl<T: ToString> Digestible for T {
    fn digest(&self) -> String {
        self.to_string()
    }
}
