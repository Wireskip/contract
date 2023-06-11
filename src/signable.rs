use ed25519_dalek::{SigningKey, VerifyingKey, Signature};

pub trait Signable {
    fn digest(&self) -> String;
    fn public_key(&self) -> VerifyingKey;
    fn signature(&self) -> Signature;
    fn sign(&mut self, kp: SigningKey);
}
