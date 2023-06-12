use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub trait Signable {
    fn public_key(&self) -> VerifyingKey;
    fn signature(&self) -> Signature;
    fn sign(&mut self, kp: SigningKey);
}
