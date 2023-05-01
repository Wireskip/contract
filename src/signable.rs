use ed25519_dalek::{Keypair, PublicKey, Signature};

pub trait Signable {
    fn digest(&self) -> String;
    fn public_key(&self) -> PublicKey;
    fn signature(&self) -> Signature;
    fn sign(&mut self, kp: Keypair);
}
