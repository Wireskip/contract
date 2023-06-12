use crate::{api::digestible::Digestible, api::signable::Signable};
use ed25519_dalek::Verifier;
use serde::{Deserialize, Deserializer};
use std::ops::Deref;

// signed types are themselves for practical purposes
impl<T> Deref for Signed<T>
where
    T: Signable,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Signed<T: Signable>(pub T);

impl<'de, T> Deserialize<'de> for Signed<T>
where
    T: Signable + Deserialize<'de> + Digestible,
{
    fn deserialize<D>(de: D) -> Result<Signed<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let t = T::deserialize(de)?;
        t.public_key() // Signer
            .verify(t.digest().as_bytes(), &t.signature())
            .map_err(serde::de::Error::custom)
            .map(|()| Signed(t))
    }
}
