use base64::Engine;
use ed25519_dalek::{ed25519::SignatureBytes, SecretKey, Signature, SigningKey, VerifyingKey};
use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64<T>(pub T);

impl From<Base64<SigningKey>> for SigningKey {
    fn from(w: Base64<SigningKey>) -> SigningKey {
        w.0
    }
}
impl From<Base64<VerifyingKey>> for VerifyingKey {
    fn from(w: Base64<VerifyingKey>) -> VerifyingKey {
        w.0
    }
}
impl From<Base64<SecretKey>> for SecretKey {
    fn from(w: Base64<SecretKey>) -> SecretKey {
        w.0
    }
}
impl From<Base64<SignatureBytes>> for Signature {
    fn from(w: Base64<SignatureBytes>) -> Signature {
        w.0.into()
    }
}

fn bytes_serialize<T: AsRef<[u8]>, S: Serializer>(t: &Base64<T>, ser: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    ser.collect_str(&base64::display::Base64Display::new(
        t.0.as_ref(),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ))
}

fn bytes_deserialize<'de, T, D, E>(
    des: D,
    mk: fn(&[u8]) -> Result<T, E>,
) -> Result<Base64<T>, D::Error>
where
    T: AsRef<[u8]>,
    D: Deserializer<'de>,
    E: fmt::Display,
{
    struct Vis<V, E> {
        _u: PhantomData<Base64<V>>,
        mk: fn(&[u8]) -> Result<V, E>,
    }
    impl<V, E: fmt::Display> Visitor<'_> for Vis<V, E> {
        type Value = Base64<V>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(
                "a base64 (URL-safe, unpadded) string encoding ed25519 secret or public key or signature",
            )
        }

        fn visit_str<E1: de::Error>(self, v: &str) -> Result<Self::Value, E1> {
            let dec = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v)
                .map_err(de::Error::custom)?;
            (self.mk)(&dec).map(Base64).map_err(de::Error::custom)
        }
    }
    des.deserialize_str(Vis {
        _u: PhantomData::<Base64<T>>,
        mk,
    })
}

impl<'de> Deserialize<'de> for Base64<SigningKey> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Secret,
            Public,
        }

        struct SigningKeyVisitor;

        impl<'de> Visitor<'de> for SigningKeyVisitor {
            type Value = Base64<SigningKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter
                    .write_str("keypair object with base64-encoded secret and public key fields")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Base64<SigningKey>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut secret: Option<Base64<SecretKey>> = None;
                let mut public: Option<Base64<VerifyingKey>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Secret => {
                            if secret.is_some() {
                                return Err(de::Error::duplicate_field("secret"));
                            }
                            secret = Some(map.next_value()?);
                        }
                        Field::Public => {
                            if public.is_some() {
                                return Err(de::Error::duplicate_field("public"));
                            }
                            public = Some(map.next_value()?);
                        }
                    }
                }
                let secret = secret.ok_or_else(|| de::Error::missing_field("secret"))?;
                Ok(Base64(SigningKey::from_bytes(&secret.0)))
            }
        }

        const FIELDS: &'static [&'static str] = &["secret", "public"];
        deserializer.deserialize_struct("keypair", FIELDS, SigningKeyVisitor)
    }
}

impl Serialize for Base64<SigningKey> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut state = ser.serialize_struct("keypair", 2)?;
        state.serialize_field("secret", &Base64(self.0.to_bytes()))?;
        state.serialize_field("public", &Base64(self.0.verifying_key()))?;
        state.end()
    }
}

impl Serialize for Base64<VerifyingKey> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        bytes_serialize(self, ser)
    }
}

impl<'de> Deserialize<'de> for Base64<VerifyingKey> {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        bytes_deserialize(des, |src: &[u8]| {
            VerifyingKey::from_bytes(&src[..].try_into().expect("Verifying key has wrong length!"))
        })
    }
}

impl Serialize for Base64<SignatureBytes> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        bytes_serialize(self, ser)
    }
}

impl<'de> Deserialize<'de> for Base64<SignatureBytes> {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        bytes_deserialize(des, |src: &[u8]| SignatureBytes::try_from(&src[..]))
    }
}

impl Serialize for Base64<SecretKey> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        bytes_serialize(self, ser)
    }
}

impl<'de> Deserialize<'de> for Base64<SecretKey> {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        bytes_deserialize(des, |src: &[u8]| <SecretKey>::try_from(&src[..]))
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Base64<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &base64::display::Base64Display::new(
            self.0.as_ref(),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        );
        write!(f, "{}", s)
    }
}
