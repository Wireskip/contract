use async_trait::async_trait;
use axum::{body::Body, body::HttpBody, extract::FromRequest, http::StatusCode, Json};
use ed25519_dalek::{ed25519::SignatureBytes, Signature, Verifier, VerifyingKey};
use hyper::Request;
use serde::de::DeserializeOwned;
use std::str::FromStr;
use strum::EnumString;
use ws_common::{api::Status, b64e::Base64};

#[derive(Debug, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Signatory {
    Auth,
    Relay,
    Client,
    Contract,
    Directory,
}

#[derive(Debug, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Field {
    Pubkey,
    Signature,
}

pub struct HeaderSignedJson<T> {
    pub signatory: Signatory,
    pub public_key: Base64<VerifyingKey>,
    pub signature: Base64<Signature>,
    pub data: T,
}

fn error<E: ToString>(s: E) -> Json<Status> {
    Json(Status {
        code: StatusCode::BAD_REQUEST.into(),
        desc: s.to_string(),
    })
}

const QUOTE: char = '"';

fn quote(s: &str) -> String {
    QUOTE.to_string() + s + &QUOTE.to_string()
}

#[async_trait]
impl<S, B, T> FromRequest<S, B> for HeaderSignedJson<T>
where
    S: Send + Sync,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: ToString,
    T: DeserializeOwned,
{
    type Rejection = Json<Status>;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        if let (Some(signatory), Some(pk), Some(sig)) =
            parts
                .headers
                .iter()
                .fold((None, None, None), |acc, (k, v)| {
                    let k = k.as_str();
                    if k.starts_with("wireleap-") {
                        let ks: Vec<_> = k.split("-").collect();
                        if ks.len() == 3 {
                            if let (Ok(who), Ok(what)) =
                                (Signatory::from_str(ks[1]), Field::from_str(ks[2]))
                            {
                                match what {
                                    Field::Pubkey => return (Some(who), v.to_str().ok(), acc.2),
                                    Field::Signature => return (Some(who), acc.1, v.to_str().ok()),
                                }
                            }
                        }
                    };
                    acc
                })
        {
            let pk: Base64<VerifyingKey> = serde_json::from_str(&quote(pk)).map_err(error)?;
            let sig: Base64<SignatureBytes> = serde_json::from_str(&quote(sig)).map_err(error)?;
            let bytes = hyper::body::to_bytes(body).await.map_err(error)?;
            if let Ok(()) = pk.0.verify(&bytes, &sig.0.into()) {
                let body2 = Body::from(bytes);
                let req = Request::from_parts(parts, body2);
                match <axum::Json<T> as FromRequest<S, Body>>::from_request(req, state).await {
                    Ok(value) => Ok(Self {
                        signatory,
                        public_key: pk,
                        signature: Base64(sig.0.into()),
                        data: value.0,
                    }),
                    Err(rejection) => Err(error(rejection)),
                }
            } else {
                Err(error("invalid signature"))
            }
        } else {
            Err(error("missing headers"))
        }
    }
}
