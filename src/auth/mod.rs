use axum::{
    extract::{rejection::JsonRejection, State},
    response::IntoResponse,
    Json,
};
use ed25519_dalek::{Signature, Signer};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::time::SystemTime;

use crate::{
    api::{Accesskey, AccesskeyRequest, Contract, Pof, Status},
    api::b64e::Base64,
    VERSION,
};

// TODO unix socket support
// https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs

fn mk_nonce(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn mk_pof(s: &dyn Signer<Signature>, pof_type: String, duration: u64) -> Pof {
    let nonce = mk_nonce(18);
    let expiration = crate::time::utime(SystemTime::now()) + duration;
    let msg = vec![pof_type.clone(), expiration.to_string(), nonce.clone()].join(":");
    let signature = Base64(s.sign(msg.as_bytes()).to_bytes());
    Pof {
        pof_type,
        nonce,
        expiration,
        signature,
    }
}

pub async fn issue_accesskeys_post_handler(
    State(st): crate::state::Safe,
    body: Result<Json<AccesskeyRequest>, JsonRejection>,
) -> impl IntoResponse {
    match body {
        Ok(Json(payload)) => {
            let st = st.read().unwrap();
            Json(Accesskey {
                version: VERSION.clone(),
                contract: Contract {
                    endpoint: st.public.defined.endpoint.clone(),
                    public_key: st.public.derived.public_key,
                },
                pofs: (0..payload.quantity)
                    .map(|_| mk_pof(&*st.signer, payload.pof_type.clone(), payload.duration))
                    .collect(),
            })
            .into_response()
        }
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        })
        .into_response(),
    }
}
