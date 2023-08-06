use crate::VERSION;
use axum::{
    extract::{rejection::JsonRejection, State},
    response::IntoResponse,
    Json,
};
use ed25519_dalek::{Signature, Signer};
use std::time::SystemTime;
use ws_common::{
    api::{Accesskey, AccesskeyRequest, Contract, Pof, Status, WithdrawalRequest},
    b64e::Base64,
    nonce::mk_nonce,
    time::utime,
};

// TODO unix socket support
// https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs

fn mk_pof(s: &dyn Signer<Signature>, pof_type: String, duration: i64) -> Pof {
    let nonce = mk_nonce(18);
    let expiration = utime(SystemTime::now()) + duration;
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
            let st = st.read().await;
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

// only provided temporarily as backwards compat
// withdrawals will be reworked in the future so this isn't needed
pub async fn verify_withdrawal_request_post_handler(
    State(_): crate::state::Safe,
    body: Result<Json<WithdrawalRequest>, JsonRejection>,
) -> impl IntoResponse {
    match body {
        Ok(Json(_payload)) => Json(Status {
            code: 200,
            desc: "OK".to_string(),
        })
        .into_response(),
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        })
        .into_response(),
    }
}
