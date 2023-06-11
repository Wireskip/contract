use crate::api::ActivationRequest;
use crate::{
    api::{SKContract, Sharetoken, Status},
    b64e::Base64,
    signed::Signed,
    time::utime,
};
use axum::{
    extract::{rejection::JsonRejection, State},
    response::IntoResponse,
    Json,
};
use log::debug;
use std::time::SystemTime;

pub mod calc;
pub mod tracker;

pub async fn activate_post_handler(
    State(st): crate::state::Safe,
    body: Result<Json<ActivationRequest>, JsonRejection>,
) -> impl IntoResponse {
    match body {
        // TODO validate payload
        Ok(Json(_)) => {
            let st = st.read().unwrap();

            let now = SystemTime::now();
            let skd = st.public.defined.servicekey.duration;
            let subw = st.public.defined.settlement.submission_window;

            let pk = st.public.derived.public_key;
            let so = now + skd;
            let ss = so + subw;

            let uso = utime(so);
            let uss = utime(ss);

            let msg = vec![pk.to_string(), uso.to_string(), uss.to_string()].join(":");

            let skc = SKContract {
                public_key: pk,
                signature: Base64(st.signer.sign(msg.as_bytes()).to_bytes()),
                settlement_open: uso,
                settlement_close: uss,
            };
            Json(skc).into_response()
        }
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        })
        .into_response(),
    }
}

pub async fn submit_post_handler(
    State(st): crate::state::Safe,
    body: Result<Json<Signed<Sharetoken>>, JsonRejection>,
) -> impl IntoResponse {
    debug!("Entered /submit handler.");
    match body {
        Ok(Json(payload)) => {
            debug!("/submit body is OK");
            let mut st = st.write().unwrap();
            (if payload.contract.public_key != st.public.derived.public_key {
                Json(Status {
                    code: 400,
                    desc: "Sharetoken is not for this contract".to_string(),
                })
            } else {
                st.sts.push(payload.0);
                Json(Status {
                    code: 200,
                    desc: "OK".to_string(),
                })
            })
            .into_response()
        }
        Err(e) => {
            debug!("/submit body is NOT OK: {:?}", e);
            Json(Status {
                code: 400,
                desc: e.to_string(),
            })
            .into_response()
        }
    }
}
