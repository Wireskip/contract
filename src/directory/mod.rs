use crate::{
    api::{Public, Relay, Status},
    api::b64e::Base64,
};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use log::{debug, warn};

pub async fn relays_post_handler(
    State(st): crate::state::Safe,
    body: Result<Json<Relay>, JsonRejection>,
) -> Json<Status> {
    debug!("Relay POSTed: {:?}", body);
    match body {
        Ok(Json(payload)) => {
            let mut st = st.write().unwrap();
            if st.public.derived.enrollment.role(payload.role).record(1) {
                st.relays.insert(payload.address.clone(), payload);
                Json(Status {
                    code: 200,
                    desc: "OK".to_string(),
                })
            } else {
                Json(Status {
                    code: 500,
                    desc: "Too many relays!".to_string(),
                })
            }
        }
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        }),
    }
}

pub async fn relays_delete_handler(
    State(st): crate::state::Safe,
    body: Result<Json<Relay>, JsonRejection>,
) -> Json<Status> {
    debug!("Relay DELETEd: {:?}", body);
    match body {
        Ok(Json(payload)) => {
            let mut st = st.write().unwrap();
            if !st.relays.contains_key(&payload.address) {
                return Json(Status {
                    code: 404,
                    desc: "No such relay".to_string(),
                });
            }
            let roleinfo = st.public.derived.enrollment.role(payload.role);
            if !roleinfo.record(-1) {
                warn!(
                    "Relay bookkeeping underflow for {:?} at {:?} ({})! Weird.",
                    payload.role, roleinfo.count, -1,
                )
            };
            st.relays.remove(&payload.address);
            Json(Status {
                code: 200,
                desc: "OK".to_string(),
            })
        }
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        }),
    }
}

pub async fn relays_get_handler(State(st): crate::state::Safe) -> impl IntoResponse {
    debug!("Relay GET");
    let mut header_map = HeaderMap::new();
    let st = st.read().unwrap();
    let s = serde_json::to_string(&st.relays.clone()).unwrap();
    let sig = Base64(st.signer.sign(s.as_bytes()).to_bytes()).to_string();
    header_map.insert(
        "wireleap-directory-pubkey",
        st.public.derived.public_key.to_string().parse().unwrap(),
    );
    header_map.insert("wireleap-directory-signature", sig.parse().unwrap());
    (header_map, s)
}

pub async fn info_get_handler(State(st): crate::state::Safe) -> Json<Public> {
    Json(st.read().unwrap().public.clone())
}
