use crate::api::headersignedjson::HeaderSignedJson;
use crate::api::{ActivationRequest, HttpClient, Withdrawal, WithdrawalRequest};
use crate::{
    api::b64e::Base64,
    api::signed::Signed,
    api::{SKContract, Sharetoken, Status},
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, State},
    response::IntoResponse,
    Json,
};
use hyper::{body, Method, Request};
use log::debug;
use rust_decimal::Decimal;
use std::time::SystemTime;
use crate::time::utime;

pub mod calc;
pub mod tracker;

pub async fn activate_post_handler(
    State(st): crate::state::Safe,
    body: Result<Json<ActivationRequest>, JsonRejection>,
) -> impl IntoResponse {
    match body {
        // TODO validate payload
        Ok(Json(_)) => {
            let st = st.read().await;

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
            let st = st.write().await;
            (if payload.contract.public_key != st.public.derived.public_key {
                Json(Status {
                    code: 400,
                    desc: "Sharetoken is not for this contract".to_string(),
                })
            } else {
                // TODO channel send
                st.tracker.write().await.push(payload.0);
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

pub async fn withdraw_post_handler(
    State(st): crate::state::Safe,
    rbody: Result<HeaderSignedJson<WithdrawalRequest>, Json<Status>>,
) -> axum::response::Result<Json<Withdrawal>, Json<Status>> {
    debug!("Entered /withdraw handler.");
    // TODO FIXME validation and error reporting needs to be generalized!
    match rbody {
        Ok(hsj) => {
            debug!("/withdraw body is OK");
            let st = st.write().await;
            if st.public.defined.payout.ps_type == hsj.data.w_type {
                let wrs = serde_json::to_string(&hsj.data).map_err(|e| {
                    Json(Status {
                        code: 500,
                        desc: e.to_string(),
                    })
                })?;

                let req = Request::builder()
                    .method(Method::POST)
                    .uri(st.public.defined.payout.endpoint.to_string())
                    .body(Body::from(wrs))
                    .expect("request builder");

                let rk = hsj.public_key.to_string();

                st.tracker
                    .write()
                    .await
                    .balances
                    .draft(&rk, -Decimal::from(hsj.data.amount))
                    .await
                    .map_err(|e| {
                        Json(Status {
                            code: 500,
                            desc: e.to_string(),
                        })
                    })?;
                // TODO reuse httpclient
                let res = HttpClient::new().request(req).await.map_err({
                    |e| {
                        Json(Status {
                            code: 500,
                            desc: format!(
                                "could not perform payment system request: {}",
                                e.to_string()
                            ),
                        })
                    }
                })?;
                let w: Withdrawal = serde_json::from_slice(
                    &body::to_bytes(res.into_body()).await.map_err(|e| {
                        Json(Status {
                            code: 500,
                            desc: format!(
                                "could not get body from payment system: {}",
                                e.to_string()
                            ),
                        })
                    })?,
                )
                .map_err(|e| {
                    Json(Status {
                        code: 500,
                        desc: format!("could not get body from payment system: {}", e.to_string()),
                    })
                })?;
                if w.state_data.state == crate::api::WithdrawalState::Pending {
                    st.watcher_tx.send(w.clone()).await.map_err(|e| {
                        Json(Status {
                            code: 500,
                            desc: format!(
                                "could not send pending withdrawal to watcher: {}",
                                e.to_string()
                            ),
                        })
                    })?;
                };
                Ok(Json(w))
            } else {
                Err(Json(Status {
                    code: 500,
                    desc: "no payout methods fits withdrawal".to_string(),
                }))
            }
        }
        Err(e) => {
            debug!("/withdraw body is NOT OK: {:?}", e);
            Err(e)
        }
    }
}
