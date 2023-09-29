use crate::{
    api::PubDefined,
    contract::{calc, tracker},
};
use axum::{
    routing::{get, post},
    Router, ServiceExt,
};
use log::*;
use once_cell::sync::Lazy;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use semver::Version;
use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{mpsc, RwLock};
use tower::layer::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use ws_common::{b64e::Base64, bin::common_setup, cfg::ConfigType, time::utime};

mod api;
mod auth;
mod cfg;
mod contract;
mod directory;
mod state;

// version of this binary
static VERSION: Lazy<Version> = Lazy::new(|| Version::parse(env!("CARGO_PKG_VERSION")).unwrap());

#[tokio::main]
async fn main() {
    let cfg = match common_setup(ConfigType::<PubDefined>::new()) {
        Ok(Ok(c)) => c,
        Ok(Err(())) => return,
        Err(e) => panic!("{}", e),
    };

    let kp = cfg.keypair.clone().unwrap().0;

    let calc = calc::DefaultShareCalc {
        value: cfg.etc.servicekey.value,
        fee_frac: cfg.etc.settlement.fee_percent / Decimal::ONE_HUNDRED,
        rsh_frac: dec!(5) / Decimal::ONE_HUNDRED, // hardcoded revenue share
    };

    let (txn_tx, txn_rx) = mpsc::channel(100);
    let (watcher_tx, _watcher_rx) = mpsc::channel(100);

    let pk = match cfg.keypair {
        Some(Base64(ref kp)) => kp.verifying_key().clone(),
        None => panic!("No keys defined -- is your config.local.json5 in place? `init` done?"),
    };

    let state = ws_common::state::new(
        kp,
        Arc::new(RwLock::new(state::Custom {
            relays: HashMap::new(),
            public: cfg::mkpublic(cfg.etc.clone(), pk),
            tracker: Arc::new(RwLock::new(
                tracker::Tracker::new(cfg.root, Arc::new(Box::new(calc)), 5, txn_rx)
                    .await
                    .unwrap(),
            )),
            txn_tx: txn_tx.clone(),
            watcher_tx: watcher_tx.clone(),
        })),
    );

    let bgstate = state.clone();

    tokio::task::spawn(async move {
        debug!("- Tracker thread spawned!");
        loop {
            let unow = utime(SystemTime::now());
            let unext = bgstate.write().await.tracker.write().await.tick(unow).await;
            bgstate.write().await.tracker.write().await.txn_tick().await;
            tokio::time::sleep(Duration::from_secs((unext - unow).try_into().unwrap())).await
        }
    });

    /*
    tokio::task::spawn(async move {
        debug!("- Withdrawal status update thread spawned!");
        tokio::time::sleep(Duration::from_secs(5)).await;
        debug!("- Sending withdrawal status update.");
        txn_tx
            .send(BalanceUpdate {
                relay: "dummy".to_string(),
                action: tracker::Action::Apply,
            })
            .await
            .unwrap();
        debug!("- Withdrawal status update thread exited.");
    });
    */

    let app = NormalizePathLayer::trim_trailing_slash().layer(
        Router::new()
            .route("/info", get(directory::info_get_handler))
            .route(
                "/relays",
                get(directory::relays_get_handler)
                    .post(directory::relays_post_handler)
                    .delete(directory::relays_delete_handler),
            )
            .route(
                "/issue-accesskeys",
                post(auth::issue_accesskeys_post_handler),
            )
            .route(
                "/servicekey/activate",
                post(contract::activate_post_handler),
            )
            .route("/submit", post(contract::submit_post_handler))
            .route("/withdraw", post(contract::withdraw_post_handler))
            .route(
                "/verify-withdrawal-request",
                post(auth::verify_withdrawal_request_post_handler),
            )
            .route("/payout/balance", get(contract::balance_get_handler))
            .with_state(state),
    );

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
