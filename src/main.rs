use crate::{
    cfg::Cfg,
    contract::tracker::BalanceUpdate,
    contract::{calc, tracker},
};
use axum::{
    routing::{get, post},
    Router, ServiceExt,
};
use config::Config;
use ed25519_dalek::SigningKey;
use log::*;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use semver::Version;
use serde::Serialize;
use std::{
    collections::HashMap,
    env, fs,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{mpsc, RwLock};
use tower::layer::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use ws_common::{b64e::Base64, time::utime};

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
    env_logger::init();

    let mut p = env::current_exe().unwrap();
    p.pop();

    let main = p.join("config.json5");
    if !main.exists() {
        fs::write(main, serde_json::to_string(&Cfg::default()).unwrap())
            .expect("Unable to write config file");
    }

    let local = p.join("config.local.json5");
    if !local.exists() {
        // to write just the correct config subset
        #[derive(Serialize)]
        struct K<'a> {
            keypair: &'a Base64<SigningKey>,
        }

        let mut rng = OsRng {};
        let kp: SigningKey = SigningKey::generate(&mut rng);

        fs::write(
            p.join("key.pub"),
            serde_json::to_string(&Base64(kp.verifying_key())).unwrap(),
        )
        .expect("Unable to write pubkey compat file");
        fs::write(
            local,
            serde_json::to_string(&K {
                keypair: &Base64(kp),
            })
            .unwrap(),
        )
        .expect("Unable to write local config file");
    }

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "init" {
        // our job here is done
        return;
    }

    let cfg: Cfg = Config::builder()
        .add_source(config::File::from(p.join("config")))
        .add_source(config::File::from(p.join("config.local")))
        .add_source(config::Environment::with_prefix("WIRESKIP_CONTRACT"))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();

    info!("Listening on {}", cfg.address);

    let pk = match cfg.keypair {
        Some(Base64(ref kp)) => kp.verifying_key().clone(),
        None => panic!("No keys defined -- is your config.local.json5 in place? `init` done?"),
    };

    let kp = cfg.keypair.unwrap().0;

    let calc = calc::DefaultShareCalc {
        value: cfg.pubdef.servicekey.value,
        fee_frac: cfg.pubdef.settlement.fee_percent / Decimal::ONE_HUNDRED,
        rsh_frac: dec!(5) / Decimal::ONE_HUNDRED, // hardcoded revenue share
    };

    let (txn_tx, txn_rx) = mpsc::channel(100);
    let (watcher_tx, _watcher_rx) = mpsc::channel(100);

    let state: state::SafeInner = Arc::new(RwLock::new(state::Custom {
        relays: HashMap::new(),
        signer: Arc::new(kp),
        public: cfg::mkpublic(cfg.pubdef.clone(), pk),
        tracker: Arc::new(RwLock::new(tracker::Tracker::new(
            Arc::new(Box::new(calc)),
            5,
            txn_rx,
        ))),
        txn_tx: txn_tx.clone(),
        watcher_tx: watcher_tx.clone(),
    }));

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

    tokio::task::spawn(async move {
        debug!("- Withdrawal status update thread spawned!");
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            debug!("- Sending withdrawal status update!");
            txn_tx
                .send(BalanceUpdate {
                    relay: "dummy".to_string(),
                    action: tracker::Action::Apply,
                })
                .await
                .unwrap()
        }
    });

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
            .with_state(state),
    );

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
