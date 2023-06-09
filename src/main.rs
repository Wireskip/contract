use axum::{
    routing::{get, post},
    Router,
};
use config::Config;
use ed25519_dalek::Keypair;
use log::*;
use rand::rngs::OsRng;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use semver::{BuildMetadata, Prerelease, Version};
use serde::Serialize;
use std::{
    collections::HashMap,
    env, fs,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

mod api;
mod auth;
mod b64e;
mod cfg;
mod contract;
mod directory;
mod signable;
mod signed;
mod state;
mod time;

use crate::b64e::Base64;
use crate::cfg::Cfg;
use crate::contract::{calc, tracker};
use crate::time::utime;

// version of this binary
static VERSION: Version = Version {
    major: 0,
    minor: 1,
    patch: 0,
    pre: Prerelease::EMPTY,
    build: BuildMetadata::EMPTY,
};

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
            keypair: &'a Base64<Keypair>,
        }

        let mut rng = OsRng {};
        let kp: Keypair = Keypair::generate(&mut rng);

        fs::write(
            p.join("key.pub"),
            serde_json::to_string(&Base64(kp.public)).unwrap(),
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

    println!("Listening on {}", cfg.address);

    let pk = match cfg.keypair {
        Some(Base64(ref kp)) => kp.public.clone(),
        None => panic!("No keys defined -- is your config.local.json5 in place? `init` done?"),
    };

    let kp = cfg.keypair.unwrap().0;

    let calc = calc::DefaultShareCalc {
        value: cfg.pubdef.servicekey.value,
        fee_frac: cfg.pubdef.settlement.fee_percent / Decimal::ONE_HUNDRED,
        rsh_frac: dec!(5) / Decimal::ONE_HUNDRED, // hardcoded revenue share
    };

    let state: state::SafeInner = Arc::new(RwLock::new(state::Custom {
        relays: HashMap::new(),
        signer: Arc::new(kp),
        public: cfg::mkpublic(cfg.pubdef.clone(), pk),
        sts: tracker::Tracker::new(Arc::new(Box::new(calc))),
    }));

    let bgstate = state.clone();

    tokio::task::spawn(async move {
        debug!("- Tracker thread spawned!");
        loop {
            let unow = utime(SystemTime::now());
            let unext = bgstate.write().unwrap().sts.tick(unow);
            tokio::time::sleep(Duration::from_secs(unext - unow)).await
        }
    });

    // NOTE: double routes for now
    // (they are considered equal / canonicalized by go stdlib in client but not axum)
    let app = Router::new()
        .route("/info", get(directory::info_get_handler))
        .route("//info", get(directory::info_get_handler))
        .route(
            "/relays",
            get(directory::relays_get_handler)
                .post(directory::relays_post_handler)
                .delete(directory::relays_delete_handler),
        )
        .route(
            "//relays",
            get(directory::relays_get_handler)
                .post(directory::relays_post_handler)
                .delete(directory::relays_delete_handler),
        )
        .route(
            "/issue-accesskeys",
            post(auth::issue_accesskeys_post_handler),
        )
        .route(
            "//issue-accesskeys",
            post(auth::issue_accesskeys_post_handler),
        )
        .route(
            "/servicekey/activate",
            post(contract::activate_post_handler),
        )
        .route(
            "//servicekey/activate",
            post(contract::activate_post_handler),
        )
        .route("/submit", post(contract::submit_post_handler))
        .route("//submit", post(contract::submit_post_handler))
        .with_state(state);

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
