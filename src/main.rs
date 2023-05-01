use config::Config;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::{distributions::Alphanumeric, rngs::OsRng, thread_rng, Rng};
use rust_decimal_macros::dec;
use semver::{BuildMetadata, Prerelease, Version};
use serde::{Deserialize, Serialize};
use signed::Signed;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{
    collections::HashMap,
    env, fs,
    sync::{Arc, RwLock},
};
use url::Url;

use axum::{
    extract::rejection::JsonRejection,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

mod b64e;
use b64e::*;

mod api;
use api::*;

mod signable;
mod signed;

// version of this binary
static VERSION: Version = Version {
    major: 0,
    minor: 1,
    patch: 0,
    pre: Prerelease::EMPTY,
    build: BuildMetadata::EMPTY,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
struct Cfg {
    address: String,
    keypair: Option<Base64<Keypair>>,
    #[serde(flatten)]
    pubdef: PubDefined,
}

// sane defaults
impl Default for Cfg {
    fn default() -> Self {
        let addr = "127.0.0.1:8081";
        Self {
            address: addr.to_string(),
            // keypair is pre-generated in main() so this is fine
            keypair: None,
            pubdef: PubDefined {
                endpoint: Url::parse(&("http://".to_owned() + addr)).unwrap(),
                info: None,
                upgrade_channels: HashMap::new(),
                pofsources: Vec::new(),
                servicekey: ServicekeyCfg {
                    currency: "USD".to_string(),
                    value: dec!(100),
                    duration: Duration::from_secs(600),
                },
                settlement: SettlementCfg {
                    fee_percent: dec!(5),
                    submission_window: Duration::from_secs(3600),
                },
                metadata: Some(Metadata {
                    name: Some("PLEASE CONFIGURE ME".to_string()),
                    operator: Some("TEST CONTRACT WITH DEFAULT CONFIG".to_string()),
                    ..Default::default()
                }),
            },
        }
    }
}

// fill out the derived fields
fn mkpublic(def: PubDefined, pk: PublicKey) -> Public {
    Public {
        defined: def.clone(),
        derived: PubDerived {
            pubkey: Base64(pk),
            public_key: Base64(pk),
            version: VERSION.clone(),
            enrollment: Default::default(),
            directory: Directory {
                endpoint: def.endpoint.clone(),
                public_key: Base64(pk),
            },
        },
    }
}

// handler shared state
#[derive(Clone)]
struct OurState {
    relays: HashMap<String, Relay>,
    signer: Arc<dyn Signer<Signature> + Send + Sync>,
    public: Public,
}

// convenience type abbreviations:

// actual state datatype
type SafeStateInner = Arc<RwLock<OurState>>;

// what is passed to handlers
type SafeState = State<SafeStateInner>;

// DIRECTORY HANDLERS

async fn relays_post(
    State(st): SafeState,
    body: Result<Json<Relay>, JsonRejection>,
) -> Json<Status> {
    eprintln!("Relay POSTed: {:?}", body);
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

async fn relays_delete(
    State(st): SafeState,
    body: Result<Json<Relay>, JsonRejection>,
) -> Json<Status> {
    eprintln!("Relay DELETEd: {:?}", body);
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
                eprintln!(
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

async fn relays_get(State(st): SafeState) -> impl IntoResponse {
    eprintln!("Relay GET");
    let mut header_map = HeaderMap::new();
    let st = st.read().unwrap();
    let s = serde_json::to_string(&st.relays.clone()).unwrap();
    let sig = Base64(st.signer.sign(s.as_bytes())).to_string();
    header_map.insert(
        "wireleap-directory-pubkey",
        st.public.derived.public_key.to_string().parse().unwrap(),
    );
    header_map.insert("wireleap-directory-signature", sig.parse().unwrap());
    (header_map, s)
}

async fn info_get(State(st): SafeState) -> Json<Public> {
    Json(st.read().unwrap().public.clone())
}

// END DIRECTORY HANDLERS

// AUTH HANDLERS
// TODO unix socket support
// https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs

fn mk_nonce(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

// NOTE: we don't really expect to work with times before epoch, but is this safe enough?
fn utime(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs()
}

fn mk_pof(s: &dyn Signer<Signature>, pof_type: String, duration: u64) -> Pof {
    let nonce = mk_nonce(18);
    let expiration = utime(SystemTime::now()) + duration;
    let msg = vec![pof_type.clone(), expiration.to_string(), nonce.clone()].join(":");
    let signature = Base64(s.sign(msg.as_bytes()));
    Pof {
        pof_type,
        nonce,
        expiration,
        signature,
    }
}

async fn issue_accesskeys_post(
    State(st): SafeState,
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

// END AUTH HANDLERS

// START CONTRACT HANDLERS

async fn sk_activate(
    State(st): SafeState,
    body: Result<Json<ActivationRequest>, JsonRejection>,
) -> impl IntoResponse {
    match body {
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
                signature: Base64(st.signer.sign(msg.as_bytes())),
                settlement_open: uso,
                settlement_close: uss,
            };

            println!("{:#?}", skc);
            Json(skc).into_response()
        }
        Err(e) => Json(Status {
            code: 400,
            desc: e.to_string(),
        })
        .into_response(),
    }
}

async fn st_submit(
    State(st): SafeState,
    body: Result<Json<Signed<Sharetoken>>, JsonRejection>,
) -> impl IntoResponse {
    match body {
        Ok(Json(payload)) => {
            let st = st.read().unwrap();
            (if payload.contract.public_key != st.public.derived.public_key {
                Json(Status {
                    code: 400,
                    desc: "Sharetoken is not for this contract".to_string(),
                })
            } else {
                Json(Status {
                    code: 200,
                    desc: "OK".to_string(),
                })
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

// END CONTRACT HANDLERS

#[tokio::main]
async fn main() {
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

    let state: SafeStateInner = Arc::new(RwLock::new(OurState {
        relays: HashMap::new(),
        signer: Arc::new(kp),
        public: mkpublic(cfg.pubdef.clone(), pk),
    }));

    // NOTE: double routes for now
    // (they are considered equal / canonicalized by go stdlib in client but not axum)
    let app = Router::new()
        .route("/info", get(info_get))
        .route("//info", get(info_get))
        .route(
            "/relays",
            get(relays_get).post(relays_post).delete(relays_delete),
        )
        .route(
            "//relays",
            get(relays_get).post(relays_post).delete(relays_delete),
        )
        .route("/issue-accesskeys", post(issue_accesskeys_post))
        .route("//issue-accesskeys", post(issue_accesskeys_post))
        .route("/servicekey/activate", post(sk_activate))
        .route("//servicekey/activate", post(sk_activate))
        .route("/submit", post(st_submit))
        .route("//submit", post(st_submit))
        .with_state(state);

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
