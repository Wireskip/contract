use config::Config;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::{distributions::Alphanumeric, rngs::OsRng, thread_rng, Rng};
use semver::{BuildMetadata, Prerelease, Version};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
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
            directory: Directory{
                endpoint: def.endpoint.clone(),
                public_key: Base64(pk),
            },
        },
    }
}

// handler shared state
#[derive(Clone)]
struct DirState {
    relays: HashMap<String, Relay>,
    signer: Arc<dyn Signer<Signature> + Send + Sync>,
    public: Public,
}

// convenience type abbreviations:

// actual state datatype
type SafeStateInner = Arc<RwLock<DirState>>;

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
fn utime() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs()
}

fn mk_pof(s: &dyn Signer<Signature>, poftype: String, duration: u64) -> Pof {
    let nonce = mk_nonce(18);
    let expiration = utime() + duration;
    let msg = vec![poftype.clone(), expiration.to_string(), nonce.clone()].join(":");
    let signature = Base64(s.sign(msg.as_bytes()));
    Pof {
        poftype,
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
                    // TODO FIXME hardcoded old contract for testing
                    endpoint: Url::parse(&"http://127.0.0.1:8080/").unwrap(),
                    // endpoint: st.public.defined.endpoint.clone(),
                    public_key: st.public.derived.public_key,
                },
                pofs: (0..payload.quantity)
                    .map(|_| mk_pof(&*st.signer, payload.poftype.clone(), payload.duration))
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

#[tokio::main]
async fn main() {
    let mut p = env::current_exe().unwrap();
    p.pop();

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

    let state: SafeStateInner = Arc::new(RwLock::new(DirState {
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
        .with_state(state);

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
