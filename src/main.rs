use url::Url;
use config::Config;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use semver::{BuildMetadata, Prerelease, Version};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use std::{env, fs, collections::HashMap, sync::{Arc, RwLock}};

use axum::{
    Json,
    Router,
    routing::get,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    extract::rejection::JsonRejection,
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
        defined: def,
        derived: PubDerived {
            public_key: Base64(pk),
            version: VERSION.clone(),
            enrollment: Default::default(),
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

        let mut csprng = OsRng {};
        let kp: Keypair = Keypair::generate(&mut csprng);

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
        .add_source(config::File::from(p.join("config.local")).required(false))
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

    // double routes for now (they are considered equal by go stdlib but not axum)
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
        .with_state(state);

    axum::Server::bind(&cfg.address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
