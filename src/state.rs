use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::extract::State;
use ed25519_dalek::{Signature, Signer};

use crate::{
    api::{Public, Relay},
    contract::tracker::Tracker,
};

// handler shared state
#[derive(Clone)]
pub struct Custom {
    pub relays: HashMap<String, Relay>,
    pub signer: Arc<dyn Signer<Signature> + Send + Sync>,
    pub public: Public,
    pub sts: Tracker,
}

// convenience type abbreviations:

// actual state datatype
pub type SafeInner = Arc<RwLock<Custom>>;

// what is passed to handlers
pub type Safe = State<SafeInner>;
