use std::{collections::HashMap, sync::Arc};

use axum::extract::State;
use ed25519_dalek::{Signature, Signer};
use tokio::sync::{mpsc::Sender, RwLock};

use crate::{
    api::{Public, Relay, Withdrawal},
    contract::tracker::{BalanceUpdate, Tracker},
};

// handler shared state
// TODO derive separate threadsafe substates via FromRef?
#[derive(Clone)]
pub struct Custom {
    pub relays: HashMap<String, Relay>,
    pub signer: Arc<dyn Signer<Signature> + Send + Sync>,
    pub public: Public,
    pub tracker: Arc<RwLock<Tracker>>,
    pub txn_tx: Sender<BalanceUpdate>,
    pub watcher_tx: Sender<Withdrawal>,
}

// convenience type abbreviations:

// actual state datatype
pub type SafeInner = Arc<RwLock<Custom>>;

// what is passed to handlers
pub type Safe = State<SafeInner>;
