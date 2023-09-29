use crate::{
    api::{Public, Relay},
    contract::tracker::{BalanceUpdate, Tracker},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};
use ws_common::api::Withdrawal;

// handler shared state
#[derive(Clone)]
pub struct Custom {
    pub relays: HashMap<String, Relay>,
    pub public: Public,
    pub tracker: Arc<RwLock<Tracker>>,
    pub txn_tx: Sender<BalanceUpdate>,
    pub watcher_tx: Sender<Withdrawal>,
}

pub type SafeInner = Arc<RwLock<Custom>>;

pub type Safe = ws_common::state::Safe<SafeInner>;
