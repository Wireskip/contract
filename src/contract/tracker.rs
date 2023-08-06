use super::calc::SafeCalc;
use crate::{
    api::signable::Signable,
    api::{chronosort::ChronoSort, Sharetoken},
};
use log::debug;
use rust_decimal::Decimal;
use std::{
    collections::{BinaryHeap, HashMap},
    sync::Arc,
};
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use ws_common::b64e::Base64;

#[derive(Clone, Debug)]
pub enum Action {
    Apply,
    Abort,
}

#[derive(Clone, Debug)]
pub struct BalanceUpdate {
    pub relay: String,
    pub action: Action,
}

/// The tracker keeps track of: Sharetokens, shares (only during settlement), resulting balances.
pub struct Tracker {
    /// The defined share reward calculation function.
    calc: SafeCalc,
    /// The interval at which to attempt settlement of accumulated Sharetokens.
    /// Smaller values => higher granularity over time, more overhead.
    /// Higher values  => lower granularity over time, less overhead.
    interval: i64,
    /// The to-be-settled `Sharetoken` queue. Using a BinaryHeap ensures the Sharetokens are sorted
    /// chronologically.
    sts: BinaryHeap<ChronoSort<Sharetoken>>,
    /// The balances table with actual and pending relay balances.
    pub balances: Balances,
    /// For temporary use during settlement calculation of one SK only.
    totals: HashMap<String, Decimal>,
    /// For temporary use during settlement calculation of one SK only.
    tokens: HashMap<(String, String), Decimal>,
    /// For receiving txn state updates.
    txn_chan: ReceiverStream<BalanceUpdate>,
}

/// The balances struct allows threadsafe access to the actual and pending balance of a relay.
#[derive(Clone, Debug, Default)]
pub struct Balances {
    /// New entries can be added on demand, existing entries' modification is mutex-protected;
    /// therefore we do not need to mutex-protect the entire hashmap for now.
    /// The HashMap itself is Send + Sync, it can be shared safely as is (1 writer, N readers).
    h: HashMap<String, Arc<Mutex<(Decimal, Decimal)>>>,
}

/// The balances table with actual and pending relay balances.
impl Balances {
    /// Draft a pending change. This prevents other changes from being drafted simultaneously and
    /// will be applied after the next commit.
    pub async fn draft(&mut self, rk: &str, delta: Decimal) -> Result<(), String> {
        // TODO look into not allocating string copy
        let mut cur = self.h.entry(rk.to_string()).or_default().lock().await;

        if cur.1 != Decimal::ZERO {
            return Err("balance change already pending!".to_string());
        }

        if delta.is_sign_negative() {
            // it's a withdrawal
            if cur.0 <= Decimal::ZERO {
                return Err("you got zero cash!".to_string());
            } else if cur.0 + delta <= Decimal::ZERO {
                return Err(format!(
                    "insufficient balance: {} requested, {} available",
                    delta, cur.0
                ));
            } else if Decimal::MIN - delta >= cur.0 {
                // check for underflow
                return Err("balance overflow!!!".to_string());
            } else {
                // to be finalized later
                cur.1 = delta;
            }
        } else {
            // it's a share reward... probably
            // just check for overflow
            if Decimal::MAX - delta <= cur.0 {
                return Err("balance overflow!!!".to_string());
            }
            cur.1 = delta;
        };
        Ok(())
    }

    /// Apply or abort a pending change at a later point.
    async fn commit(&mut self, rk: &str, act: Action) {
        // TODO look into not allocating string copy
        let mut cur = self.h.entry(rk.to_string()).or_default().lock().await;

        match act {
            Action::Apply => {
                // in production, the value can be 0 and the reward can thus be 0
                // in debug builds, we are interested in when the reward is 0 despite the value not being 0
                // UNLESS it is a test specifically with 0 value
                if cfg!(debug_assertions) {
                    if cur.1 == Decimal::ZERO && !cfg!(allow_zero_apply) {
                        panic!("nothing to apply, delta = 0! {:?}", cur);
                    }
                }

                let delta = cur.1;
                cur.0 += delta;
                cur.1 = Decimal::ZERO
            }
            Action::Abort => {
                if cfg!(debug_assertions) {
                    if cur.1 == Decimal::ZERO && !cfg!(allow_zero_abort) {
                        panic!("nothing to abort, delta = 0! {:?}", cur);
                    }
                }

                cur.1 = Decimal::ZERO
            }
        }
    }

    /// How many entries are there?
    pub fn len(&self) -> usize {
        self.h.len()
    }
}

/// The tracker keeps track of: Sharetokens, shares (only during settlement), resulting balances.
impl Tracker {
    /// Creates a new tracker with the given share reward calculation function and settlement check
    /// interval.
    pub fn new(calc: SafeCalc, interval: i64, txn_chan: Receiver<BalanceUpdate>) -> Tracker {
        Tracker {
            calc,
            interval,
            sts: BinaryHeap::new(),
            balances: Balances::default(),
            totals: HashMap::new(),
            tokens: HashMap::new(),
            txn_chan: ReceiverStream::new(txn_chan),
        }
    }

    /// Enqueues a `Sharetoken` for settlement. The `Sharetoken` itself contains all the necessary
    /// information to perform the settlement in favor of a relay for a given servicekey.
    pub fn push(&mut self, st: Sharetoken) {
        self.sts.push(ChronoSort(st))
    }

    /// Synchronous (blocking) tracker tick to settle (over)due Sharetokens.
    /// Intended to be called periodically from a separate Tokio task.
    /// Returns the next possible time for checking: either the settlement close of the next
    /// `Sharetoken` in the queue or `interval` seconds later if the queue is empty.
    pub async fn tick(&mut self, t: i64) -> i64 {
        debug!("Tracker tick!");
        let mut next = t + self.interval;

        loop {
            if let Some(st) = self.sts.peek() {
                debug!("Peeked ST from queue.");
                let st = &st.0; // unwrap ChronoSort
                if st.contract.settlement_close <= t {
                    if let Some(st) = self.sts.pop() {
                        debug!(
                            "st.contract.settlement_close ({}) <= t ({}), settling now!",
                            st.contract.settlement_close, t
                        );
                        debug!("Popped ST from queue.");
                        let pks = st.relay_pubkey.to_string();
                        let sks = Base64(st.public_key()).to_string();
                        *self.totals.entry(sks.clone()).or_default() += Decimal::ONE;
                        *self.tokens.entry((sks, pks)).or_default() += Decimal::ONE;
                        // look for more tokens to settle
                        continue;
                    }
                } else {
                    debug!(
                        "ST queue has future STs, next ST settlement will happen at {}",
                        st.contract.settlement_close
                    );
                    next = st.contract.settlement_close;
                    break;
                }
            }
            debug!("ST queue has no more STs, attempting settlement.");
            break;
        }

        // calculate actual balances off shares
        for (k, v) in self
            .tokens
            .drain()
            .map(|((sk, rk), v)| (rk, v / self.totals[&sk]))
        {
            let r = self.calc.reward(v);
            assert!(r.is_sign_positive()); // the subsequent unwrap depends on this
            self.balances.draft(&k, r).await.unwrap();
            self.balances.commit(&k, Action::Apply).await
        }
        if self.balances.len() > 0 {
            debug!("* ST balances = {:#?}", self.balances);
        }
        if self.totals.len() > 0 {
            debug!("* ST totals = {:#?}", self.totals);
        }
        self.totals.clear();
        debug!("Tracker tick finished.");
        next
    }

    pub async fn txn_tick(&mut self) {
        debug!("Looking for balance update...");
        if let Some(upd) = self.txn_chan.next().await {
            debug!("Balance update received! {:?}", upd);
            self.balances.commit(&upd.relay, upd.action).await
        } else {
            debug!("No balance update received!");
        }
    }
}
