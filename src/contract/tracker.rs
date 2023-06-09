use super::calc::SafeCalc;
use crate::{api::Sharetoken, b64e::Base64, signable::Signable};
use log::debug;
use rust_decimal::Decimal;
use std::collections::{BinaryHeap, HashMap};

#[derive(Clone)]
pub struct Tracker {
    calc: SafeCalc,
    sts: BinaryHeap<Sharetoken>,
    balances: HashMap<String, Decimal>,
    totals: HashMap<String, Decimal>,
    tokens: HashMap<(String, String), Decimal>,
}

impl Tracker {
    pub fn new(calc: SafeCalc) -> Tracker {
        // TODO reward
        Tracker {
            calc,
            sts: BinaryHeap::new(),
            balances: HashMap::new(),
            totals: HashMap::new(),
            tokens: HashMap::new(),
        }
    }

    pub fn push(&mut self, st: Sharetoken) {
        self.sts.push(st)
    }

    pub fn tick(&mut self, t: u64) -> u64 {
        debug!("Tracker tick!");
        // idle at 5s intervals, should maybe allow tweaking for production use
        let mut next = t + 5;
        loop {
            if let Some(st) = self.sts.peek() {
                debug!("Peeked ST from queue.");
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
            self.balances.insert(k, self.calc.reward(v));
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
}
