use log::debug;
use rust_decimal::Decimal;
use std::sync::Arc;

pub trait ShareCalc {
    fn reward(&self, share: Decimal) -> Decimal;
}

// value, fee in %, revshare in %
pub struct DefaultShareCalc {
    pub value: Decimal,
    pub fee_frac: Decimal,
    pub rsh_frac: Decimal,
}

impl ShareCalc for DefaultShareCalc {
    fn reward(&self, share: Decimal) -> Decimal {
        let fee = self.fee_frac * self.value;
        let rsh = self.rsh_frac * self.value;

        debug!("Calculating reward for {} share as:", share);
        debug!("    {} * ({} - {} - {})", share, self.value, fee, rsh);

        share * (self.value - (self.fee_frac * self.value) - (self.rsh_frac * self.value))
    }
}

pub type SafeCalc = Arc<Box<dyn ShareCalc + Send + Sync>>;
