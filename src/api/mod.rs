use crate::api::timestamp::Timestamped;
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{SecretKey, Signer, VerifyingKey};
use rust_decimal::Decimal;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{collections::HashMap, time::Duration};
use url::Url;
use wireskip_macros::{Sign, Timestamped};
use ws_common::api::{Pof, WithdrawalState};

pub mod chronosort;
pub mod digestible;
pub mod headersignedjson;
pub mod signable;
pub mod signed;
pub mod timestamp;

use digestible::*;
use signable::*;
use ws_common::b64e::*;

// GENERAL SECTION

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Public {
    #[serde(flatten)]
    pub derived: PubDerived,
    #[serde(flatten)]
    pub defined: PubDefined,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDefined {
    pub endpoint: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Url>,
    pub upgrade_channels: HashMap<String, HashMap<String, Version>>,
    #[serde(rename = "proof_of_funding")]
    pub pofsources: Vec<PofSource>,
    pub servicekey: ServicekeyCfg,
    pub settlement: SettlementCfg,
    pub payout: PayoutCfg,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDerived {
    // TODO rename to public_key globally
    pub pubkey: Base64<VerifyingKey>,
    pub public_key: Base64<VerifyingKey>,
    pub version: Version,
    pub enrollment: Enrollment,
    pub directory: Directory,
}

// DIR SECTION

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Fronting,
    Entropic,
    Backing,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Relay {
    // TODO rename to public_key globally
    #[serde(rename = "pubkey")]
    pub public_key: Base64<VerifyingKey>,
    pub role: Role,
    pub address: String,
    pub versions: Versions,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Versions {
    pub software: Version,
    pub client_relay: Version,
    pub relay_relay: Version,
    pub relay_dir: Version,
    pub relay_contract: Version,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RoleInfo {
    pub count: u32,
    pub restricted: bool,
}

impl RoleInfo {
    pub fn record(&mut self, delta: i8) -> bool {
        match self.count.checked_add_signed(delta.into()) {
            Some(i) => {
                self.count = i;
                true
            }
            None => false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Enrollment {
    fronting: RoleInfo,
    entropic: RoleInfo,
    backing: RoleInfo,
}

impl Enrollment {
    pub fn role(&mut self, r: Role) -> &mut RoleInfo {
        use Role::*;
        match r {
            Fronting => &mut self.fronting,
            Entropic => &mut self.entropic,
            Backing => &mut self.backing,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Directory {
    pub endpoint: Url,
    pub public_key: Base64<VerifyingKey>,
}

// CONTRACT SECTION

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PofSource {
    pub endpoint: Url,
    #[serde(rename = "type")]
    pub pof_type: String,
    pub pubkey: Base64<VerifyingKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServicekeyCfg {
    pub currency: String,
    // TODO change to float when compat can be broken
    #[serde(with = "rust_decimal::serde::str")]
    pub value: Decimal,
    #[serde(with = "humantime_serde")]
    pub duration: Duration,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SettlementCfg {
    // TODO change to float when compat can be broken
    #[serde(with = "rust_decimal::serde::str")]
    pub fee_percent: Decimal,
    #[serde(with = "humantime_serde")]
    pub submission_window: Duration,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PayoutCfg {
    // The URL of the payment system.
    pub endpoint: Url,
    // Payment system type.
    #[serde(rename = "type")]
    pub ps_type: String,
    // How often to check for withdrawal status changes.
    #[serde(with = "humantime_serde")]
    pub check_period: Duration,
    // Minimum withdrawal amount.
    pub min_withdrawal: Option<u64>,
    // Maximum withdrawal amount.
    pub max_withdrawal: Option<u64>,
    // Optional info URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Url>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<Url>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ActivationRequest {
    // TODO rename to public_key globally
    #[serde(rename = "pubkey")]
    pub public_key: Base64<VerifyingKey>,
    pub pof: Pof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Servicekey {
    #[serde(rename = "private_key")]
    pub secret_key: Base64<SecretKey>,
    pub public_key: Base64<VerifyingKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<SKContract>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Sign)]
pub struct SKContract {
    pub public_key: Base64<VerifyingKey>,
    pub signature: Base64<SignatureBytes>,
    pub settlement_open: i64,
    pub settlement_close: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Sign, Timestamped)]
pub struct Sharetoken {
    pub version: u8,
    pub public_key: Base64<VerifyingKey>,
    pub timestamp: i64,
    pub relay_pubkey: Base64<VerifyingKey>,
    pub share_key: String, // unused
    pub nonce: String,
    pub signature: Base64<SignatureBytes>,
    #[digest_with_sig]
    pub contract: SKContract,
}

impl Sharetoken {
    // TODO different subdirs for contract & relay side
    pub fn subdir(&self) -> PathBuf {
        PathBuf::from(
            [self.public_key.to_string(), self.relay_pubkey.to_string()]
                .join(&std::path::MAIN_SEPARATOR_STR),
        )
    }

    pub fn filename(&self) -> String {
        self.signature.to_string()
    }

    pub fn path(&self) -> PathBuf {
        self.subdir().join(self.filename())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WithdrawalStateUpdate {
    pub id: String,
    pub state: WithdrawalState,
}
