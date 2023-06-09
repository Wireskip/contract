use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use rust_decimal::Decimal;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::{collections::HashMap, time::Duration};
use url::Url;

use crate::b64e::*;
use crate::signable::*;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDerived {
    // TODO rename to public_key globally
    pub pubkey: Base64<PublicKey>,
    pub public_key: Base64<PublicKey>,
    pub version: Version,
    pub enrollment: Enrollment,
    pub directory: Directory,
}

#[derive(Serialize)]
pub struct Status {
    pub code: u16,
    #[serde(rename = "description")]
    pub desc: String,
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
    pub public_key: Base64<PublicKey>,
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
    pub public_key: Base64<PublicKey>,
}

// AUTH SECTION

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Pof {
    // "type" is a reserved keyword
    #[serde(rename = "type")]
    pub pof_type: String,
    pub nonce: String,
    pub expiration: u64,
    pub signature: Base64<Signature>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Contract {
    pub endpoint: Url,
    pub public_key: Base64<PublicKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccesskeyRequest {
    // "type" is a reserved keyword
    #[serde(rename = "type")]
    pub pof_type: String,
    pub quantity: u64,
    pub duration: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Accesskey {
    pub version: Version,
    pub contract: Contract,
    pub pofs: Vec<Pof>,
}

// CONTRACT SECTION

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PofSource {
    pub endpoint: Url,
    #[serde(rename = "type")]
    pub pof_type: String,
    pub pubkey: Base64<PublicKey>,
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
    pub endpoint: Url,
    #[serde(rename = "type")]
    pub pof_type: String,
    #[serde(with = "humantime_serde")]
    pub check_period: Duration,
    pub min_withdrawal: u64,
    pub max_withdrawal: u64,
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
    pub public_key: Base64<PublicKey>,
    pub pof: Pof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Servicekey {
    #[serde(rename = "private_key")]
    pub secret_key: Base64<SecretKey>,
    pub public_key: Base64<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<SKContract>,
}

// TODO implement stateful deserialization via seed to sign inner data?
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SKContract {
    pub public_key: Base64<PublicKey>,
    pub signature: Base64<Signature>,
    pub settlement_open: u64,
    pub settlement_close: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sharetoken {
    pub version: u8,
    pub public_key: Base64<PublicKey>,
    pub timestamp: u64,
    pub relay_pubkey: Base64<PublicKey>,
    pub signature: Base64<Signature>,
    pub nonce: String,
    pub contract: SKContract,
}

// TODO implement derive(Signable) procmacro?
impl Signable for Sharetoken {
    fn digest(&self) -> String {
        let r = vec![
            self.version.to_string(),
            self.public_key.to_string(),
            self.timestamp.to_string(),
            self.relay_pubkey.to_string(),
            "".to_string(), // sharekey was never implemented
            self.nonce.clone(),
            self.contract.public_key.to_string(),
            self.contract.signature.to_string(),
            self.contract.settlement_open.to_string(),
            self.contract.settlement_close.to_string(),
        ]
        .join(":");
        println!("{}", r);
        r
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.into()
    }

    fn signature(&self) -> Signature {
        self.signature.into()
    }

    fn sign(&mut self, kp: Keypair) {
        self.public_key = Base64(kp.public);
        self.signature = Base64(kp.sign(self.digest().as_bytes()));
    }
}

impl PartialEq for Sharetoken {
    fn eq(&self, other: &Self) -> bool {
        u64::eq(&self.timestamp, &other.timestamp)
    }
}

impl Eq for Sharetoken {}

impl PartialOrd for Sharetoken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        u64::partial_cmp(&self.timestamp, &other.timestamp)
    }
}

impl Ord for Sharetoken {
    fn cmp(&self, other: &Self) -> Ordering {
        Ordering::reverse(u64::cmp(&self.timestamp, &other.timestamp))
    }
}
