use url::Url;
use semver::Version;
use ed25519_dalek::PublicKey;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::b64e::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Public {
    #[serde(flatten)]
    pub defined: PubDefined,
    #[serde(flatten)]
    pub derived: PubDerived,
}

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
    pub public_key : Base64<PublicKey>,
    pub role : Role,
    pub address : String,
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

#[derive(Serialize)]
pub struct Status {
    pub code : u16,
    #[serde(rename = "description")]
    pub desc : String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RoleInfo {
    pub count: u32,
    pub restricted: bool,
}

impl RoleInfo {
    pub fn record(&mut self, delta : i8) -> bool {
        match self.count.checked_add_signed(delta.into()) {
            Some(i) => { self.count = i; true },
            None => false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDefined {
    pub endpoint: Url,
    pub info: Option<Url>,
    pub upgrade_channels: HashMap<String, HashMap<String, Version>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubDerived {
    pub public_key: Base64<PublicKey>,
    pub version: Version,
    pub enrollment: Enrollment,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Enrollment {
    fronting: RoleInfo,
    entropic: RoleInfo,
    backing: RoleInfo,
}

impl Enrollment {
    pub fn role(&mut self, r : Role) -> &mut RoleInfo {
        use Role::*;
        match r {
            Fronting => &mut self.fronting,
            Entropic => &mut self.entropic,
            Backing  => &mut self.backing,
        }
    }
}


