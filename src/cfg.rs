use ed25519_dalek::{SigningKey, VerifyingKey};
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use url::Url;

use crate::{
    api::{Directory, Metadata, PubDefined, PubDerived, Public, ServicekeyCfg, SettlementCfg},
    api::b64e::Base64,
    VERSION,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Cfg {
    pub address: String,
    pub keypair: Option<Base64<SigningKey>>,
    #[serde(flatten)]
    pub pubdef: PubDefined,
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
                pofsources: Vec::new(),
                servicekey: ServicekeyCfg {
                    currency: "USD".to_string(),
                    value: dec!(100),
                    duration: Duration::from_secs(600),
                },
                settlement: SettlementCfg {
                    fee_percent: dec!(5),
                    submission_window: Duration::from_secs(3600),
                },
                metadata: Some(Metadata {
                    name: Some("PLEASE CONFIGURE ME".to_string()),
                    operator: Some("TEST CONTRACT WITH DEFAULT CONFIG".to_string()),
                    ..Default::default()
                }),
            },
        }
    }
}

// fill out the derived fields
pub fn mkpublic(def: PubDefined, pk: VerifyingKey) -> Public {
    Public {
        defined: def.clone(),
        derived: PubDerived {
            pubkey: Base64(pk),
            public_key: Base64(pk),
            version: VERSION.clone(),
            enrollment: Default::default(),
            directory: Directory {
                endpoint: def.endpoint.clone(),
                public_key: Base64(pk),
            },
        },
    }
}
