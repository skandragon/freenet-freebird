//! The control channel: what Freebird publishes through its singleton cell
//! contract — currently the latest deployed build (drives the UI's update
//! banner) plus a feature-flag map for future rollouts.
//!
//! This schema is CLIENT-SIDE ONLY. The cell contract treats the body as
//! opaque signed bytes, so fields can be added here freely: decoding
//! tolerates unknown fields, and anything undecodable is treated as "no
//! control state" (no banner, all flags default). Contracts must never
//! depend on this crate.

use std::collections::BTreeMap;

use cell_contract::CellParametersV1;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The cell purpose naming the control channel.
pub const CONTROL_PURPOSE: &str = "control";

/// The publisher verifying key (hex) — the only key whose control records
/// clients accept. The secret half lives in ~/.freebird/publisher.key on the
/// publishing machine; minted 2026-08-10.
pub const PUBLISHER_VK_HEX: &str =
    "7fd93de864ba7940a06433143f4e1454092ca1226d5233305df499431a3181d2";

pub fn publisher_key() -> VerifyingKey {
    let bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(PUBLISHER_VK_HEX.as_bytes())
        .expect("compiled-in publisher key is hex")
        .try_into()
        .expect("publisher key is 32 bytes");
    VerifyingKey::from_bytes(&bytes).expect("compiled-in publisher key parses")
}

pub fn control_params() -> CellParametersV1 {
    CellParametersV1 {
        owner: publisher_key(),
        purpose: CONTROL_PURPOSE.into(),
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ControlV1 {
    /// Schema version; readers accept any `v >= 1` map with these fields.
    pub v: u32,
    /// Latest deployed build (git commit count) — the banner comparison key.
    pub build: u64,
    /// Human label for the build (git short hash).
    #[serde(default)]
    pub build_label: String,
    /// Feature flags; absent flag = client default.
    #[serde(default)]
    pub flags: BTreeMap<String, ciborium::Value>,
}

impl ControlV1 {
    pub fn new(build: u64, build_label: String) -> Self {
        Self {
            v: 1,
            build,
            build_label,
            flags: BTreeMap::new(),
        }
    }

    /// Decode a cell body. None for anything unreadable: an old client
    /// facing a future incompatible schema must fail toward "no control
    /// state", never toward an error the user sees.
    pub fn decode(body: &[u8]) -> Option<Self> {
        cell_contract::from_cbor(body).ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        cell_contract::to_cbor(self).expect("control record serializes")
    }

    pub fn flag_bool(&self, name: &str, default: bool) -> bool {
        match self.flags.get(name) {
            Some(ciborium::Value::Bool(b)) => *b,
            _ => default,
        }
    }
}

/// The update banner predicate: a strictly newer build than both what we run
/// and what the user already dismissed. Build 0 = "no git at compile time"
/// (dev build) — those never nag, and a published build of 0 is nonsense.
pub fn update_available(own_build: u64, published: Option<u64>, dismissed: u64) -> bool {
    match published {
        Some(p) => own_build > 0 && p > own_build && p > dismissed,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_key_parses() {
        let _ = publisher_key();
        let _ = control_params();
    }

    #[test]
    fn roundtrip() {
        let c = ControlV1::new(42, "abc1234".into());
        assert_eq!(ControlV1::decode(&c.encode()), Some(c));
    }

    #[test]
    fn unknown_fields_tolerated() {
        // A future publisher adds a field this build doesn't know about.
        #[derive(Serialize)]
        struct Future {
            v: u32,
            build: u64,
            build_label: String,
            flags: BTreeMap<String, ciborium::Value>,
            shiny_new_thing: String,
        }
        let f = Future {
            v: 2,
            build: 99,
            build_label: "zzz".into(),
            flags: BTreeMap::new(),
            shiny_new_thing: "ignored".into(),
        };
        let bytes = cell_contract::to_cbor(&f).unwrap();
        let decoded = ControlV1::decode(&bytes).expect("decodes");
        assert_eq!(decoded.build, 99);
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(ControlV1::decode(&[0xff, 0x00, 0x13, 0x37]), None);
        assert_eq!(ControlV1::decode(b""), None);
    }

    #[test]
    fn flag_bool_defaults() {
        let mut c = ControlV1::new(1, String::new());
        assert!(c.flag_bool("missing", true));
        assert!(!c.flag_bool("missing", false));
        c.flags
            .insert("dark_launch".into(), ciborium::Value::Bool(true));
        assert!(c.flag_bool("dark_launch", false));
        c.flags
            .insert("weird".into(), ciborium::Value::Text("yes".into()));
        assert!(!c.flag_bool("weird", false), "non-bool value = default");
    }

    #[test]
    fn banner_predicate_table() {
        // (own, published, dismissed) -> show
        let cases = [
            (10, Some(11), 0, true),   // newer build, never dismissed
            (10, Some(11), 11, false), // dismissed exactly this build
            (10, Some(12), 11, true),  // even newer than the dismissal
            (10, Some(10), 0, false),  // same build
            (10, Some(9), 0, false),   // older build
            (0, Some(11), 0, false),   // dev build: never nag
            (10, None, 0, false),      // no control state
        ];
        for (own, published, dismissed, want) in cases {
            assert_eq!(
                update_available(own, published, dismissed),
                want,
                "own={own} published={published:?} dismissed={dismissed}"
            );
        }
    }
}
