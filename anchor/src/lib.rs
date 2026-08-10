//! Per-author anchor cells (issue #23): the routing layer that makes contract
//! address rotation soft. Each author owns one cell (frozen `cell-contract`
//! kernel, `purpose = "anchor"`) whose body maps role → the version and
//! address of their current contract for that role. The cell wasm never
//! changes, so the anchor address derived from a posting key is stable
//! forever — future schema rotations publish a new role entry instead of
//! stranding readers.
//!
//! This schema is CLIENT-SIDE ONLY, same doctrine as `freebird-control`: the
//! cell contract treats the body as opaque signed bytes, decoding tolerates
//! unknown fields, and anything undecodable means "no anchor" — readers fall
//! back to derived addresses, never surface an error.

use std::collections::BTreeMap;

use cell_contract::CellParametersV1;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The cell purpose naming the per-author anchor channel.
pub const ANCHOR_PURPOSE: &str = "anchor";

/// Role key for the author's reply inbox.
pub const ROLE_INBOX: &str = "inbox";

/// One role's routing entry: which schema version the author currently
/// publishes, and (optionally) the contract instance address, so readers can
/// GET it even without the wasm that derives it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RoleV1 {
    pub version: u32,
    #[serde(default)]
    pub address: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct AnchorV1 {
    /// Schema version; readers accept any `v >= 1` map with these fields.
    pub v: u32,
    #[serde(default)]
    pub roles: BTreeMap<String, RoleV1>,
}

impl AnchorV1 {
    pub fn new(roles: BTreeMap<String, RoleV1>) -> Self {
        Self { v: 1, roles }
    }

    /// Decode a cell body. None for anything unreadable: an old client facing
    /// a future incompatible schema must fail toward "no anchor", never
    /// toward an error the user sees.
    pub fn decode(body: &[u8]) -> Option<Self> {
        cell_contract::from_cbor(body).ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        cell_contract::to_cbor(self).expect("anchor record serializes")
    }

    pub fn role(&self, name: &str) -> Option<&RoleV1> {
        self.roles.get(name)
    }
}

/// Params of an author's anchor cell — with the frozen cell wasm these
/// derive the one address for that author that can never rotate.
pub fn anchor_params(owner: &VerifyingKey) -> CellParametersV1 {
    CellParametersV1 {
        owner: *owner,
        purpose: ANCHOR_PURPOSE.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn anchor() -> AnchorV1 {
        AnchorV1::new(
            [(
                ROLE_INBOX.to_string(),
                RoleV1 {
                    version: 2,
                    address: Some([7u8; 32]),
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    #[test]
    fn roundtrip() {
        let a = anchor();
        assert_eq!(AnchorV1::decode(&a.encode()), Some(a));
    }

    #[test]
    fn role_lookup() {
        let a = anchor();
        assert_eq!(a.role(ROLE_INBOX).map(|r| r.version), Some(2));
        assert!(a.role("feed").is_none());
    }

    #[test]
    fn unknown_fields_tolerated() {
        #[derive(Serialize)]
        struct Future {
            v: u32,
            roles: BTreeMap<String, RoleV1>,
            shiny_new_thing: String,
        }
        let f = Future {
            v: 2,
            roles: anchor().roles,
            shiny_new_thing: "ignored".into(),
        };
        let bytes = cell_contract::to_cbor(&f).unwrap();
        let decoded = AnchorV1::decode(&bytes).expect("decodes");
        assert_eq!(decoded.role(ROLE_INBOX).unwrap().version, 2);
    }

    #[test]
    fn missing_address_tolerated() {
        #[derive(Serialize)]
        struct BareRole {
            version: u32,
        }
        #[derive(Serialize)]
        struct Bare {
            v: u32,
            roles: BTreeMap<String, BareRole>,
        }
        let bytes = cell_contract::to_cbor(&Bare {
            v: 1,
            roles: [("inbox".to_string(), BareRole { version: 3 })]
                .into_iter()
                .collect(),
        })
        .unwrap();
        let decoded = AnchorV1::decode(&bytes).expect("decodes");
        assert_eq!(decoded.role(ROLE_INBOX).unwrap().address, None);
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(AnchorV1::decode(&[0xff, 0x00, 0x13, 0x37]), None);
        assert_eq!(AnchorV1::decode(b""), None);
    }

    #[test]
    fn anchor_params_purpose() {
        let sk = SigningKey::generate(&mut OsRng);
        let p = anchor_params(&sk.verifying_key());
        assert_eq!(p.purpose, ANCHOR_PURPOSE);
        assert_eq!(p.owner, sk.verifying_key());
    }
}
