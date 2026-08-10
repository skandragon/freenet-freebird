//! Wire types between the Freebird UI and the freebird-delegate (a per-app
//! encrypted key-value store on the user's own node).
//!
//! Well-known keys the UI uses:
//! - `posting_key` — 32-byte Ed25519 seed for the account's posting key
//! - `draft` — in-progress compose text
//! - `follows_cache` — last-published follows set (UX cache; the network
//!   copy in the feed contract is authoritative)

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum FreebirdDelegateRequest {
    Store { key: String, value: Vec<u8> },
    Get { key: String },
    Delete { key: String },
    List,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum FreebirdDelegateResponse {
    Stored { key: String },
    Value { key: String, value: Option<Vec<u8>> },
    Deleted { key: String },
    KeyList { keys: Vec<String> },
    Error { message: String },
}
