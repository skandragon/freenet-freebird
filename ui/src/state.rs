//! Global UI state (Dioxus signals).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use freebird_core::feed::FeedStateV1;
use freebird_core::inbox::InboxStateV1;
use freenet_stdlib::client_api::WebApi;

#[derive(Clone, PartialEq, Debug, Default)]
pub enum SyncStatus {
    #[default]
    Connecting,
    Connected,
    Error(String),
}

pub static WEB_API: GlobalSignal<Option<WebApi>> = Signal::global(|| None);
pub static SYNC_STATUS: GlobalSignal<SyncStatus> = Signal::global(SyncStatus::default);

/// The local account's posting key (None until onboarded).
pub static ACCOUNT: GlobalSignal<Option<SigningKey>> = Signal::global(|| None);

/// Feed states by author key. `None` value = requested, not yet arrived.
pub static FEEDS: GlobalSignal<BTreeMap<[u8; 32], Option<FeedStateV1>>> =
    Signal::global(BTreeMap::new);

/// Inbox states by owner key.
pub static INBOXES: GlobalSignal<BTreeMap<[u8; 32], InboxStateV1>> =
    Signal::global(BTreeMap::new);

/// Result of asking the freebird delegate for `posting_key`:
/// None = not answered yet; Some(None) = no account stored (onboard);
/// Some(Some(seed)) = existing account.
pub static POSTING_KEY_LOADED: GlobalSignal<Option<Option<Vec<u8>>>> = Signal::global(|| None);

/// Latest ghostkey-delegate sign flow result:
/// Ok((scoped_payload, signature, certificate_pem)) or Err(user message).
pub static GHOSTKEY_SIGN_RESULT: GlobalSignal<Option<Result<(Vec<u8>, Vec<u8>, String), String>>> =
    Signal::global(|| None);
pub static GHOSTKEY_HAS_IDENTITY: GlobalSignal<Option<bool>> = Signal::global(|| None);

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum View {
    #[default]
    Home,
    Profile,
}

pub static VIEW: GlobalSignal<View> = Signal::global(View::default);

/// The Identity Vault's current delegate key, auto-discovered at startup
/// from the vault webapp's published `delegate-key.json` (never hardcoded —
/// freenet/ghostkeys#21). None until discovery completes; stays None if the
/// vault app isn't reachable on this node.
pub static GHOSTKEY_DELEGATE: GlobalSignal<Option<freenet_stdlib::prelude::DelegateKey>> =
    Signal::global(|| None);

pub fn own_author() -> Option<[u8; 32]> {
    ACCOUNT
        .read()
        .as_ref()
        .map(|sk| sk.verifying_key().to_bytes())
}
