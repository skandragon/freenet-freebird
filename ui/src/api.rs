#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code, unused_imports))]
//! Node connection + request plumbing + response dispatch.
//!
//! Slimmed from River's freenet_api layer: one WebSocket via
//! `freenet_stdlib::client_api::WebApi`, global Dioxus signals for state,
//! stateless response dispatch (responses are recognized by their content —
//! contract keys map to known feeds/inboxes, delegate responses by type).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use directory_contract::{AuthorizedListingV3, DirectoryStateV4};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freebird_core::delegate_api::{FreebirdDelegateRequest, FreebirdDelegateResponse};
use freebird_core::feed::legacy::LegacyFeedState;
use freebird_core::feed::{AttestationSlot, FeedParametersV1, FeedStateV1, FeedStateV1Delta, PostsV1};
use freebird_core::inbox::{InboxStateV1, InboxStateV1Delta};
use freebird_core::types::{AuthorizedFollows, AuthorizedProfile, FollowsV1, ProfileV1};
use inbox_contract::state::{InboxStateV3, InboxStateV3Delta};
use freenet_scaffold::ComposableState;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse, DelegateRequest, HostResponse};
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::WebApi;
use freenet_stdlib::prelude::*;

use crate::ghostkey::{GhostkeyRequest, GhostkeyResponse};
use crate::keys;
use crate::state::*;

#[cfg(target_arch = "wasm32")]
pub fn websocket_url() -> String {
    let win = web_sys::window().expect("window");
    let location = win.location();
    let proto = if location.protocol().unwrap_or_default() == "https:" {
        "wss"
    } else {
        "ws"
    };
    let host = location.host().unwrap_or_else(|_| "127.0.0.1:50509".into());
    let base = format!("{proto}://{host}/v1/contract/command?encodingProtocol=native");
    // Auth token arrives as ?authToken= on the page URL (node-served apps).
    let token = location
        .search()
        .ok()
        .and_then(|s| web_sys::UrlSearchParams::new_with_str(&s).ok())
        .and_then(|p| p.get("authToken"));
    match token {
        Some(t) => format!("{base}&authToken={t}"),
        None => base,
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn connect() -> Result<(), String> {
    use futures::channel::mpsc;
    use futures::StreamExt;

    let url = websocket_url();
    let ws = web_sys::WebSocket::new(&url).map_err(|e| format!("websocket open: {e:?}"))?;

    let (tx, mut rx) = mpsc::unbounded::<Result<HostResponse, String>>();
    let tx_err = tx.clone();
    let api = WebApi::start(
        ws,
        move |result| {
            let _ = tx.unbounded_send(result.map_err(|e| e.to_string()));
        },
        move |err| {
            let _ = tx_err.unbounded_send(Err(format!("connection error: {err}")));
        },
        || {
            *SYNC_STATUS.write() = SyncStatus::Connected;
        },
    );
    *WEB_API.write() = Some(api);

    // Response pump: runs for the life of the page.
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(msg) = rx.next().await {
            match msg {
                Ok(response) => dispatch(response),
                Err(e) => {
                    let connection_dead = e.contains("AUTH_TOKEN_INVALID")
                        || e.contains("WebSocket is not open")
                        || e.starts_with("connection error");
                    if connection_dead {
                        log(&format!("connection lost: {e}"));
                        *SYNC_STATUS.write() =
                            SyncStatus::Error("connection lost — reconnecting…".into());
                        schedule_reload();
                    } else if *SYNC_STATUS.read() != SyncStatus::Connected {
                        *SYNC_STATUS.write() = SyncStatus::Error(e);
                    } else {
                        // Request-level error (e.g. probing a delegate that
                        // isn't installed) — the connection is fine.
                        log(&format!("request error: {e}"));
                        note_feed_error(&e);
                    }
                }
            }
        }
    });
    Ok(())
}

/// Reload the page once, after a short delay — the simplest reliable
/// reconnect (fresh socket, fresh auth token, full resync). Guarded so a
/// burst of errors schedules only one.
#[cfg(target_arch = "wasm32")]
fn schedule_reload() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SCHEDULED: AtomicBool = AtomicBool::new(false);
    if SCHEDULED.swap(true, Ordering::SeqCst) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        crate::sleep_ms(5000).await;
        if let Some(win) = web_sys::window() {
            let _ = win.location().reload();
        }
    });
}

/// Does this request-level error name our own feed contract?
///
/// Errors carry no request id (the protocol has none), so the contract id in
/// the message is the only correlation available. Scoped to our own feed on
/// purpose: GETs for absent avatars, anchors and v1 contracts fail routinely
/// and are not user news, while a failed write to our feed is the one the UI
/// otherwise reports as a success (issue #79).
fn names_own_feed(error: &str, vk: &VerifyingKey) -> bool {
    error.contains(&keys::feed_instance_id(vk).encode())
}

fn note_feed_error(error: &str) {
    let Some(vk) = ACCOUNT.peek().as_ref().map(|sk| sk.verifying_key()) else {
        return;
    };
    if names_own_feed(error, &vk) {
        *FEED_WRITE_ERROR.write() = Some(error.to_string());
    }
}

pub async fn send(request: ClientRequest<'static>) -> Result<(), String> {
    let mut guard = WEB_API.write();
    let api = guard.as_mut().ok_or("not connected")?;
    api.send(request).await.map_err(|e| e.to_string())
}

// ---- contract operations ----

fn feed_container(author: &VerifyingKey) -> ContractContainer {
    let params = freebird_core::to_cbor(&keys::feed_params(author)).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::FEED_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

fn avatar_container(author: &VerifyingKey) -> ContractContainer {
    let params = freebird_core::to_cbor(&keys::avatar_params(author)).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::AVATAR_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

fn inbox_container(owner: &VerifyingKey) -> ContractContainer {
    let params = freebird_core::to_cbor(&keys::inbox_params(owner)).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::INBOX_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

fn directory_container() -> ContractContainer {
    let params = freebird_core::to_cbor(&keys::directory_params()).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::DIRECTORY_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

/// PUT our own feed + inbox (first run), subscribing to both.
pub async fn put_own_contracts(author: &VerifyingKey, feed: &FeedStateV1) -> Result<(), String> {
    put_own_feed(author, feed).await?;
    ensure_own_inbox(author).await
}

async fn put_own_feed(author: &VerifyingKey, feed: &FeedStateV1) -> Result<(), String> {
    let feed_state = freebird_core::to_cbor(feed)?;
    track(keys::feed_key(author), TrackedKind::Feed(author.to_bytes()));
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: feed_container(author),
        state: WrappedState::new(feed_state),
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// The state a feed is created with when we only know it must exist: signed
/// (there is no default — every component carries the author's signature) and
/// versioned BELOW anything real, so merging it over a live feed can never
/// roll a profile or follow list back to empty.
fn seed_feed(sk: &SigningKey) -> FeedStateV1 {
    FeedStateV1 {
        profile: AuthorizedProfile::new(
            ProfileV1 { name: String::new(), bio: String::new(), version: 0 },
            sk,
        ),
        follows: AuthorizedFollows::new(
            FollowsV1 { follows: Default::default(), version: 0 },
            sk,
        ),
        attestation: AttestationSlot(None),
        posts: PostsV1::default(),
    }
}

/// PUT our own feed with the seed state: creates it when the node has never
/// seen it, and the contract's merge turns a re-Put over a live feed into a
/// no-op — safe on every resume (issue #79).
///
/// Load-bearing after a feed rotation (#64, #67): the address every existing
/// author's feed lives at changed, so their v2 contract does not exist and
/// every `update_own_feed` — posting, following, and `migrate_v1`'s first
/// write — is an Update against nothing.
pub async fn ensure_own_feed(sk: &SigningKey) -> Result<(), String> {
    put_own_feed(&sk.verifying_key(), &seed_feed(sk)).await
}

/// PUT our v2 inbox with an empty state: creates it on first use, and the
/// contract's merge makes a re-Put over an existing inbox a no-op — safe to
/// call on every resume (the owner-republish half of the #23 migration).
pub async fn ensure_own_inbox(author: &VerifyingKey) -> Result<(), String> {
    let inbox_state = freebird_core::to_cbor(&InboxStateV3::default())?;
    track(keys::inbox_key(author), TrackedKind::Inbox(author.to_bytes()));
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: inbox_container(author),
        state: WrappedState::new(inbox_state),
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// Address generation per anchor role: which generation of that contract
/// this build derives, publishes, and reads. Hand-maintained — nothing ties
/// them to the vendored wasm, so a rotation must bump the matching constant
/// in the same change (see `own_anchor_is_not_a_rotation`, and
/// `golden_addresses_pinned` in keys.rs for the addresses themselves).
const INBOX_GENERATION: u32 = 2;
const FEED_GENERATION: u32 = 2;
const AVATAR_GENERATION: u32 = 1;

/// The anchor body this build publishes for `vk`: every role at the address
/// this same build derives. Split out from `publish_anchor` so the read half
/// can be tested against it — a role paired with the wrong derivation would
/// point every reader at a wrong address, the exact failure the anchor
/// exists to prevent.
fn own_anchor(vk: &VerifyingKey) -> freebird_anchor::AnchorV1 {
    let role = |version: u32, id: ContractInstanceId| freebird_anchor::RoleV1 {
        version,
        address: Some(id.as_bytes().try_into().expect("instance id is 32 bytes")),
    };
    freebird_anchor::AnchorV1::new(
        [
            (
                freebird_anchor::ROLE_INBOX.to_string(),
                role(INBOX_GENERATION, keys::inbox_instance_id(vk)),
            ),
            (
                freebird_anchor::ROLE_FEED.to_string(),
                role(FEED_GENERATION, keys::feed_instance_id(vk)),
            ),
            (
                freebird_anchor::ROLE_AVATAR.to_string(),
                role(AVATAR_GENERATION, keys::avatar_instance_id(vk)),
            ),
        ]
        .into_iter()
        .collect(),
    )
}

/// Publish (or refresh) our anchor cell: role → current contract version +
/// address, for the inbox, feed and avatar. Rides the FROZEN cell kernel, so
/// this address never rotates — future readers learn where our
/// current-generation contracts live even after their derived addresses
/// change again.
pub async fn publish_anchor(sk: &SigningKey) -> Result<(), String> {
    let vk = sk.verifying_key();
    let anchor = own_anchor(&vk);
    let cell = cell_contract::SignedCellV1::new(
        sk,
        freebird_anchor::ANCHOR_PURPOSE,
        keys::now_ms(),
        anchor.encode(),
    );
    let params = cell_contract::to_cbor(&keys::anchor_params(&vk))?;
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::CELL_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )));
    let state = cell_contract::to_cbor(&cell)?;
    track(keys::anchor_key(&vk), TrackedKind::Anchor(vk.to_bytes()));
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: container,
        state: WrappedState::new(state),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
}

/// GET + subscribe someone's feed, inbox, and anchor cell by author key.
/// During the dual-read window (`read_v1_inbox` flag, default on) the
/// legacy v1 inbox is fetched too, so pre-migration replies stay visible.
pub async fn fetch_feed(author: [u8; 32]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&author).map_err(|e| e.to_string())?;
    // Pending placeholder so effects don't re-spawn the fetch every render
    // until the response lands.
    FEEDS.write().entry(author).or_insert(None);
    track(keys::feed_key(&vk), TrackedKind::Feed(author));
    track(keys::inbox_key(&vk), TrackedKind::Inbox(author));
    track(keys::anchor_key(&vk), TrackedKind::Anchor(author));
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::feed_instance_id(&vk),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await?;
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::inbox_instance_id(&vk),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await?;
    ANCHORS.write().entry(author).or_insert(None);
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::anchor_instance_id(&vk),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await?;
    if flag_bool("read_v1_inbox", true) {
        track(keys::inbox_key_v1(&vk), TrackedKind::LegacyInbox(author));
        send(ClientRequest::ContractOp(ContractRequest::Get {
            key: keys::inbox_instance_id_v1(&vk),
            return_contract_code: false,
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await?;
    }
    if flag_bool("read_v1_feed", true) {
        LEGACY_FEEDS.write().entry(author).or_insert(None);
        track(keys::feed_key_v1(&vk), TrackedKind::LegacyFeed(author));
        send(ClientRequest::ContractOp(ContractRequest::Get {
            key: keys::feed_instance_id_v1(&vk),
            return_contract_code: false,
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await?;
    }
    Ok(())
}

/// GET someone's avatar. Write-rarely contract: no subscription, session
/// cache in AVATARS (issue #10).
pub async fn fetch_avatar(author: [u8; 32]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&author).map_err(|e| e.to_string())?;
    AVATARS.write().entry(author).or_insert(None);
    track(keys::avatar_key(&vk), TrackedKind::Avatar(author));
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::avatar_instance_id(&vk),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
}

/// PUT our own avatar; Put creates the contract on first upload and the
/// contract's LWW merge handles every later one.
pub async fn put_own_avatar(
    author: &VerifyingKey,
    avatar: &freebird_core::avatar::AuthorizedAvatar,
) -> Result<(), String> {
    let state = freebird_core::to_cbor(avatar)?;
    track(keys::avatar_key(author), TrackedKind::Avatar(author.to_bytes()));
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: avatar_container(author),
        state: WrappedState::new(state),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
}

pub async fn update_own_feed(delta: FeedStateV1Delta) -> Result<(), String> {
    let author = own_author().ok_or("no account")?;
    let vk = VerifyingKey::from_bytes(&author).map_err(|e| e.to_string())?;
    let bytes = freebird_core::to_cbor(&delta)?;
    send(ClientRequest::ContractOp(ContractRequest::Update {
        key: keys::feed_key(&vk),
        data: UpdateData::Delta(StateDelta::from(bytes)),
    }))
    .await
}

/// Send a reply pointer into the TARGET author's inbox.
///
/// Put, not Update: during the migration window the target's v2 inbox only
/// exists once its OWNER has resumed on a new build — an Update to a
/// nonexistent contract fails asynchronously (console-only) and the reply
/// would silently vanish behind a success message. Put creates the inbox on
/// first write (same pattern as the directory and avatars), and the
/// contract's merge turns a Put over an existing inbox into a plain apply.
pub async fn update_inbox(target_author: [u8; 32], delta: InboxStateV3Delta) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&target_author).map_err(|e| e.to_string())?;
    // Materialize the delta as a self-contained state (cred + pointer): the
    // same verification the contract runs, so a bad delta fails HERE with a
    // real message instead of as a rejected update.
    let mut state = InboxStateV3::default();
    let clone = state.clone();
    state
        .apply_delta(&clone, &keys::inbox_params(&vk), &Some(delta))
        .map_err(|e| format!("inbox pointer rejected locally: {e}"))?;
    let bytes = freebird_core::to_cbor(&state)?;
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: inbox_container(&vk),
        state: WrappedState::new(bytes),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
}

/// GET + subscribe the well-known public directory (issue #11), plus the
/// legacy v1 directory during the dual-read window (`read_v1_directory`).
pub async fn fetch_directory() -> Result<(), String> {
    track(keys::directory_key(), TrackedKind::Directory);
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::directory_instance_id(),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await?;
    if flag_bool("read_v1_directory", true) {
        track(keys::directory_key_v1(), TrackedKind::LegacyDirectory);
        send(ClientRequest::ContractOp(ContractRequest::Get {
            key: keys::directory_instance_id_v1(),
            return_contract_code: false,
            subscribe: true,
            blocking_subscribe: false,
        }))
        .await?;
    }
    Ok(())
}

/// GET + subscribe the publisher's control cell (update banner + flags).
pub async fn fetch_control() -> Result<(), String> {
    track(keys::control_cell_key(), TrackedKind::Control);
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::control_cell_instance_id(),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// GET + subscribe the publisher's PoW difficulty cell (issue #66).
pub async fn fetch_pow_difficulty() -> Result<(), String> {
    track(keys::pow_cell_key(), TrackedKind::Pow);
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::pow_cell_instance_id(),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// PUT our directory listing. Put creates the directory on the very first
/// listing network-wide and the contract's per-author LWW merge handles
/// every later one (same pattern as avatars).
pub async fn put_directory_listing(
    listing: &AuthorizedListingV3,
    pow_difficulty: Option<cell_contract::SignedCellV1>,
) -> Result<(), String> {
    let mut state = DirectoryStateV4 {
        // Carry the difficulty record so this PUT latches the raise into the
        // directory rather than merging in a state that has forgotten it
        // (issue #66). The merge is monotone, so an older record is a no-op.
        pow_difficulty,
        ..DirectoryStateV4::default()
    };
    let tier = if listing.is_anon() {
        &mut state.anon
    } else {
        &mut state.attested
    };
    tier.insert(listing.listing.author, listing.clone());
    let bytes = freebird_core::to_cbor(&state)?;
    track(keys::directory_key(), TrackedKind::Directory);
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: directory_container(),
        state: WrappedState::new(bytes),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
}

// ---- delegate operations ----

fn freebird_delegate_container() -> DelegateContainer {
    let code = DelegateCode::from(keys::FREEBIRD_DELEGATE_WASM.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    let delegate = Delegate::from((&code, &params));
    DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate))
}

pub fn freebird_delegate_key() -> DelegateKey {
    delegate_key_for(keys::FREEBIRD_DELEGATE_WASM)
}

fn delegate_key_for(wasm: &[u8]) -> DelegateKey {
    let code = DelegateCode::from(wasm.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    DelegateKey::from_params(code.hash_str(), &params).expect("delegate key")
}

/// Previously-shipped delegate generations whose key differs from the
/// current build's — the ones the carry-forward probe (issue #53) reads
/// stored secrets out of. Empty while the delegate hasn't rotated.
pub fn legacy_delegates() -> Vec<(&'static [u8], DelegateKey)> {
    legacy_delegates_from(keys::LEGACY_DELEGATE_WASMS)
}

fn legacy_delegates_from(registry: &[&'static [u8]]) -> Vec<(&'static [u8], DelegateKey)> {
    let current = freebird_delegate_key();
    registry
        .iter()
        .map(|w| (*w, delegate_key_for(w)))
        .filter(|(_, k)| *k != current)
        .collect()
}

/// Stable-but-local cipher material, same rationale as River (river#397):
/// re-registrations must reuse identical material or the node re-keys the
/// delegate's secret store.
#[cfg(target_arch = "wasm32")]
fn delegate_cipher_material() -> ([u8; 32], [u8; 24]) {
    const CIPHER_KEY: &str = "freebird_delegate_cipher_v1";
    const NONCE_KEY: &str = "freebird_delegate_nonce_v1";
    let storage = web_sys::window().and_then(|w| w.local_storage().ok().flatten());
    if let Some(s) = &storage {
        if let (Ok(Some(c)), Ok(Some(n))) = (s.get_item(CIPHER_KEY), s.get_item(NONCE_KEY)) {
            if let (Ok(c), Ok(n)) = (bs58::decode(c).into_vec(), bs58::decode(n).into_vec()) {
                if c.len() == 32 && n.len() == 24 {
                    return (c.try_into().unwrap(), n.try_into().unwrap());
                }
            }
        }
    }
    use rand::RngCore;
    let mut cipher = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut cipher);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    if let Some(s) = &storage {
        let _ = s.set_item(CIPHER_KEY, &bs58::encode(cipher).into_string());
        let _ = s.set_item(NONCE_KEY, &bs58::encode(nonce).into_string());
    }
    (cipher, nonce)
}

#[cfg(target_arch = "wasm32")]
pub async fn register_freebird_delegate() -> Result<(), String> {
    let (cipher, nonce) = delegate_cipher_material();
    send(ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
        delegate: freebird_delegate_container(),
        cipher,
        nonce,
    }))
    .await
}

pub async fn kv_request(request: FreebirdDelegateRequest) -> Result<(), String> {
    kv_request_to(freebird_delegate_key(), request).await
}

/// Same KV request aimed at a specific delegate generation (the current one
/// for normal traffic, an old one during the carry-forward probe).
pub async fn kv_request_to(
    key: DelegateKey,
    request: FreebirdDelegateRequest,
) -> Result<(), String> {
    let payload = freebird_core::to_cbor(&request)?;
    send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
        key,
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(payload),
        )],
    }))
    .await
}

// ---- carry-forward probe (issue #53) ----
//
// When the current delegate has no stored seed, each OLD delegate
// generation is registered (same cipher material) and asked to `List` its
// secrets; the responses fold every stored value forward via
// `dispatch_legacy_kv`. No-op while the delegate has never rotated.

/// The probe already ran (or was suppressed) this page load.
static PROBE_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Delegate answers the probe still owes: one KeyList per generation, then
/// one Value per listed key. Drives LEGACY_PROBE_PENDING to false the moment
/// the last answer lands (the run's sleep is only a fallback ceiling).
static PROBE_OUTSTANDING: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);
/// Legitimate empty legacy responses left: each RegisterDelegate sent to a
/// legacy generation is acked with one empty response. Any empty beyond the
/// budget means the node swallowed a probe error.
// ponytail: one global budget, not a per-key ledger — the registry will only
// ever hold a couple of generations; go per-key if that stops being true.
static LEGACY_ACK_BUDGET: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

/// Never probe (again) this page load — called by nuke_account so a
/// deliberately destroyed seed can't be resurrected from an old generation.
pub fn suppress_legacy_probe() {
    PROBE_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Synchronous half of the probe: claims the once-per-load slot and raises
/// the account gate BEFORE the caller yields, so no render can show
/// onboarding while a seed may still turn up. Returns whether the caller
/// should spawn `run_legacy_probe`.
pub fn begin_legacy_probe() -> bool {
    if PROBE_DONE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    let legacy = legacy_delegates();
    if legacy.is_empty() {
        return false;
    }
    PROBE_OUTSTANDING.store(legacy.len() as isize, std::sync::atomic::Ordering::SeqCst);
    *LEGACY_PROBE_PENDING.write() = true;
    true
}

/// Note `delta` probe answers (negative = one arrived); the gate drops when
/// none are left.
fn probe_note(delta: isize) {
    let left = PROBE_OUTSTANDING.fetch_add(delta, std::sync::atomic::Ordering::SeqCst) + delta;
    if left <= 0 && *LEGACY_PROBE_PENDING.peek() {
        *LEGACY_PROBE_PENDING.write() = false;
    }
}

/// Register an old delegate generation (same cipher material as the current
/// one) so the node can run it even after a restart — messages to an
/// unregistered delegate are silently dropped.
#[cfg(target_arch = "wasm32")]
pub async fn register_legacy(wasm: &[u8]) -> Result<(), String> {
    let (cipher, nonce) = delegate_cipher_material();
    let code = DelegateCode::from(wasm.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    let delegate = Delegate::from((&code, &params));
    LEGACY_ACK_BUDGET.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    send(ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
        delegate: DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate)),
        cipher,
        nonce,
    }))
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn run_legacy_probe() {
    for (wasm, key) in legacy_delegates() {
        let sent = async {
            register_legacy(wasm).await?;
            kv_request_to(key, FreebirdDelegateRequest::List).await
        }
        .await;
        if let Err(e) = sent {
            log(&format!("legacy delegate probe failed: {e}"));
            *LEGACY_PROBE_FAILED.write() = true;
            probe_note(-1);
        }
    }
    // Fallback ceiling: answers are node-local, so anything still
    // outstanding after this long was lost or swallowed — surface it instead
    // of letting onboarding pose as "no account".
    crate::sleep_ms(5000).await;
    if *LEGACY_PROBE_PENDING.peek() {
        log("legacy probe timed out with answers outstanding");
        *LEGACY_PROBE_FAILED.write() = true;
        *LEGACY_PROBE_PENDING.write() = false;
    }
}

/// Delete the posting-key seed from every OLD delegate generation (register
/// first — see `register_legacy`). Any failure fails the caller: a nuke that
/// leaves the seed in an old generation isn't a nuke.
#[cfg(target_arch = "wasm32")]
pub async fn wipe_legacy_seeds() -> Result<(), String> {
    for (wasm, key) in legacy_delegates() {
        register_legacy(wasm).await?;
        kv_request_to(
            key,
            FreebirdDelegateRequest::Delete {
                key: "posting_key".into(),
            },
        )
        .await?;
    }
    Ok(())
}

/// Ask the ghostkey delegate (auto-discovered from the vault) to sign our
/// attestation payload. Response arrives via dispatch.
pub async fn ghostkey_request(request: GhostkeyRequest) -> Result<(), String> {
    let key = GHOSTKEY_DELEGATE
        .read()
        .clone()
        .ok_or("Identity Vault not discovered on this node yet")?;
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&request, &mut payload).map_err(|e| e.to_string())?;
    send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
        key,
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(payload),
        )],
    }))
    .await
}

// ---- response dispatch ----

fn dispatch(response: HostResponse) {
    log(&format!("host response: {}", response_name(&response)));
    match response {
        HostResponse::ContractResponse(cr) => dispatch_contract(cr),
        HostResponse::DelegateResponse { key, values } => {
            let is_freebird = key == freebird_delegate_key();
            let is_legacy =
                !is_freebird && legacy_delegates().iter().any(|(_, k)| *k == key);
            if values.is_empty() {
                if is_legacy {
                    note_empty_legacy_response();
                } else {
                    note_empty_delegate_response(is_freebird);
                }
            }
            for out in values {
                if let OutboundDelegateMsg::ApplicationMessage(app_msg) = out {
                    if is_freebird {
                        dispatch_kv(app_msg.payload.as_ref());
                    } else if is_legacy {
                        dispatch_legacy_kv(&key, app_msg.payload.as_ref());
                    } else {
                        dispatch_ghostkey(app_msg.payload.as_ref());
                    }
                }
            }
        }
        HostResponse::Ok => {}
        _ => {}
    }
}

/// An empty delegate response is the node's tell for a swallowed delegate
/// error: when execution fails (e.g. "missing message origin" on an
/// unattested connection) the node logs node-side and answers with an EMPTY
/// message list instead of an error, so the real answer never comes.
///
/// For the freebird delegate exactly one empty response is legitimate — the
/// RegisterDelegate ack — so only a SECOND one proves errors are being
/// swallowed. The ghostkey delegate is never registered by us, so for it any
/// empty response is an error; surfacing it through GHOSTKEY_SIGN_RESULT
/// both explains the situation in the Verification card and unsticks a
/// pending "Waiting for Identity Vault…" flow.
/// Empty responses from a LEGACY generation: one per RegisterDelegate we
/// sent is its ack; any beyond that budget is the node's swallowed-error
/// tell (same failure `note_empty_delegate_response` catches for the current
/// delegate) — the owed answer will never arrive, so count it and flag the
/// probe as failed rather than letting onboarding pose as "no account".
fn note_empty_legacy_response() {
    if LEGACY_ACK_BUDGET.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) > 0 {
        return;
    }
    log("legacy delegate: empty response beyond its register ack — node swallowed a probe error");
    *LEGACY_PROBE_FAILED.write() = true;
    probe_note(-1);
}

fn note_empty_delegate_response(is_freebird: bool) {
    use std::sync::atomic::{AtomicU32, Ordering};
    if is_freebird {
        static EMPTY_FREEBIRD: AtomicU32 = AtomicU32::new(0);
        let seen = EMPTY_FREEBIRD.fetch_add(1, Ordering::SeqCst) + 1;
        if seen >= 2 && POSTING_KEY_LOADED.peek().is_none() {
            log("empty freebird delegate response beyond the register ack — node is swallowing delegate errors");
            *KEY_STORE_UNREACHABLE.write() = true;
        }
    } else {
        *GHOSTKEY_SIGN_RESULT.write() = Some(Err(
            "The Identity Vault on this node didn't answer (the node reported \
             an empty response). Verification is optional — everything else \
             keeps working. Reloading the page may fix it."
                .into(),
        ));
    }
}

fn response_name(r: &HostResponse) -> String {
    match r {
        HostResponse::ContractResponse(c) => format!("Contract::{c:?}").chars().take(120).collect(),
        HostResponse::DelegateResponse { key, values } => {
            format!("Delegate(key={key}, {} values)", values.len())
        }
        HostResponse::Ok => "Ok".into(),
        other => format!("{other:?}").chars().take(120).collect(),
    }
}

fn dispatch_contract(response: ContractResponse) {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            apply_contract_bytes(&key, state.as_ref(), true);
        }
        ContractResponse::UpdateNotification { key, update } => match update {
            UpdateData::State(s) => apply_contract_bytes(&key, s.as_ref(), true),
            UpdateData::Delta(d) => apply_contract_bytes(&key, d.as_ref(), false),
            UpdateData::StateAndDelta { state, .. } => {
                apply_contract_bytes(&key, state.as_ref(), true)
            }
            _ => {}
        },
        ContractResponse::PutResponse { .. } | ContractResponse::UpdateResponse { .. } => {}
        ContractResponse::SubscribeResponse { .. } => {}
        _ => {}
    }
}

/// Where an author's anchor says to read each role, when that differs from
/// the address we derive from bundled wasm — the read half of the anchor
/// (issue #54). Returns `(role, address, kind, subscribe)`.
///
/// A role is skipped when it names a generation other than the one this
/// build derives: the addresses of older generations are reached through
/// the dual-read flags instead, and a newer one is a schema we have no
/// decoder for. Either way the derived address still holds what we can
/// read, which is the fail-soft the anchor doctrine asks for.
///
/// `tracked` is the registry as it stands. An address already in it is
/// never re-tagged — see the rejection below.
fn anchor_targets(
    author: [u8; 32],
    vk: &VerifyingKey,
    anchor: &freebird_anchor::AnchorV1,
    tracked: &BTreeMap<String, TrackedKind>,
) -> Vec<(&'static str, ContractInstanceId, TrackedKind, bool)> {
    let roles = [
        (
            freebird_anchor::ROLE_INBOX,
            INBOX_GENERATION,
            keys::inbox_instance_id(vk),
            TrackedKind::Inbox(author),
            true,
        ),
        (
            freebird_anchor::ROLE_FEED,
            FEED_GENERATION,
            keys::feed_instance_id(vk),
            TrackedKind::Feed(author),
            true,
        ),
        (
            freebird_anchor::ROLE_AVATAR,
            AVATAR_GENERATION,
            keys::avatar_instance_id(vk),
            // Write-rarely, same as fetch_avatar: no subscription.
            TrackedKind::Avatar(author),
            false,
        ),
    ];
    let mut targets = Vec::new();
    for (role, generation, derived, kind, subscribe) in roles {
        let Some(entry) = anchor.role(role) else { continue };
        let Some(address) = entry.address else { continue };
        let address = ContractInstanceId::new(address);
        if entry.version != generation {
            log(&format!(
                "anchor: {role} is generation {}, this build derives {generation} — \
                 staying on the derived address",
                entry.version
            ));
            continue;
        }
        if address == derived {
            continue;
        }
        // The address in an anchor is chosen by its author, and nothing ties
        // it to that author: it can name anyone's contract, or the
        // directory. Re-tagging an address we already track would send that
        // contract's updates into the wrong decoder, where they are rejected
        // as malformed — reader-side denial of service for everyone who
        // views the profile. First claim wins; a claim already equal to
        // `kind` is this same rotation, already followed.
        if let Some(held) = tracked.get(&address.to_string()) {
            if *held != kind {
                log(&format!(
                    "anchor: {role} names {address}, already tracked as {held:?} — ignored"
                ));
            }
            continue;
        }
        targets.push((role, address, kind, subscribe));
    }
    targets
}

/// Act on `anchor_targets`: add the rotated address to the tracked registry
/// alongside the derived one (so its state dispatches into this author's
/// existing slot) and fetch it. Without this a rotation strands every reader
/// on the derived address, as if the anchor did not exist.
///
/// Additive on purpose: the derived address stays tracked and subscribed, so
/// a reader that followed a rotation still sees whatever remains at the old
/// address. Both merge into the one per-author slot.
fn follow_anchor(author: [u8; 32], vk: &VerifyingKey, anchor: &freebird_anchor::AnchorV1) {
    // The registry snapshot is taken (and dropped) before any `track_id`
    // write below.
    let targets = anchor_targets(author, vk, anchor, &TRACKED.peek());
    for (role, address, kind, subscribe) in targets {
        log(&format!("anchor: following rotated {role} at {address}"));
        track_id(address, kind);
        spawn_local_task(async move {
            if let Err(e) = send(ClientRequest::ContractOp(ContractRequest::Get {
                key: address,
                return_contract_code: false,
                subscribe,
                blocking_subscribe: false,
            }))
            .await
            {
                log(&format!("anchor {role} fetch failed: {e}"));
            }
        });
    }
}

/// Apply full state or delta bytes for a tracked contract.
fn apply_contract_bytes(key: &ContractKey, bytes: &[u8], is_full_state: bool) {
    if bytes.is_empty() {
        return;
    }
    let Some(kind) = lookup(key) else { return };
    match kind {
        TrackedKind::Feed(author) => {
            let Ok(vk) = VerifyingKey::from_bytes(&author) else { return };
            let params = keys::feed_params(&vk);
            let mut feeds = FEEDS.write();
            let entry = feeds.entry(author).or_insert_with(empty_feed_placeholder);
            if is_full_state {
                match freebird_core::from_cbor::<FeedStateV1>(bytes) {
                    Ok(incoming) => merge_feed(entry, &incoming, &params),
                    Err(e) => log(&format!("bad feed state for {key}: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<FeedStateV1Delta>(bytes) {
                    Ok(delta) => {
                        if let Some(state) = entry {
                            let clone = state.clone();
                            if let Err(e) = state.apply_delta(&clone, &params, &Some(delta)) {
                                log(&format!("feed delta rejected: {e}"));
                            }
                        }
                    }
                    Err(e) => log(&format!("bad feed delta: {e}")),
                }
            }
        }
        TrackedKind::Avatar(author) => {
            let Ok(vk) = VerifyingKey::from_bytes(&author) else { return };
            // State and delta are both one full signed avatar; the blob is
            // untrusted input — full check before it ever reaches an <img>.
            match freebird_core::from_cbor::<freebird_core::avatar::AuthorizedAvatar>(bytes) {
                Ok(incoming) => {
                    if let Err(e) = freebird_core::avatar::check_avatar(&incoming, &vk) {
                        log(&format!("rejected invalid avatar for {key}: {e}"));
                        return;
                    }
                    let mut avatars = AVATARS.write();
                    let entry = avatars.entry(author).or_insert(None);
                    let newer = entry.as_ref().is_none_or(|held| {
                        freebird_core::avatar::order_key(&incoming)
                            > freebird_core::avatar::order_key(held)
                    });
                    if newer {
                        *entry = Some(incoming);
                    }
                }
                Err(e) => log(&format!("bad avatar state: {e}")),
            }
        }
        TrackedKind::Directory => {
            let params = keys::directory_params();
            let mut dir = DIRECTORY.write();
            let entry = dir.get_or_insert_with(DirectoryStateV4::default);
            if is_full_state {
                match freebird_core::from_cbor::<DirectoryStateV4>(bytes) {
                    Ok(incoming) => {
                        if let Err(e) = entry.merge(&params, &incoming) {
                            log(&format!("directory merge rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad directory state: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<directory_contract::DirectoryDeltaV3>(bytes) {
                    Ok(delta) => {
                        if let Err(e) = entry.apply_delta(&params, &delta) {
                            log(&format!("directory delta rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad directory delta: {e}")),
                }
            }
        }
        TrackedKind::LegacyDirectory => {
            // Read-only remnant of the v1 directory: the deployed v1 wasm
            // still enforces its own invariants network-side, but each
            // listing is re-checked here (mandatory attestation) before the
            // Discover tab trusts it. Per-author LWW keeps the newest.
            use directory_contract::legacy::{LegacyAuthorizedListing, LegacyDirectoryState};
            let master = keys::master_key();
            let merge_listings = |incoming: Vec<LegacyAuthorizedListing>| {
                let mut dir = LEGACY_DIRECTORY.write();
                let entry = dir.get_or_insert_with(LegacyDirectoryState::default);
                for l in incoming {
                    if l.check(&master).is_err() {
                        log("rejected invalid legacy directory listing");
                        continue;
                    }
                    let newer = entry
                        .listings
                        .get(&l.listing.author)
                        .is_none_or(|held| held.listing.last_active < l.listing.last_active);
                    if newer {
                        entry.listings.insert(l.listing.author, l);
                    }
                }
            };
            if is_full_state {
                match freebird_core::from_cbor::<LegacyDirectoryState>(bytes) {
                    Ok(incoming) => merge_listings(incoming.listings.into_values().collect()),
                    Err(e) => log(&format!("bad legacy directory state: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<directory_contract::legacy::LegacyDirectoryDelta>(
                    bytes,
                ) {
                    Ok(delta) => merge_listings(delta),
                    Err(e) => log(&format!("bad legacy directory delta: {e}")),
                }
            }
        }
        TrackedKind::Anchor(author) => {
            // State and delta are both one full signed cell (same shape as
            // the control cell). Re-verify against the author's key + the
            // "anchor" purpose before decoding.
            let Ok(vk) = VerifyingKey::from_bytes(&author) else {
                // TRACKED is self-populated, so this "cannot happen" — but a
                // silent return would make the broken invariant undiagnosable.
                log("anchor dispatch: tracked author key is not a valid key");
                return;
            };
            match cell_contract::from_cbor::<cell_contract::SignedCellV1>(bytes) {
                Ok(cell) => {
                    if let Err(e) = cell.check(&keys::anchor_params(&vk)) {
                        log(&format!("rejected invalid anchor cell: {e}"));
                        return;
                    }
                    // LWW by the cell's order key: Get responses and update
                    // notifications can arrive out of order.
                    let newer = ANCHOR_ORDER
                        .read()
                        .get(&author)
                        .is_none_or(|held| cell.order_key() > *held);
                    if !newer {
                        return;
                    }
                    match freebird_anchor::AnchorV1::decode(&cell.body) {
                        Some(anchor) => {
                            ANCHOR_ORDER.write().insert(author, cell.order_key());
                            follow_anchor(author, &vk, &anchor);
                            ANCHORS.write().insert(author, Some(anchor));
                        }
                        // A future schema this build can't read: stay quiet.
                        None => log("anchor cell body undecodable (newer schema?)"),
                    }
                }
                Err(e) => log(&format!("bad anchor cell state: {e}")),
            }
        }
        TrackedKind::Control => {
            // State and delta are both one full signed cell. Client-side
            // re-verification is cheap and keeps a misbehaving peer from
            // feeding us an unsigned record.
            match cell_contract::from_cbor::<cell_contract::SignedCellV1>(bytes) {
                Ok(cell) => {
                    if let Err(e) = cell.check(&freebird_control::control_params()) {
                        log(&format!("rejected invalid control cell: {e}"));
                        return;
                    }
                    match freebird_control::ControlV1::decode(&cell.body) {
                        Some(control) => {
                            let newer = CONTROL
                                .read()
                                .as_ref()
                                .is_none_or(|held| control.build > held.build);
                            if newer {
                                *CONTROL.write() = Some(control);
                            }
                        }
                        // A future schema this build can't read: stay quiet.
                        None => log("control cell body undecodable (newer schema?)"),
                    }
                }
                Err(e) => log(&format!("bad control cell state: {e}")),
            }
        }
        TrackedKind::Pow => {
            // State and delta are both one full signed cell. `adopt_difficulty`
            // is the SAME rule the contracts apply (publisher signature +
            // strictly increasing seq), so the client can never end up solving
            // against a record a contract would refuse to latch.
            match cell_contract::from_cbor::<cell_contract::SignedCellV1>(bytes) {
                Ok(cell) => {
                    if let Err(e) = cell.check(&freebird_pow::pow_params()) {
                        log(&format!("rejected invalid PoW difficulty cell: {e}"));
                        return;
                    }
                    // A re-delivery of one we already hold is normal (a
                    // subscription resends on reconnect) — silently a no-op.
                    freebird_pow::adopt_difficulty(&mut POW_DIFFICULTY.write(), Some(&cell));
                }
                Err(e) => log(&format!("bad PoW difficulty cell state: {e}")),
            }
        }
        TrackedKind::Inbox(author) => {
            let Ok(vk) = VerifyingKey::from_bytes(&author) else { return };
            let params = keys::inbox_params(&vk);
            let mut inboxes = INBOXES.write();
            let entry = inboxes.entry(author).or_default();
            if is_full_state {
                match freebird_core::from_cbor::<InboxStateV3>(bytes) {
                    Ok(incoming) => {
                        let clone = entry.clone();
                        if let Err(e) = entry.merge(&clone, &params, &incoming) {
                            log(&format!("inbox merge rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad inbox state: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<InboxStateV3Delta>(bytes) {
                    Ok(delta) => {
                        let clone = entry.clone();
                        if let Err(e) = entry.apply_delta(&clone, &params, &Some(delta)) {
                            log(&format!("inbox delta rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad inbox delta: {e}")),
                }
            }
        }
        TrackedKind::LegacyInbox(author) => {
            // Read-only remnant of the v1 inbox (dual-read window): decoded
            // with the FROZEN freebird-core v1 types, merged with the same
            // v1 merge logic the deployed contract runs.
            let Ok(vk) = VerifyingKey::from_bytes(&author) else {
                log("legacy inbox dispatch: tracked author key is not a valid key");
                return;
            };
            let params = keys::inbox_params_v1(&vk);
            let mut inboxes = LEGACY_INBOXES.write();
            let entry = inboxes.entry(author).or_default();
            if is_full_state {
                match freebird_core::from_cbor::<InboxStateV1>(bytes) {
                    Ok(incoming) => {
                        let clone = entry.clone();
                        if let Err(e) = entry.merge(&clone, &params, &incoming) {
                            log(&format!("legacy inbox merge rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad legacy inbox state: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<InboxStateV1Delta>(bytes) {
                    Ok(delta) => {
                        let clone = entry.clone();
                        if let Err(e) = entry.apply_delta(&clone, &params, &Some(delta)) {
                            log(&format!("legacy inbox delta rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad legacy inbox delta: {e}")),
                }
            }
        }
        TrackedKind::LegacyFeed(author) => {
            // Read-only remnant of the pre-#64 feed (dual-read window): decode
            // with the FROZEN legacy type and verify under the OLD rules
            // (bare-CBOR signatures, AttestationV1). Full state only — the old
            // contract is dead, so no new deltas arrive; a delta would need the
            // old delta type and there is nothing to apply it to anyway.
            let Ok(vk) = VerifyingKey::from_bytes(&author) else {
                log("legacy feed dispatch: tracked author key is not a valid key");
                return;
            };
            if !is_full_state {
                log("ignoring legacy feed delta (dead contract, display-only)");
                return;
            }
            match freebird_core::from_cbor::<LegacyFeedState>(bytes) {
                Ok(incoming) => {
                    if let Err(e) = incoming.verify(&vk, &keys::master_key()) {
                        log(&format!("rejected invalid legacy feed for {key}: {e}"));
                        return;
                    }
                    LEGACY_FEEDS.write().insert(author, Some(incoming));
                }
                Err(e) => log(&format!("bad legacy feed state for {key}: {e}")),
            }
        }
    }
}

/// A feed entry before its first full state arrives.
fn empty_feed_placeholder() -> Option<FeedStateV1> {
    None
}

fn merge_feed(entry: &mut Option<FeedStateV1>, incoming: &FeedStateV1, params: &FeedParametersV1) {
    match entry {
        None => {
            // First copy: verify before trusting.
            if let Err(e) = incoming.verify(incoming, params) {
                log(&format!("rejected invalid feed state: {e}"));
                return;
            }
            *entry = Some(incoming.clone());
        }
        Some(current) => {
            let clone = current.clone();
            if let Err(e) = current.merge(&clone, params, incoming) {
                log(&format!("feed merge rejected: {e}"));
            }
        }
    }
}

fn dispatch_kv(payload: &[u8]) {
    match freebird_core::from_cbor::<FreebirdDelegateResponse>(payload) {
        Ok(FreebirdDelegateResponse::Value { key, value }) => {
            if key == "posting_key" {
                *POSTING_KEY_LOADED.write() = Some(value);
            } else if key == "theme" {
                if let Some(label) = value.as_deref().and_then(|v| std::str::from_utf8(v).ok()) {
                    crate::state::apply_theme(crate::state::Theme::from_label(label));
                }
            } else if key == "public_listing" {
                *PUBLIC_LISTING.write() = Some(value.as_deref() == Some(b"on".as_ref()));
            } else if key == "dismissed_build" {
                // Decimal string; absent/garbled = never dismissed.
                let build = value
                    .as_deref()
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                *DISMISSED_BUILD.write() = Some(build);
            } else if key == V1_MIGRATION_KEY {
                *V1_MIGRATION.write() = Some(V1Migration::decode(value.as_deref()));
            }
        }
        Ok(FreebirdDelegateResponse::Stored { .. })
        | Ok(FreebirdDelegateResponse::Deleted { .. })
        | Ok(FreebirdDelegateResponse::KeyList { .. }) => {}
        Ok(FreebirdDelegateResponse::Error { message }) => {
            log(&format!("delegate error: {message}"));
        }
        Err(e) => log(&format!("bad delegate response: {e}")),
    }
}

/// Fold an OLD delegate generation's answers forward (issue #53): its
/// KeyList fans out into Gets against the same generation, and every value
/// that comes back is stored into the CURRENT delegate. The posting-key seed
/// additionally resumes the account — guarded so a seed already loaded from
/// the current delegate is never overwritten.
fn dispatch_legacy_kv(from: &DelegateKey, payload: &[u8]) {
    match freebird_core::from_cbor::<FreebirdDelegateResponse>(payload) {
        Ok(FreebirdDelegateResponse::KeyList { keys }) => {
            // This KeyList answers the probe's List; every key now owes one
            // Value.
            probe_note(keys.len() as isize - 1);
            let from = from.clone();
            spawn_local_task(async move {
                for key in keys {
                    if let Err(e) =
                        kv_request_to(from.clone(), FreebirdDelegateRequest::Get { key }).await
                    {
                        log(&format!("legacy delegate get failed: {e}"));
                        probe_note(-1);
                    }
                }
            });
        }
        Ok(FreebirdDelegateResponse::Value { key, value: Some(value) }) => {
            probe_note(-1);
            if key == "posting_key" {
                // Never clobber an existing identity: an account created (or
                // seed loaded) while this answer was in flight wins.
                if ACCOUNT.peek().is_some()
                    || POSTING_KEY_LOADED.peek().as_ref().is_some_and(|v| v.is_some())
                {
                    return;
                }
                *POSTING_KEY_LOADED.write() = Some(Some(value.clone()));
                log("posting key carried forward from an old delegate generation");
            }
            spawn_local_task(async move {
                if let Err(e) =
                    kv_request(FreebirdDelegateRequest::Store { key, value }).await
                {
                    log(&format!("carry-forward store failed: {e}"));
                }
            });
        }
        Ok(FreebirdDelegateResponse::Value { key, value: None }) => {
            probe_note(-1);
            log(&format!("legacy delegate listed {key} but returned no value"));
        }
        Ok(FreebirdDelegateResponse::Error { message }) => {
            probe_note(-1);
            log(&format!("legacy delegate error: {message}"));
        }
        Ok(_) => {}
        Err(e) => log(&format!("bad legacy delegate response: {e}")),
    }
}

/// Spawn a fire-and-forget future from dispatch context (wasm only; native
/// test builds drop it — dispatch never runs there).
fn spawn_local_task<F: std::future::Future<Output = ()> + 'static>(fut: F) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(fut);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = fut;
}

fn dispatch_ghostkey(payload: &[u8]) {
    match ciborium::de::from_reader::<GhostkeyResponse, _>(payload) {
        Ok(GhostkeyResponse::SignResult {
            scoped_payload,
            signature,
            certificate_pem,
        }) => {
            *GHOSTKEY_SIGN_RESULT.write() =
                Some(Ok((scoped_payload, signature, certificate_pem)));
        }
        Ok(GhostkeyResponse::NoIdentityAvailable) => {
            *GHOSTKEY_SIGN_RESULT.write() = Some(Err(
                "No Ghost Key found — buy one at freenet.org/ghostkey, import it in the \
                 Identity Vault, then retry."
                    .into(),
            ));
        }
        Ok(GhostkeyResponse::AccessDenied { .. }) => {
            *GHOSTKEY_SIGN_RESULT.write() = Some(Err("Request denied".into()));
        }
        Ok(GhostkeyResponse::Error { message }) => {
            *GHOSTKEY_SIGN_RESULT.write() = Some(Err(message));
        }
        Ok(GhostkeyResponse::IdentityPresence { usable, .. }) => {
            *GHOSTKEY_HAS_IDENTITY.write() = Some(usable > 0);
        }
        Err(e) => log(&format!("bad ghostkey response: {e}")),
    }
}

// ---- tracked-contract registry ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrackedKind {
    Feed([u8; 32]),
    LegacyFeed([u8; 32]),
    Inbox([u8; 32]),
    LegacyInbox([u8; 32]),
    Anchor([u8; 32]),
    Avatar([u8; 32]),
    Directory,
    LegacyDirectory,
    Control,
    Pow,
}

pub static TRACKED: GlobalSignal<BTreeMap<String, TrackedKind>> =
    Signal::global(BTreeMap::new);

/// Newest anchor-cell order key seen per author (LWW guard for ANCHORS).
static ANCHOR_ORDER: GlobalSignal<BTreeMap<[u8; 32], (u64, [u8; 32])>> =
    Signal::global(BTreeMap::new);

fn track(key: ContractKey, kind: TrackedKind) {
    track_id(*key.id(), kind);
}

fn track_id(id: ContractInstanceId, kind: TrackedKind) {
    TRACKED.write().insert(id.to_string(), kind);
}

fn lookup(key: &ContractKey) -> Option<TrackedKind> {
    TRACKED.read().get(&key.id().to_string()).copied()
}

#[cfg(test)]
mod tests {
    use super::{
        anchor_targets, names_own_feed, own_anchor, seed_feed, TrackedKind, AVATAR_GENERATION,
        FEED_GENERATION, INBOX_GENERATION,
    };
    use crate::keys;
    use ed25519_dalek::SigningKey;
    use freebird_anchor::{AnchorV1, RoleV1, ROLE_AVATAR, ROLE_FEED, ROLE_INBOX};
    use freenet_stdlib::prelude::ContractInstanceId;
    use std::collections::BTreeMap;

    /// Issue #79: the feed rotations (#64, #67) moved every existing author's
    /// feed to an address their node has never seen, so `resume_account` PUTs
    /// the seed state before anything writes. Two properties make that PUT
    /// safe to run on EVERY resume, not just the first after a rotation: the
    /// contract must accept the seed as a first Put, and merging it over a
    /// feed already in use must change nothing.
    #[test]
    fn seed_feed_bootstraps_a_rotated_feed_without_clobbering_it() {
        use freebird_core::feed::FeedStateV1Delta;
        use freebird_core::types::{
            AuthorizedFollows, AuthorizedProfile, FollowsV1, ProfileV1,
        };
        use freenet_scaffold::ComposableState;

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let params = keys::feed_params(&sk.verifying_key());
        let seed = seed_feed(&sk);
        seed.verify(&seed, &params)
            .expect("the contract must accept the seed as a first Put");

        // Resume, then everything the account does next — the profile and
        // follows `migrate_v1` restores, and a post.
        let mut live = seed.clone();
        let clone = live.clone();
        live.apply_delta(
            &clone,
            &params,
            &Some(FeedStateV1Delta {
                profile: Some(AuthorizedProfile::new(
                    ProfileV1 { name: "gryph".into(), bio: "hi".into(), version: 3 },
                    &sk,
                )),
                follows: Some(AuthorizedFollows::new(
                    FollowsV1 { follows: [[9u8; 32]].into_iter().collect(), version: 2 },
                    &sk,
                )),
                attestation: None,
                posts: Some(vec![keys::make_post(&sk, "hello".into(), None)]),
            }),
        )
        .expect("writes land on the seeded feed");

        // The NEXT resume re-PUTs the same seed; the contract merges it.
        let before = live.clone();
        let clone = live.clone();
        live.merge(&clone, &params, &seed).expect("merge");
        assert_eq!(live, before, "a re-PUT of the seed must change nothing");
    }

    /// A rejected write reaches us with no request id, so the contract id in
    /// the message is the only correlation there is. Our own feed's failures
    /// are user news; every other contract's fail routinely (absent avatars,
    /// anchors, v1 reads) and stay in the log.
    #[test]
    fn only_our_own_feed_errors_reach_the_user() {
        let vk = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let msg = |id: ContractInstanceId| {
            format!(
                "client error: error while executing operation in the network: \
                 originator missing contract code/params for {id}; auto-fetch triggered"
            )
        };
        assert!(names_own_feed(&msg(keys::feed_instance_id(&vk)), &vk));
        assert!(!names_own_feed(&msg(keys::feed_instance_id(&other)), &vk));
        assert!(!names_own_feed(&msg(keys::avatar_instance_id(&vk)), &vk));
        assert!(!names_own_feed(
            "client error: error while registering delegate 5Kd3",
            &vk
        ));
    }

    fn anchor(roles: &[(&str, RoleV1)]) -> AnchorV1 {
        AnchorV1::new(
            roles
                .iter()
                .map(|(n, r)| (n.to_string(), r.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn id_bytes(id: ContractInstanceId) -> [u8; 32] {
        id.as_bytes().try_into().unwrap()
    }

    /// A simulated inbox rotation: the author's anchor names an address the
    /// bundled wasm does not derive, and it comes back tagged for this
    /// author's inbox slot — so its state merges where the UI already
    /// reads, no rebuild.
    #[test]
    fn rotated_inbox_is_followed() {
        let vk = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let author = vk.to_bytes();
        let rotated = [9u8; 32];
        let a = anchor(&[(
            ROLE_INBOX,
            RoleV1 { version: INBOX_GENERATION, address: Some(rotated) },
        )]);
        let got = anchor_targets(author, &vk, &a, &BTreeMap::new());
        assert_eq!(got.len(), 1, "one rotated role to follow");
        assert_eq!(got[0].1, ContractInstanceId::new(rotated));
        assert_eq!(got[0].2, TrackedKind::Inbox(author));
        assert!(got[0].3, "inbox reads subscribe");
    }

    /// Everything else falls back to the derived address: an unrotated
    /// anchor, a generation other than ours (either side), and a role with
    /// no address.
    #[test]
    fn non_rotations_yield_no_targets() {
        let vk = SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        let author = vk.to_bytes();
        let derived = id_bytes(keys::inbox_instance_id(&vk));
        let cases = [
            ("same as derived", RoleV1 { version: INBOX_GENERATION, address: Some(derived) }),
            ("future generation", RoleV1 { version: INBOX_GENERATION + 1, address: Some([9u8; 32]) }),
            ("older generation", RoleV1 { version: INBOX_GENERATION - 1, address: Some([9u8; 32]) }),
            ("no address", RoleV1 { version: INBOX_GENERATION, address: None }),
        ];
        for (why, role) in cases {
            let got = anchor_targets(author, &vk, &anchor(&[(ROLE_INBOX, role)]), &BTreeMap::new());
            assert!(got.is_empty(), "{why} must not be followed");
        }
        let empty = anchor_targets(author, &vk, &anchor(&[]), &BTreeMap::new());
        assert!(empty.is_empty(), "empty anchor");
    }

    /// Avatars rotate too, and are fetched without a subscription.
    #[test]
    fn rotated_avatar_is_followed_unsubscribed() {
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let author = vk.to_bytes();
        let a = anchor(&[(
            ROLE_AVATAR,
            RoleV1 { version: AVATAR_GENERATION, address: Some([9u8; 32]) },
        )]);
        let got = anchor_targets(author, &vk, &a, &BTreeMap::new());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2, TrackedKind::Avatar(author));
        assert!(!got[0].3, "avatar reads do not subscribe");
    }

    /// Nothing binds an anchor's address to its author, so an anchor may
    /// name a contract we already track — a victim's feed, or the
    /// directory. Re-tagging it would route that contract's updates into
    /// the wrong decoder, which discards them: reader-side denial of
    /// service for everyone who views the profile. First claim wins.
    #[test]
    fn anchor_never_retags_an_address_we_already_track() {
        let attacker = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        let victim = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let claimed = keys::feed_instance_id(&victim);
        let a = anchor(&[(
            ROLE_FEED,
            RoleV1 { version: FEED_GENERATION, address: Some(id_bytes(claimed)) },
        )]);
        let tracked = [(claimed.to_string(), TrackedKind::Feed(victim.to_bytes()))]
            .into_iter()
            .collect();
        let got = anchor_targets(attacker.to_bytes(), &attacker, &a, &tracked);
        assert!(got.is_empty(), "an anchor must not re-tag someone else's address");

        // Same address, same tag: our own rotation, already followed.
        let rotated = [7u8; 32];
        let mine = anchor(&[(
            ROLE_FEED,
            RoleV1 { version: FEED_GENERATION, address: Some(rotated) },
        )]);
        let author = attacker.to_bytes();
        let tracked = [(
            ContractInstanceId::new(rotated).to_string(),
            TrackedKind::Feed(author),
        )]
        .into_iter()
        .collect();
        let got = anchor_targets(author, &attacker, &mine, &tracked);
        assert!(got.is_empty(), "a rotation already followed is not re-fetched");
    }

    /// Each role must carry its OWN derivation and tag. A mispaired row
    /// (feed derived from the inbox address, say) would make every
    /// unrotated author look rotated, and send their state to the wrong
    /// decoder — so check the publish half against the read half: what this
    /// build publishes must read back as "nothing to follow".
    #[test]
    fn own_anchor_is_not_a_rotation() {
        let vk = SigningKey::from_bytes(&[6u8; 32]).verifying_key();
        let author = vk.to_bytes();
        let mine = own_anchor(&vk);
        assert_eq!(mine.roles.len(), 3, "inbox, feed and avatar are published");
        let got = anchor_targets(author, &vk, &mine, &BTreeMap::new());
        assert!(got.is_empty(), "a peer on this build must not re-fetch from our anchor");

        // ...and with all three rotated, all three are followed, each with
        // its own tag.
        let rotated = anchor(&[
            (ROLE_INBOX, RoleV1 { version: INBOX_GENERATION, address: Some([1u8; 32]) }),
            (ROLE_FEED, RoleV1 { version: FEED_GENERATION, address: Some([2u8; 32]) }),
            (ROLE_AVATAR, RoleV1 { version: AVATAR_GENERATION, address: Some([3u8; 32]) }),
        ]);
        let got = anchor_targets(author, &vk, &rotated, &BTreeMap::new());
        assert_eq!(got.len(), 3);
        let feed = (ROLE_FEED, ContractInstanceId::new([2u8; 32]), TrackedKind::Feed(author), true);
        assert!(got.contains(&feed), "feed row pairs its own derivation and tag");
    }

    /// The probe list keeps rotated generations and filters the CURRENT one
    /// (probing yourself would fold secrets onto themselves). Exercised with
    /// a synthetic registry: the current wasm plus a mutated (= rotated)
    /// copy — mutated kept, current dropped.
    #[test]
    fn legacy_registry_filters_current_generation() {
        let mutated: &'static [u8] = Box::leak({
            let mut v = crate::keys::FREEBIRD_DELEGATE_WASM.to_vec();
            *v.last_mut().unwrap() ^= 1;
            v.into_boxed_slice()
        });
        let registry: &[&'static [u8]] = &[crate::keys::FREEBIRD_DELEGATE_WASM, mutated];
        let got = super::legacy_delegates_from(registry);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, super::delegate_key_for(mutated));
        // And the real registry never yields the current key.
        let current = super::freebird_delegate_key();
        assert!(super::legacy_delegates().iter().all(|(_, k)| *k != current));
    }
}

pub fn log(msg: &str) {
    #[cfg(target_arch = "wasm32")]
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(msg));
    #[cfg(not(target_arch = "wasm32"))]
    println!("{msg}");
}
