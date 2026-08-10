#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code, unused_imports))]
//! Node connection + request plumbing + response dispatch.
//!
//! Slimmed from River's freenet_api layer: one WebSocket via
//! `freenet_stdlib::client_api::WebApi`, global Dioxus signals for state,
//! stateless response dispatch (responses are recognized by their content —
//! contract keys map to known feeds/inboxes, delegate responses by type).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freebird_core::delegate_api::{FreebirdDelegateRequest, FreebirdDelegateResponse};
use freebird_core::feed::{FeedParametersV1, FeedStateV1, FeedStateV1Delta};
use freebird_core::inbox::{InboxStateV1, InboxStateV1Delta};
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

fn inbox_container(owner: &VerifyingKey) -> ContractContainer {
    let params = freebird_core::to_cbor(&keys::inbox_params(owner)).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::INBOX_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

/// PUT our own feed + inbox (first run), subscribing to both.
pub async fn put_own_contracts(author: &VerifyingKey, feed: &FeedStateV1) -> Result<(), String> {
    let feed_state = freebird_core::to_cbor(feed)?;
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: feed_container(author),
        state: WrappedState::new(feed_state),
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await?;
    let inbox_state = freebird_core::to_cbor(&InboxStateV1::default())?;
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: inbox_container(author),
        state: WrappedState::new(inbox_state),
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// GET + subscribe someone's feed and inbox by author key.
pub async fn fetch_feed(author: [u8; 32]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&author).map_err(|e| e.to_string())?;
    // Pending placeholder so effects don't re-spawn the fetch every render
    // until the response lands.
    FEEDS.write().entry(author).or_insert(None);
    track(keys::feed_key(&vk), TrackedKind::Feed(author));
    track(keys::inbox_key(&vk), TrackedKind::Inbox(author));
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
pub async fn update_inbox(target_author: [u8; 32], delta: InboxStateV1Delta) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&target_author).map_err(|e| e.to_string())?;
    let bytes = freebird_core::to_cbor(&delta)?;
    send(ClientRequest::ContractOp(ContractRequest::Update {
        key: keys::inbox_key(&vk),
        data: UpdateData::Delta(StateDelta::from(bytes)),
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
    let code = DelegateCode::from(keys::FREEBIRD_DELEGATE_WASM.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    DelegateKey::from_params(code.hash_str(), &params).expect("delegate key")
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
    let payload = freebird_core::to_cbor(&request)?;
    send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
        key: freebird_delegate_key(),
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(payload),
        )],
    }))
    .await
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
            for out in values {
                if let OutboundDelegateMsg::ApplicationMessage(app_msg) = out {
                    if is_freebird {
                        dispatch_kv(app_msg.payload.as_ref());
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
        TrackedKind::Inbox(author) => {
            let Ok(vk) = VerifyingKey::from_bytes(&author) else { return };
            let params = keys::inbox_params(&vk);
            let mut inboxes = INBOXES.write();
            let entry = inboxes.entry(author).or_default();
            if is_full_state {
                match freebird_core::from_cbor::<InboxStateV1>(bytes) {
                    Ok(incoming) => {
                        let clone = entry.clone();
                        if let Err(e) = entry.merge(&clone, &params, &incoming) {
                            log(&format!("inbox merge rejected: {e}"));
                        }
                    }
                    Err(e) => log(&format!("bad inbox state: {e}")),
                }
            } else {
                match freebird_core::from_cbor::<InboxStateV1Delta>(bytes) {
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
    Inbox([u8; 32]),
}

pub static TRACKED: GlobalSignal<BTreeMap<String, TrackedKind>> =
    Signal::global(BTreeMap::new);

fn track(key: ContractKey, kind: TrackedKind) {
    TRACKED.write().insert(key.id().to_string(), kind);
}

fn lookup(key: &ContractKey) -> Option<TrackedKind> {
    TRACKED.read().get(&key.id().to_string()).copied()
}

pub fn log(msg: &str) {
    #[cfg(target_arch = "wasm32")]
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(msg));
    #[cfg(not(target_arch = "wasm32"))]
    println!("{msg}");
}
