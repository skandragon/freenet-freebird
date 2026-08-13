//! Key material and contract-address derivation.

use directory_contract::{DirectoryParametersV3, DIRECTORY_SEED};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freebird_core::avatar::AvatarParametersV1;
use freebird_core::feed::{FeedParametersV1, MAX_FUTURE_MS};
use freebird_core::inbox::InboxParametersV1;
use inbox_contract::state::InboxParametersV3;
use freebird_core::types::{AuthorizedPost, PostId, PostV1};
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, ContractKey, Parameters};
use ghostkey_lib::armorable::Armorable;

pub const FEED_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/feed_contract.wasm");
pub const INBOX_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/inbox_contract.wasm");
pub const AVATAR_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/avatar_contract.wasm");
pub const DIRECTORY_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/directory_contract.wasm");
pub const CELL_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/cell_contract.wasm");
pub const FREEBIRD_DELEGATE_WASM: &[u8] = include_bytes!("../contracts/freebird_delegate.wasm");

// Frozen v1 bytes, kept ONLY to derive the legacy inbox/directory addresses
// for the dual-read migration window (issue #23). Reads use the instance id;
// these wasm modules are never instantiated by this build.
pub const FEED_V1_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/feed_contract_v1.wasm");
pub const INBOX_V1_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/inbox_contract_v1.wasm");
pub const DIRECTORY_V1_CONTRACT_WASM: &[u8] =
    include_bytes!("../contracts/directory_contract_v1.wasm");

/// Frozen v1 delegate bytes — same convention as the frozen v1 contracts.
pub const FREEBIRD_DELEGATE_V1_WASM: &[u8] =
    include_bytes!("../contracts/freebird_delegate_v1.wasm");

/// Registry of every delegate generation ever shipped, oldest first (issue
/// #53). When the delegate rotates (any edit to common/ re-keys it), the
/// startup probe messages each OLD generation whose key differs from the
/// current one and folds its stored secrets — above all the posting-key seed
/// — forward into the new delegate. Rotating the delegate means: freeze the
/// outgoing wasm as `freebird_delegate_vN.wasm`, append it here, re-pin.
pub const LEGACY_DELEGATE_WASMS: &[&[u8]] = &[FREEBIRD_DELEGATE_V1_WASM];

/// This bundle's build number (git commit count; 0 in git-less dev builds).
pub fn own_build() -> u64 {
    env!("BUILD_NUMBER").parse().unwrap_or(0)
}

/// The Freenet Ghost Key master verifying key — the compiled-in trust anchor
/// every canonical Freebird client derives addresses with.
pub fn master_key() -> VerifyingKey {
    VerifyingKey::from_base64(ghostkey_lib::FREENET_MASTER_VERIFYING_KEY_BASE64)
        .expect("compiled-in master key parses")
}

pub fn feed_params(author: &VerifyingKey) -> FeedParametersV1 {
    FeedParametersV1 {
        author: *author,
        ghostkey_master: master_key(),
    }
}

pub fn inbox_params(owner: &VerifyingKey) -> InboxParametersV3 {
    InboxParametersV3 {
        owner: *owner,
        ghostkey_master: master_key(),
    }
}

/// Params of the author's LEGACY (v1) inbox — dual-read window only.
pub fn inbox_params_v1(owner: &VerifyingKey) -> InboxParametersV1 {
    InboxParametersV1 {
        owner: *owner,
        ghostkey_master: master_key(),
    }
}

pub fn avatar_params(author: &VerifyingKey) -> AvatarParametersV1 {
    AvatarParametersV1 { author: *author }
}

/// The public directory (issue #11): no author key in the params, so every
/// client derives the SAME address — one instance for the whole network.
pub fn directory_params() -> DirectoryParametersV3 {
    DirectoryParametersV3 {
        seed: DIRECTORY_SEED.into(),
        ghostkey_master: master_key(),
    }
}

/// Params of the LEGACY (v1) directory — dual-read window only.
pub fn directory_params_v1() -> directory_contract::legacy::LegacyDirectoryParameters {
    directory_contract::legacy::LegacyDirectoryParameters {
        seed: directory_contract::legacy::DIRECTORY_SEED_V1.into(),
        ghostkey_master: master_key(),
    }
}

fn contract_key(wasm: &[u8], params_cbor: Vec<u8>) -> ContractKey {
    ContractKey::from_params_and_code(
        Parameters::from(params_cbor),
        &ContractCode::from(wasm.to_vec()),
    )
}

pub fn feed_key(author: &VerifyingKey) -> ContractKey {
    let params = freebird_core::to_cbor(&feed_params(author)).expect("params serialize");
    contract_key(FEED_CONTRACT_WASM, params)
}

/// The author's LEGACY (pre-#64) feed address — dual-read window only. Same
/// params as the current feed; only the frozen v1 wasm bytes differ, so the
/// derived address differs.
pub fn feed_key_v1(author: &VerifyingKey) -> ContractKey {
    let params = freebird_core::to_cbor(&feed_params(author)).expect("params serialize");
    contract_key(FEED_V1_CONTRACT_WASM, params)
}

pub fn feed_instance_id_v1(author: &VerifyingKey) -> ContractInstanceId {
    *feed_key_v1(author).id()
}

pub fn inbox_key(owner: &VerifyingKey) -> ContractKey {
    let params = freebird_core::to_cbor(&inbox_params(owner)).expect("params serialize");
    contract_key(INBOX_CONTRACT_WASM, params)
}

pub fn inbox_key_v1(owner: &VerifyingKey) -> ContractKey {
    let params = freebird_core::to_cbor(&inbox_params_v1(owner)).expect("params serialize");
    contract_key(INBOX_V1_CONTRACT_WASM, params)
}

pub fn avatar_key(author: &VerifyingKey) -> ContractKey {
    let params = freebird_core::to_cbor(&avatar_params(author)).expect("params serialize");
    contract_key(AVATAR_CONTRACT_WASM, params)
}

pub fn feed_instance_id(author: &VerifyingKey) -> ContractInstanceId {
    *feed_key(author).id()
}

pub fn inbox_instance_id(owner: &VerifyingKey) -> ContractInstanceId {
    *inbox_key(owner).id()
}

pub fn inbox_instance_id_v1(owner: &VerifyingKey) -> ContractInstanceId {
    *inbox_key_v1(owner).id()
}

pub fn avatar_instance_id(author: &VerifyingKey) -> ContractInstanceId {
    *avatar_key(author).id()
}

pub fn directory_key() -> ContractKey {
    let params = freebird_core::to_cbor(&directory_params()).expect("params serialize");
    contract_key(DIRECTORY_CONTRACT_WASM, params)
}

pub fn directory_instance_id() -> ContractInstanceId {
    *directory_key().id()
}

pub fn directory_key_v1() -> ContractKey {
    let params = freebird_core::to_cbor(&directory_params_v1()).expect("params serialize");
    contract_key(DIRECTORY_V1_CONTRACT_WASM, params)
}

pub fn directory_instance_id_v1() -> ContractInstanceId {
    *directory_key_v1().id()
}

/// An author's anchor cell (issue #23): frozen cell wasm + posting key +
/// purpose "anchor" — the one per-author address that can never rotate.
pub fn anchor_params(owner: &VerifyingKey) -> cell_contract::CellParametersV1 {
    freebird_anchor::anchor_params(owner)
}

pub fn anchor_key(owner: &VerifyingKey) -> ContractKey {
    let params = cell_contract::to_cbor(&anchor_params(owner)).expect("params serialize");
    contract_key(CELL_CONTRACT_WASM, params)
}

pub fn anchor_instance_id(owner: &VerifyingKey) -> ContractInstanceId {
    *anchor_key(owner).id()
}

/// The publisher's control cell (build number + feature flags): like the
/// directory, params contain no per-user key, so every client derives the
/// same address.
pub fn control_cell_key() -> ContractKey {
    let params = cell_contract::to_cbor(&freebird_control::control_params()).expect("params serialize");
    contract_key(CELL_CONTRACT_WASM, params)
}

pub fn control_cell_instance_id() -> ContractInstanceId {
    *control_cell_key().id()
}

/// The publisher's anonymous-PoW difficulty cell (issue #66): same frozen
/// cell wasm, purpose "pow" — a separate address from control so a build
/// record can never be read as a difficulty record. Clients read it to solve
/// at the current bar and to relay the record into the contracts it governs.
pub fn pow_cell_key() -> ContractKey {
    let params = cell_contract::to_cbor(&freebird_pow::pow_params()).expect("params serialize");
    contract_key(CELL_CONTRACT_WASM, params)
}

pub fn pow_cell_instance_id() -> ContractInstanceId {
    *pow_cell_key().id()
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build and sign a post; clamps nothing — the caller supplies a sane time.
pub fn make_post(
    sk: &SigningKey,
    content: String,
    in_reply_to: Option<freebird_core::types::PostRef>,
) -> AuthorizedPost {
    let vk = sk.verifying_key();
    let time = now_ms().min(u64::MAX - MAX_FUTURE_MS);
    let post = PostV1 {
        id: PostId::compute(&vk, time, &content, &in_reply_to),
        time,
        content,
        in_reply_to,
    };
    AuthorizedPost::new(post, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn master_key_parses() {
        let _ = master_key();
    }

    #[test]
    fn addresses_deterministic_per_author() {
        let a = SigningKey::generate(&mut OsRng).verifying_key();
        let b = SigningKey::generate(&mut OsRng).verifying_key();
        assert_eq!(feed_key(&a), feed_key(&a));
        assert_ne!(feed_key(&a), feed_key(&b));
        assert_ne!(feed_key(&a), inbox_key(&a), "feed and inbox differ per wasm");
    }

    #[test]
    fn directory_address_fixed() {
        assert_eq!(directory_key(), directory_key());
    }

    /// Pins the actual derived addresses (issue #55). A failure here means the
    /// vendored wasm bytes or the params encoding changed — every user's data
    /// is about to become unreachable. See check-addresses in the Makefile;
    /// only update these goldens as part of a deliberate, reviewed rotation
    /// with a migration plan.
    #[test]
    fn golden_addresses_pinned() {
        let author = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let got = [
            directory_instance_id().to_string(),
            directory_instance_id_v1().to_string(),
            control_cell_instance_id().to_string(),
            feed_instance_id(&author).to_string(),
            feed_instance_id_v1(&author).to_string(),
            inbox_instance_id(&author).to_string(),
            inbox_instance_id_v1(&author).to_string(),
            avatar_instance_id(&author).to_string(),
            anchor_instance_id(&author).to_string(),
        ];
        let golden = [
            // Directory + inbox rotated 2026-08-12 (issue #52): LWW before
            // verification and a held-attestation skip on the delta paths.
            // Following the #51/#50/#49/#45 rotation precedent, neither
            // prior address gets a dual-read window (#51 rotated the same
            // pair without one): listings re-seat on republish, and inbox
            // creds/pointers re-staple as repliers repost.
            "6Jj6CndZ2DzkxRyhiriFoj7Bq6ewMDBCMJ4uiofdXyUn",
            "2Qyn5i8GzxsigkCtR1KWk9i72oRpc5Th5FuHdgZEnNdF",
            "8qkgr35PQcjn3TfNZYiJEexSf9FZsetdunpYx53n2ztF",
            // The PoW difficulty cell (#66) is deliberately NOT pinned here:
            // freebird-pow's `test-publisher` feature swaps the compiled
            // publisher key, and workspace feature unification turns it on
            // for some targets, so its derived address is build-dependent.
            // The properties a pin would protect are already covered — cell
            // wasm bytes + derivation by the control-cell entry above, and
            // the publisher key by freebird-pow's publisher_key_matches_control.
            "8iQ3nkukYF4Ux7Cixrtm8CBwc9J7ZZRZCxawxo14gatV",
            "8Drbx64Ahoc6o6MkBZQ15xGBaDCiNLT9t2TXJf6sSR5Q",
            "328eVhTm35uvJBnw35kXkNpCAvafvVpH5UoyPg7jGyxm",
            "9ayrE3HuxxGC5RDKhmBLQD8BHBnkqr5dyELJ2WqFGnZr",
            "F3dpVgrpZMwXKT92z17gaVCYg3CraPNgy3NdvAGsRGRa",
            "7ZSANRfpAfZWZttBsAzGEpvZHKmqQMvSp1S8FtLgeYf9",
        ];
        assert_eq!(got, golden, "derived contract addresses ROTATED");
    }
}
