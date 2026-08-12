//! Public author directory, v3 (issues #11, #23, #45/#47): ONE well-known contract
//! for the whole network. Params are a version seed + the ghostkey master
//! key — no author key — so every client derives the same address (doorbell
//! pattern). Authors opt in by publishing a signed listing; the Discover tab
//! reads the set.
//!
//! V2 makes the attestation OPTIONAL: anonymous authors may list themselves.
//! The Ghost Key stops being a write gate and becomes a slot policy —
//! attested listings may fill the whole cap and are never evicted by
//! anonymous ones; anonymous listings share a bounded remainder and evict
//! only each other (a keygen loop can churn the anonymous share, never a
//! verified author's listing). Same tier discipline as the v2 inbox.
//!
//! State types live HERE, not in freebird-core: adding a module to the
//! shared crate would change every deployed contract's wasm bytes and rotate
//! all derived addresses (the 2026-08-10 avatar incident). The UI depends on
//! this crate directly with default-features = false. The `legacy` module
//! keeps the v1 wire types for the dual-read migration window.

use std::collections::BTreeMap;

use cell_contract::SignedCellV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freebird_core::attestation::{AttestationV1, AttestationV2};
use freebird_core::feed::MAX_FUTURE_MS;
use freebird_pow::{difficulty_bits, meets_directory, solve_directory, POW_FLOOR_BITS};
use serde::{Deserialize, Serialize};

/// Version seed baked into the params; rotating it deliberately mints a new
/// directory address (with a migration story), never as a rebuild side
/// effect. v2 = anonymous parity (issue #23); v3 = signed attestation +
/// domain-tagged listing signature (issues #45/#47).
pub const DIRECTORY_SEED: &str = "freebird-directory-v3";

/// Domain tag for listing signatures (issue #47); the version suffix
/// doubles as the directory-generation discriminator.
pub const LISTING_SIGN_DOMAIN: &[u8] = b"freebird-listing-v3";

/// ponytail: single hot contract; ~1KB/listing (attestation chain) ≈ 1MB at
/// cap. Shard by author-key prefix if it ever fills.
pub const MAX_LISTINGS: usize = 1000;

/// Slots anonymous listings may occupy at most. One listing per posting key
/// is inherent (the map key), so the share cap is the only thing bounding a
/// keygen flood — attested listings may use all MAX_LISTINGS.
pub const ANON_LISTINGS: usize = 250;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct DirectoryParametersV3 {
    pub seed: String,
    /// Ghost Key trust anchor; see `FeedParametersV1::ghostkey_master`.
    pub ghostkey_master: VerifyingKey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ListingV1 {
    /// The listed author's posting key bytes.
    pub author: [u8; 32],
    /// Refreshed by occasional re-publishes; eviction order at capacity.
    pub last_active: u64,
}

/// Listing + signature by the author's posting key. The Ghost Key
/// attestation is optional: present = attested tier (uncrowdable), absent =
/// anonymous tier (bounded share). The signature covers the listing AND the
/// attestation slot (issue #45): nobody can re-wrap a victim's listing with
/// a different attestation (or strip it) without the author's key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedListingV3 {
    pub listing: ListingV1,
    pub signature: Signature,
    pub attestation: Option<AttestationV2>,
    /// Anonymous proof-of-work nonce (issue #51): solved over the author key
    /// (see `freebird_pow::meets_directory`). Ignored for attested listings —
    /// the ghost key skips PoW. Not covered by the signature: tampering with
    /// it only breaks the PoW check, and the author binding still holds.
    #[serde(default)]
    pub pow_nonce: u64,
}

/// The exact bytes the author signs (issue #47): domain tag + canonical
/// field layout + the attestation slot's content hash.
pub fn listing_signing_payload(
    listing: &ListingV1,
    attestation: Option<&AttestationV2>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(LISTING_SIGN_DOMAIN.len() + 32 + 8 + 1 + 32);
    out.extend_from_slice(LISTING_SIGN_DOMAIN);
    out.extend_from_slice(&listing.author);
    out.extend_from_slice(&listing.last_active.to_le_bytes());
    match attestation {
        None => out.push(0),
        Some(att) => {
            out.push(1);
            // ponytail: content_hash() = blake3(to_cbor(AttestationV2)) — a
            // residual bare-CBOR dependency in #47's manual-canonical
            // guarantee. Contained: a ciborium encoding change could only
            // invalidate an attested listing's OWN signature (availability,
            // self-healing on republish), never forge or substitute one
            // (the attestation still verifies its own manual-canonical
            // payload + pop independently). Fold the pop/ghost signature
            // bytes in here if the attestation ever gains a cheaper stable
            // identity; not worth rotating the directory address for now.
            out.extend_from_slice(&att.content_hash());
        }
    }
    out
}

impl AuthorizedListingV3 {
    pub fn new(listing: ListingV1, sk: &SigningKey, attestation: Option<AttestationV2>) -> Self {
        use ed25519_dalek::Signer;
        let signature = sk.sign(&listing_signing_payload(&listing, attestation.as_ref()));
        Self {
            signature,
            listing,
            attestation,
            pow_nonce: 0,
        }
    }

    /// An anonymous listing carrying a proof-of-work stamp solved to `bits`
    /// (issue #51). Solving is a pure integer loop; run it off the UI thread.
    pub fn new_anon(listing: ListingV1, sk: &SigningKey, bits: u8) -> Self {
        let mut l = Self::new(listing, sk, None);
        l.pow_nonce = solve_directory(&l.listing.author, bits);
        l
    }

    pub fn is_anon(&self) -> bool {
        self.attestation.is_none()
    }

    /// Full validity: author key parses, signature verifies (covering the
    /// attestation slot), and — when present — the attestation chain
    /// verifies and binds this posting key.
    pub fn check(&self, master: &VerifyingKey) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.listing.author)
            .map_err(|e| format!("bad author key: {e}"))?;
        vk.verify_strict(
            &listing_signing_payload(&self.listing, self.attestation.as_ref()),
            &self.signature,
        )
        .map_err(|e| format!("listing signature invalid: {e}"))?;
        if let Some(att) = &self.attestation {
            att.verify(&vk, Some(master))
                .map(|_tier| ())
                .map_err(|e| format!("listing attestation invalid: {e}"))?;
        }
        Ok(())
    }

    /// Per-author LWW winner: max `(last_active, attested, content hash)`.
    /// The attested bit keeps an author's own equal-time attested republish
    /// ahead of their anonymous one on every peer (stripping by THIRD
    /// parties died with #45 — the signature now covers the attestation).
    /// The hash still breaks attested-vs-attested ties deterministically.
    pub fn lww_key(&self) -> (u64, bool, [u8; 32]) {
        let bytes = freebird_core::to_cbor(self).expect("listing serializes");
        (
            self.listing.last_active,
            self.attestation.is_some(),
            *blake3::hash(&bytes).as_bytes(),
        )
    }
}

/// Eviction/horizon order across authors: oldest `(last_active, author)` first.
pub type ListingOrderKey = (u64, [u8; 32]);

fn order_key(l: &AuthorizedListingV3) -> ListingOrderKey {
    (l.listing.last_active, l.listing.author)
}

/// Per-tier retention horizon; see the v2 inbox's `TierHorizon` for the
/// derivation. `Closed` = this tier retains nothing and accepts nothing
/// (attested listings hold every slot), so senders offer nothing rather
/// than re-offer pruned anonymous listings forever.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub enum TierHorizon {
    #[default]
    Open,
    OldestRetained(ListingOrderKey),
    Closed,
}

impl TierHorizon {
    fn admits(&self, key: ListingOrderKey) -> bool {
        match self {
            TierHorizon::Open => true,
            TierHorizon::OldestRetained(oldest) => key > *oldest,
            TierHorizon::Closed => false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct DirectorySummaryV3 {
    /// author → per-author LWW key held (BTreeMap: canonical summary bytes).
    pub entries: BTreeMap<[u8; 32], (u64, bool, [u8; 32])>,
    pub attested_horizon: TierHorizon,
    pub anon_horizon: TierHorizon,
}

/// A directory delta: the listings offered, plus the optional publisher-signed
/// difficulty record (issue #51) the writer solved against. The record rides
/// the ORIGINAL client write only; node-to-node gossip (`DirectoryStateV3::
/// delta`) emits `pow_difficulty: None`, so replicas always re-admit at the
/// compiled floor and stay convergent.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct DirectoryDeltaV3 {
    pub listings: Vec<AuthorizedListingV3>,
    #[serde(default)]
    pub pow_difficulty: Option<SignedCellV1>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct DirectoryStateV3 {
    /// One listing per author, keyed by posting key.
    pub listings: BTreeMap<[u8; 32], AuthorizedListingV3>,
}

impl DirectoryStateV3 {
    fn anon_count(&self) -> usize {
        self.listings.values().filter(|l| l.is_anon()).count()
    }

    pub fn verify(&self, parameters: &DirectoryParametersV3) -> Result<(), String> {
        if self.listings.len() > MAX_LISTINGS {
            return Err(format!("more than {MAX_LISTINGS} listings"));
        }
        if self.anon_count() > ANON_LISTINGS {
            return Err(format!("more than {ANON_LISTINGS} anonymous listings"));
        }
        for (key, l) in &self.listings {
            if key != &l.listing.author {
                return Err("listing stored under wrong author key".into());
            }
            l.check(&parameters.ghostkey_master)?;
            // Every seated anonymous listing must clear the COMPILED floor
            // (issue #51). This is the convergent, adversary-facing check: a
            // fabricated full state cannot seat a free anonymous share. The
            // control-cell difficulty is enforced at admission only, so
            // raising it never retroactively bricks listings already seated.
            if l.is_anon() && !meets_directory(key, l.pow_nonce, POW_FLOOR_BITS) {
                return Err("anonymous listing below the proof-of-work floor".into());
            }
        }
        Ok(())
    }

    /// Tiered eviction, idempotent:
    /// - over the anonymous share: evict the oldest anonymous listing;
    /// - over the global cap: evict the oldest anonymous listing first, and
    ///   the oldest attested only when no anonymous remain. Verified is
    ///   never crowded out by anonymous.
    pub fn canonicalize(&mut self) {
        while self.anon_count() > ANON_LISTINGS {
            let oldest = self
                .listings
                .values()
                .filter(|l| l.is_anon())
                .map(order_key)
                .min()
                .expect("anon over cap implies anon present");
            self.listings.remove(&oldest.1);
        }
        while self.listings.len() > MAX_LISTINGS {
            let victim = self
                .listings
                .values()
                .filter(|l| l.is_anon())
                .map(order_key)
                .min()
                .or_else(|| self.listings.values().map(order_key).min())
                .expect("non-empty over cap");
            self.listings.remove(&victim.1);
        }
    }

    /// Clock-dependent scrub, called by the contract shell only (host clock
    /// lives there, never inside the pure merge).
    pub fn scrub_future(&mut self, now_ms: u64) {
        self.listings
            .retain(|_, l| l.listing.last_active <= now_ms.saturating_add(MAX_FUTURE_MS));
    }

    fn tier_horizons(&self) -> (TierHorizon, TierHorizon) {
        let attested: Vec<ListingOrderKey> = self
            .listings
            .values()
            .filter(|l| !l.is_anon())
            .map(order_key)
            .collect();
        let anon: Vec<ListingOrderKey> = self
            .listings
            .values()
            .filter(|l| l.is_anon())
            .map(order_key)
            .collect();

        let attested_h = if attested.len() >= MAX_LISTINGS {
            TierHorizon::OldestRetained(attested.iter().min().copied().expect("at cap"))
        } else {
            TierHorizon::Open
        };
        let effective = ANON_LISTINGS.min(MAX_LISTINGS.saturating_sub(attested.len()));
        let anon_h = if effective == 0 {
            TierHorizon::Closed
        } else if anon.len() >= effective {
            TierHorizon::OldestRetained(anon.iter().min().copied().expect("non-empty tier"))
        } else {
            TierHorizon::Open
        };
        (attested_h, anon_h)
    }

    pub fn summarize(&self) -> DirectorySummaryV3 {
        let (attested_horizon, anon_horizon) = self.tier_horizons();
        DirectorySummaryV3 {
            entries: self
                .listings
                .iter()
                .map(|(k, l)| (*k, l.lww_key()))
                .collect(),
            attested_horizon,
            anon_horizon,
        }
    }

    /// Listings the peer lacks (or holds older), and would retain. Gossip
    /// deltas never carry a difficulty record — admission at the receiver
    /// runs at the compiled floor (issue #51), keeping replicas convergent.
    pub fn delta(&self, theirs: &DirectorySummaryV3) -> Option<DirectoryDeltaV3> {
        let listings: Vec<AuthorizedListingV3> = self
            .listings
            .values()
            .filter(|l| match theirs.entries.get(&l.listing.author) {
                None => true,
                Some(held) => l.lww_key() > *held,
            })
            .filter(|l| {
                // Horizon-gate only authors the peer does not hold: for a
                // held author this is an in-place LWW upgrade of an existing
                // slot, and gating it can permanently withhold an update
                // whose order key exactly ties the tier's oldest entry.
                if theirs.entries.contains_key(&l.listing.author) {
                    return true;
                }
                let tier = if l.is_anon() {
                    &theirs.anon_horizon
                } else {
                    &theirs.attested_horizon
                };
                tier.admits(order_key(l))
            })
            .cloned()
            .collect();
        (!listings.is_empty()).then_some(DirectoryDeltaV3 {
            listings,
            pow_difficulty: None,
        })
    }

    /// Verify and merge incoming listings: newer per author wins, then cap.
    pub fn apply_delta(
        &mut self,
        parameters: &DirectoryParametersV3,
        delta: &DirectoryDeltaV3,
    ) -> Result<(), String> {
        // Bound the work one delta can demand: each attested listing costs
        // an RSA chain verification inside wasm.
        if delta.listings.len() > MAX_LISTINGS {
            return Err("listing delta too large".into());
        }
        // Admission difficulty: the floor, raised by a valid publisher-signed
        // control-cell record if this write carries one (issue #51).
        let bits = difficulty_bits(delta.pow_difficulty.as_ref());
        for l in &delta.listings {
            l.check(&parameters.ghostkey_master)?;
            // Anonymous listings must clear the proof-of-work bar; drop the
            // ones that don't rather than fail the whole delta (an honest
            // peer never forwards an under-bar listing, so this only bites
            // fabricated deltas — same doctrine as a missing credential).
            // Attested listings skip PoW entirely.
            if l.is_anon() && !meets_directory(&l.listing.author, l.pow_nonce, bits) {
                continue;
            }
            match self.listings.get(&l.listing.author) {
                Some(held) if held.lww_key() >= l.lww_key() => {}
                _ => {
                    self.listings.insert(l.listing.author, l.clone());
                }
            }
        }
        self.canonicalize();
        Ok(())
    }

    /// Full-state merge = apply the other side's listings as a delta. No
    /// difficulty record: floor admission, as for any gossip.
    pub fn merge(
        &mut self,
        parameters: &DirectoryParametersV3,
        other: &DirectoryStateV3,
    ) -> Result<(), String> {
        let delta = DirectoryDeltaV3 {
            listings: other.listings.values().cloned().collect(),
            pow_difficulty: None,
        };
        self.apply_delta(parameters, &delta)
    }
}

/// The v1 wire types, kept ONLY so clients can decode the old directory
/// during the dual-read migration window (the deployed v1 wasm is what
/// enforced them; nothing here writes v1). Frozen: matches the last v1
/// contract bytes exactly.
pub mod legacy {
    use super::*;

    pub const DIRECTORY_SEED_V1: &str = "freebird-directory-v1";

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct LegacyAuthorizedListing {
        pub listing: ListingV1,
        pub signature: Signature,
        pub attestation: AttestationV1,
    }

    impl LegacyAuthorizedListing {
        /// Same checks the v1 contract ran (attestation mandatory).
        pub fn check(&self, master: &VerifyingKey) -> Result<(), String> {
            let vk = VerifyingKey::from_bytes(&self.listing.author)
                .map_err(|e| format!("bad author key: {e}"))?;
            let bytes = freebird_core::to_cbor(&self.listing)?;
            vk.verify_strict(&bytes, &self.signature)
                .map_err(|e| format!("listing signature invalid: {e}"))?;
            self.attestation
                .verify(&vk, Some(master))
                .map(|_tier| ())
                .map_err(|e| format!("listing attestation invalid: {e}"))
        }
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct LegacyDirectoryState {
        pub listings: BTreeMap<[u8; 32], LegacyAuthorizedListing>,
    }

    pub type LegacyDirectoryDelta = Vec<LegacyAuthorizedListing>;

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct LegacyDirectoryParameters {
        pub seed: String,
        pub ghostkey_master: VerifyingKey,
    }
}

/// Thin contract shell, same structure and clock-scrub rationale as the
/// feed/inbox contracts. Feature-gated so the UI can depend on the state
/// types without compiling (or exporting) the contract entry points.
#[cfg(feature = "freenet-main-contract")]
mod contract {
    use super::*;
    use ciborium::{de::from_reader, ser::into_writer};
    use freenet_stdlib::prelude::*;

    fn now_ms() -> u64 {
        freenet_stdlib::time::now().timestamp_millis().max(0) as u64
    }

    fn deser<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ContractError> {
        from_reader::<T, &[u8]>(bytes).map_err(|e| ContractError::Deser(format!("{what}: {e}")))
    }

    fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
        let mut out = vec![];
        into_writer(value, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(out)
    }

    /// Drop far-future listings from an incoming delta before the merge — a
    /// poisoned timestamp must never get the chance to outlive honest ones.
    fn scrub_delta(delta: &mut DirectoryDeltaV3, now: u64) {
        delta
            .listings
            .retain(|l| l.listing.last_active <= now.saturating_add(MAX_FUTURE_MS));
    }

    #[allow(dead_code)]
    struct Contract;

    #[contract]
    impl ContractInterface for Contract {
        fn validate_state(
            parameters: Parameters<'static>,
            state: State<'static>,
            _related: RelatedContracts<'static>,
        ) -> Result<ValidateResult, ContractError> {
            let bytes = state.as_ref();
            if bytes.is_empty() {
                return Ok(ValidateResult::Valid);
            }
            let dir: DirectoryStateV3 = deser(bytes, "state")?;
            let parameters: DirectoryParametersV3 = deser(parameters.as_ref(), "parameters")?;

            let mut scrubbed = dir.clone();
            scrubbed.scrub_future(now_ms());
            if scrubbed != dir {
                return Ok(ValidateResult::Invalid);
            }

            match dir.verify(&parameters) {
                Ok(()) => Ok(ValidateResult::Valid),
                Err(_) => Ok(ValidateResult::Invalid),
            }
        }

        fn update_state(
            parameters: Parameters<'static>,
            state: State<'static>,
            data: Vec<UpdateData<'static>>,
        ) -> Result<UpdateModification<'static>, ContractError> {
            let parameters: DirectoryParametersV3 = deser(parameters.as_ref(), "parameters")?;
            let mut dir: DirectoryStateV3 = if state.as_ref().is_empty() {
                DirectoryStateV3::default()
            } else {
                deser(state.as_ref(), "state")?
            };
            let now = now_ms();
            dir.scrub_future(now);

            for update in data {
                match update {
                    UpdateData::State(new_state) => {
                        let mut incoming: DirectoryStateV3 =
                            deser(new_state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        dir.merge(&parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::Delta(d) => {
                        if d.as_ref().is_empty() {
                            continue;
                        }
                        let mut delta: DirectoryDeltaV3 = deser(d.as_ref(), "delta")?;
                        scrub_delta(&mut delta, now);
                        dir.apply_delta(&parameters, &delta)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::StateAndDelta { state, delta } => {
                        let mut incoming: DirectoryStateV3 =
                            deser(state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        dir.merge(&parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                        if !delta.as_ref().is_empty() {
                            let mut delta: DirectoryDeltaV3 = deser(delta.as_ref(), "delta")?;
                            scrub_delta(&mut delta, now);
                            dir.apply_delta(&parameters, &delta)
                                .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                        }
                    }
                    // Unknown variants (#[non_exhaustive]) are rejected, not
                    // panicked on — a panic in contract WASM kills the runtime.
                    _ => return Err(ContractError::InvalidUpdate),
                }
            }

            Ok(UpdateModification::valid(ser(&dir)?.into()))
        }

        fn summarize_state(
            parameters: Parameters<'static>,
            state: State<'static>,
        ) -> Result<StateSummary<'static>, ContractError> {
            let _ = parameters;
            let bytes = state.as_ref();
            if bytes.is_empty() {
                return Ok(StateSummary::from(vec![]));
            }
            let dir: DirectoryStateV3 = deser(bytes, "state")?;
            Ok(StateSummary::from(ser(&dir.summarize())?))
        }

        fn get_state_delta(
            parameters: Parameters<'static>,
            state: State<'static>,
            summary: StateSummary<'static>,
        ) -> Result<StateDelta<'static>, ContractError> {
            let _ = parameters;
            if state.as_ref().is_empty() {
                return Ok(StateDelta::from(vec![]));
            }
            let dir: DirectoryStateV3 = deser(state.as_ref(), "state")?;
            // Zero-byte summary = "peer has nothing" (summarize of empty
            // state emits it); parsing it as CBOR would abort the sync.
            let summary: DirectorySummaryV3 = if summary.as_ref().is_empty() {
                DirectorySummaryV3::default()
            } else {
                deser(summary.as_ref(), "summary")?
            };
            match dir.delta(&summary) {
                Some(d) => Ok(StateDelta::from(ser(&d)?)),
                None => Ok(StateDelta::from(vec![])),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_core::attestation::fixtures::TestAuthority;
    use rand::rngs::OsRng;

    struct Author {
        sk: SigningKey,
        key: [u8; 32],
        att: AttestationV2,
    }

    fn author(authority: &TestAuthority) -> Author {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Author {
            key: vk.to_bytes(),
            att: authority.attest(&sk),
            sk,
        }
    }

    fn anon_author() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let key = sk.verifying_key().to_bytes();
        (sk, key)
    }

    fn params(authority: &TestAuthority) -> DirectoryParametersV3 {
        DirectoryParametersV3 {
            seed: DIRECTORY_SEED.into(),
            ghostkey_master: authority.master_vk,
        }
    }

    fn listing(a: &Author, time: u64) -> AuthorizedListingV3 {
        AuthorizedListingV3::new(
            ListingV1 {
                author: a.key,
                last_active: time,
            },
            &a.sk,
            Some(a.att.clone()),
        )
    }

    /// Structurally valid, never verified — for cap/horizon tests where
    /// minting one real attestation per author would take minutes.
    fn fake_listing(att: Option<&AttestationV2>, author: [u8; 32], time: u64) -> AuthorizedListingV3 {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        AuthorizedListingV3::new(
            ListingV1 {
                author,
                last_active: time,
            },
            &sk,
            att.cloned(),
        )
    }

    fn key_of(i: u64, tag: u8) -> [u8; 32] {
        let mut key = [tag; 32];
        key[..8].copy_from_slice(&i.to_be_bytes());
        key
    }

    /// Wrap listings in a floor-difficulty delta (no publisher record).
    fn d(listings: Vec<AuthorizedListingV3>) -> DirectoryDeltaV3 {
        DirectoryDeltaV3 {
            listings,
            pow_difficulty: None,
        }
    }

    /// An anonymous listing carrying a valid floor-difficulty PoW stamp.
    fn anon_listing(sk: &SigningKey, key: [u8; 32], time: u64) -> AuthorizedListingV3 {
        AuthorizedListingV3::new_anon(
            ListingV1 {
                author: key,
                last_active: time,
            },
            sk,
            POW_FLOOR_BITS,
        )
    }

    #[test]
    fn attested_listing_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![listing(&a, 5)])).expect("apply ok");
        assert_eq!(s.listings.len(), 1);
        s.verify(&p).expect("verifies");
    }

    #[test]
    fn anon_listing_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let (sk, key) = anon_author();
        let mut s = DirectoryStateV3::default();
        let l = anon_listing(&sk, key, 5);
        s.apply_delta(&p, &d(vec![l])).expect("apply ok");
        assert_eq!(s.listings.len(), 1);
        assert!(s.listings[&key].is_anon());
        s.verify(&p).expect("verifies");
    }

    #[test]
    fn wrong_master_attestation_rejected() {
        let authority = TestAuthority::new();
        let rogue = TestAuthority::new();
        let p = params(&authority);
        let a = author(&rogue); // attested under the wrong master
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(vec![listing(&a, 5)])).is_err());
    }

    #[test]
    fn forged_signature_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let (_, key) = anon_author();
        let other = SigningKey::generate(&mut OsRng);
        // Claims another author's identity but signed by a different key.
        let forged = AuthorizedListingV3::new(
            ListingV1 {
                author: key,
                last_active: 5,
            },
            &other,
            None,
        );
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(vec![forged])).is_err());
    }

    #[test]
    fn lww_newer_wins_stale_noop() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![listing(&a, 5)])).unwrap();
        s.apply_delta(&p, &d(vec![listing(&a, 3)])).unwrap(); // stale: no-op
        assert_eq!(s.listings[&a.key].listing.last_active, 5);
        s.apply_delta(&p, &d(vec![listing(&a, 7)])).unwrap(); // newer: wins
        assert_eq!(s.listings[&a.key].listing.last_active, 7);
        assert_eq!(s.listings.len(), 1);
    }

    #[test]
    fn anon_share_capped() {
        let mut s = DirectoryStateV3::default();
        for i in 0..(ANON_LISTINGS as u64 + 20) {
            let key = key_of(i, 0);
            s.listings.insert(key, fake_listing(None, key, i));
        }
        s.canonicalize();
        assert_eq!(s.listings.len(), ANON_LISTINGS);
        // The oldest were evicted.
        let min = s.listings.values().map(|l| l.listing.last_active).min().unwrap();
        assert_eq!(min, 20);
    }

    #[test]
    fn anon_never_evicts_attested() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut s = DirectoryStateV3::default();
        // 900 old attested + 250 newer anon: every attested survives, anon
        // squeezed into the remaining 100 slots.
        for i in 0..900u64 {
            let key = key_of(i, 1);
            s.listings.insert(key, fake_listing(Some(&a.att), key, i));
        }
        for i in 0..250u64 {
            let key = key_of(i, 2);
            s.listings.insert(key, fake_listing(None, key, 10_000 + i));
        }
        s.canonicalize();
        let anon = s.listings.values().filter(|l| l.is_anon()).count();
        assert_eq!(s.listings.len(), MAX_LISTINGS);
        assert_eq!(anon, 100);
        assert_eq!(
            s.listings.values().filter(|l| !l.is_anon()).count(),
            900,
            "attested listings are never crowded out"
        );
    }

    #[test]
    fn attested_evicts_anon_at_cap() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut s = DirectoryStateV3::default();
        for i in 0..100u64 {
            let key = key_of(i, 2);
            s.listings.insert(key, fake_listing(None, key, i));
        }
        for i in 0..MAX_LISTINGS as u64 {
            let key = key_of(i, 1);
            s.listings.insert(key, fake_listing(Some(&a.att), key, 1000 + i));
        }
        s.canonicalize();
        assert_eq!(s.listings.len(), MAX_LISTINGS);
        assert_eq!(s.listings.values().filter(|l| l.is_anon()).count(), 0);
    }

    #[test]
    fn attested_only_eviction_when_no_anon_left() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut s = DirectoryStateV3::default();
        for i in 0..(MAX_LISTINGS as u64 + 5) {
            let key = key_of(i, 1);
            s.listings.insert(key, fake_listing(Some(&a.att), key, i));
        }
        s.canonicalize();
        assert_eq!(s.listings.len(), MAX_LISTINGS);
        let min = s.listings.values().map(|l| l.listing.last_active).min().unwrap();
        assert_eq!(min, 5);
    }

    #[test]
    fn closed_anon_horizon_no_reoffer() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        // Receiver full of attested listings ⇒ anon tier Closed.
        let mut receiver = DirectoryStateV3::default();
        for i in 0..MAX_LISTINGS as u64 {
            let key = key_of(i, 1);
            receiver.listings.insert(key, fake_listing(Some(&a.att), key, 1000 + i));
        }
        let summary = receiver.summarize();
        assert_eq!(summary.anon_horizon, TierHorizon::Closed);

        // Sender holds only anon listings ⇒ offers nothing.
        let mut sender = DirectoryStateV3::default();
        let key = key_of(0, 2);
        sender.listings.insert(key, fake_listing(None, key, 99_999));
        assert!(sender.delta(&summary).is_none());
    }

    #[test]
    fn anon_horizon_prevents_reoffer_of_pruned_listings() {
        // Receiver's anon share full with newer entries.
        let mut receiver = DirectoryStateV3::default();
        for i in 0..ANON_LISTINGS as u64 {
            let key = key_of(i, 2);
            receiver.listings.insert(key, fake_listing(None, key, 1000 + i));
        }
        let summary = receiver.summarize();
        assert!(matches!(summary.anon_horizon, TierHorizon::OldestRetained(_)));

        // Sender holds one OLD anon listing the receiver would prune.
        let mut sender = DirectoryStateV3::default();
        let old_key = key_of(999, 3);
        sender.listings.insert(old_key, fake_listing(None, old_key, 1));
        assert!(
            sender.delta(&summary).is_none(),
            "sender must not re-offer listings below the receiver's anon horizon"
        );

        // An attested listing is still offered (its tier is Open).
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut attested_sender = DirectoryStateV3::default();
        let akey = key_of(1, 4);
        attested_sender.listings.insert(akey, fake_listing(Some(&a.att), akey, 1));
        assert!(attested_sender.delta(&summary).is_some());
    }

    #[test]
    fn oversized_delta_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let delta: Vec<AuthorizedListingV3> = (0..(MAX_LISTINGS as u64 + 1))
            .map(|i| fake_listing(None, key_of(i, 0), i))
            .collect();
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(delta)).is_err());
    }

    #[test]
    fn scrub_future_removes_far_future_listings() {
        let mut s = DirectoryStateV3::default();
        let ok_key = [3u8; 32];
        let bad_key = [4u8; 32];
        s.listings.insert(ok_key, fake_listing(None, ok_key, 1_000));
        s.listings
            .insert(bad_key, fake_listing(None, bad_key, 1_000 + MAX_FUTURE_MS + 1));
        s.scrub_future(1_000);
        assert_eq!(s.listings.len(), 1);
        assert!(s.listings.contains_key(&ok_key));
    }

    /// Issue #45 directory substitution / stripping: the listing signature
    /// covers the attestation slot, so re-wrapping a victim's signed listing
    /// with `attestation: None` — or with a stranger's attestation — fails
    /// `check` outright.
    #[test]
    fn attestation_substitution_and_stripping_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let real = listing(&a, 5);

        // Stripped copy: signature no longer matches the payload.
        let stripped = AuthorizedListingV3 {
            listing: real.listing.clone(),
            signature: real.signature,
            attestation: None,
            pow_nonce: 0,
        };
        assert!(stripped.check(&authority.master_vk).is_err());
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(vec![stripped])).is_err());

        // Substituted copy: a stranger's attestation swapped in.
        let stranger = author(&authority);
        let substituted = AuthorizedListingV3 {
            listing: real.listing.clone(),
            signature: real.signature,
            attestation: Some(stranger.att.clone()),
            pow_nonce: 0,
        };
        assert!(substituted.check(&authority.master_vk).is_err());
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(vec![substituted.clone()])).is_err());

        // Full-state verify parity with the feed/inbox negative tests: a
        // fabricated state carrying the substituted listing must not verify.
        let mut fabricated = DirectoryStateV3::default();
        fabricated.listings.insert(a.key, substituted);
        assert!(fabricated.verify(&p).is_err());
    }

    /// Issue #45: an attestation minted over the author's key WITHOUT the
    /// author's cooperation (pop by the attacker) fails the listing check.
    #[test]
    fn nonconsensual_attestation_rejected_in_directory() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let (sk, key) = anon_author();
        let attacker_sk = SigningKey::generate(&mut OsRng);
        let forced = authority.mint_v2(
            TestAuthority::freebird_requestor(),
            &AttestationV2::payload_for(&sk.verifying_key()),
            &attacker_sk,
        );
        // Even if the AUTHOR's own key wraps it (the attacker can't, but be
        // strict): the attestation itself must fail verification.
        let l = AuthorizedListingV3::new(
            ListingV1 { author: key, last_active: 5 },
            &sk,
            Some(forced),
        );
        assert!(l.check(&authority.master_vk).is_err());
        let mut s = DirectoryStateV3::default();
        assert!(s.apply_delta(&p, &d(vec![l])).is_err());
    }

    /// Wire-format KAT (issue #47) for the listing signing payload.
    #[test]
    fn listing_signing_payload_kat() {
        let l = ListingV1 {
            author: [0xAB; 32],
            last_active: 0x0102030405060708,
        };
        assert_eq!(
            data_encoding::HEXLOWER.encode(&listing_signing_payload(&l, None)),
            "66726565626972642d6c697374696e672d7633abababababababababababababababababababababababababababababababab080706050403020100"
        );
    }

    /// An author who verifies upgrades their own listing: attested beats
    /// anon at equal time, and the author's NEWER publication always wins
    /// regardless of tier (their listing, their choice).
    #[test]
    fn anon_listing_upgrades_to_attested() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let anon_l = |t| anon_listing(&a.sk, a.key, t);
        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![anon_l(5)])).unwrap();
        s.apply_delta(&p, &d(vec![listing(&a, 5)])).unwrap(); // equal time: attested wins
        assert!(s.listings[&a.key].attestation.is_some());
        s.apply_delta(&p, &d(vec![anon_l(7)])).unwrap(); // newer self-publication wins
        assert!(s.listings[&a.key].is_anon());
        assert_eq!(s.listings[&a.key].listing.last_active, 7);
    }

    // ---- proof-of-work (issue #51) ----

    /// An anonymous listing with a missing/invalid stamp is dropped at
    /// admission and makes a fabricated full state fail verify.
    #[test]
    fn anon_without_valid_pow_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let (sk, key) = anon_author();
        // nonce 0 clears the 20-bit floor with probability 2^-20 — negligible.
        let bad = AuthorizedListingV3::new(
            ListingV1 { author: key, last_active: 5 },
            &sk,
            None,
        );
        assert_eq!(bad.pow_nonce, 0);

        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![bad.clone()])).expect("delta ok, listing dropped");
        assert!(s.listings.is_empty(), "unstamped anon listing must be dropped");

        let mut fabricated = DirectoryStateV3::default();
        fabricated.listings.insert(key, bad);
        assert!(fabricated.verify(&p).is_err(), "under-floor anon fails verify");
    }

    /// The ghost-key (attested) path skips PoW: an attested listing with no
    /// stamp is admitted and verifies.
    #[test]
    fn attested_skips_pow() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let l = listing(&a, 5);
        assert_eq!(l.pow_nonce, 0, "attested writes carry no stamp");
        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![l])).expect("attested admitted without PoW");
        assert_eq!(s.listings.len(), 1);
        s.verify(&p).expect("verifies");
    }

    /// A stamp solved for author A is worthless on author B's listing.
    #[test]
    fn pow_stamp_not_reusable_across_authors() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let (sk_a, key_a) = anon_author();
        let a_listing = anon_listing(&sk_a, key_a, 5);
        let harvested = a_listing.pow_nonce;

        let (sk_b, key_b) = anon_author();
        let mut b_listing = AuthorizedListingV3::new(
            ListingV1 { author: key_b, last_active: 5 },
            &sk_b,
            None,
        );
        b_listing.pow_nonce = harvested; // A's solve grafted onto B

        let mut s = DirectoryStateV3::default();
        s.apply_delta(&p, &d(vec![b_listing])).expect("delta ok");
        assert!(s.listings.is_empty(), "A's stamp must not admit B");
    }

    /// Difficulty sourced from the control cell: a publisher-signed record
    /// raises the admission bar, so a floor-only stamp is rejected while one
    /// solved to the control difficulty is accepted. (`test-publisher` feature
    /// makes the compiled publisher key a known test secret.)
    #[test]
    fn control_cell_difficulty_raises_bar() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let publisher = SigningKey::from_bytes(&freebird_pow::PUBLISHER_TEST_SECRET);
        let control = 22u8; // > POW_FLOOR_BITS (20)
        let record = SignedCellV1::new(
            &publisher,
            freebird_pow::POW_PURPOSE,
            1,
            freebird_pow::difficulty_body(control),
        );

        let (sk, key) = anon_author();
        // Floor-only solve is now under the control-cell bar → dropped.
        let weak = anon_listing(&sk, key, 5);
        let mut s = DirectoryStateV3::default();
        s.apply_delta(
            &p,
            &DirectoryDeltaV3 {
                listings: vec![weak],
                pow_difficulty: Some(record.clone()),
            },
        )
        .expect("delta ok");
        assert!(s.listings.is_empty(), "floor stamp rejected under raised difficulty");

        // Solved to the control difficulty → admitted.
        let strong = AuthorizedListingV3::new_anon(
            ListingV1 { author: key, last_active: 5 },
            &sk,
            control,
        );
        s.apply_delta(
            &p,
            &DirectoryDeltaV3 {
                listings: vec![strong],
                pow_difficulty: Some(record),
            },
        )
        .expect("delta ok");
        assert_eq!(s.listings.len(), 1, "control-difficulty stamp accepted");
    }

    /// Shrunken anon share (900 attested at the 1000 cap ⇒ effective anon
    /// share 100): the anon horizon must close below the oldest retained
    /// anon entry, and a held author's LWW upgrade must bypass the horizon.
    #[test]
    fn shrunken_anon_horizon_and_held_author_bypass() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut receiver = DirectoryStateV3::default();
        for i in 0..900u64 {
            let key = key_of(i, 1);
            receiver.listings.insert(key, fake_listing(Some(&a.att), key, i));
        }
        for i in 0..100u64 {
            let key = key_of(i, 2);
            receiver.listings.insert(key, fake_listing(None, key, 1000 + i));
        }
        receiver.canonicalize();
        assert_eq!(receiver.listings.len(), MAX_LISTINGS);
        let summary = receiver.summarize();
        assert!(
            matches!(summary.anon_horizon, TierHorizon::OldestRetained((t, _)) if t == 1000),
            "anon horizon must close at the shrunken share: {:?}",
            summary.anon_horizon
        );

        // NEW anon author below the horizon: not offered.
        let mut old_sender = DirectoryStateV3::default();
        let new_key = key_of(999, 3);
        old_sender.listings.insert(new_key, fake_listing(None, new_key, 1));
        assert!(old_sender.delta(&summary).is_none());

        // HELD anon author, newer copy whose order key TIES the horizon
        // exception path: offered despite the horizon (in-place LWW).
        let held_key = key_of(0, 2);
        let mut upgrader = DirectoryStateV3::default();
        upgrader.listings.insert(held_key, fake_listing(None, held_key, 5000));
        assert!(upgrader.delta(&summary).is_some());
    }

    /// The legacy decoder reads what the v1 contract stored: mandatory
    /// attestation, same field order.
    #[test]
    fn legacy_decode_and_check() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let att_v1 = authority.attest_v1(&a.sk.verifying_key());
        let l = legacy::LegacyAuthorizedListing {
            listing: ListingV1 {
                author: a.key,
                last_active: 5,
            },
            signature: {
                use ed25519_dalek::Signer;
                let bytes = freebird_core::to_cbor(&ListingV1 {
                    author: a.key,
                    last_active: 5,
                })
                .unwrap();
                a.sk.sign(&bytes)
            },
            attestation: att_v1,
        };
        let mut state = legacy::LegacyDirectoryState::default();
        state.listings.insert(a.key, l.clone());
        let bytes = freebird_core::to_cbor(&state).unwrap();
        let decoded: legacy::LegacyDirectoryState = freebird_core::from_cbor(&bytes).unwrap();
        assert_eq!(decoded, state);
        decoded.listings[&a.key]
            .check(&authority.master_vk)
            .expect("legacy listing checks");
    }
}
