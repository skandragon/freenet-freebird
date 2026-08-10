//! Public author directory (issue #11): ONE well-known contract for the whole
//! network. Params are a version seed + the ghostkey master key — no author
//! key — so every client derives the same address (doorbell pattern). Authors
//! opt in by publishing a signed, Ghost Key–attested listing; the Discover
//! tab reads the set. The attestation gate is the same trust rule as inbox
//! replies: your own feed is free, other people's attention costs a Ghost Key
//! — without it one keygen loop fills the cap.
//!
//! State types live HERE, not in freebird-core: adding a module to the shared
//! crate would change every deployed contract's wasm bytes and rotate all
//! derived addresses (the 2026-08-10 avatar incident). The UI depends on this
//! crate directly with default-features = false.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freebird_core::attestation::AttestationV1;
use freebird_core::feed::MAX_FUTURE_MS;
use serde::{Deserialize, Serialize};

/// Version seed baked into the params; rotating it deliberately mints a new
/// directory address (with a migration story), never as a rebuild side effect.
pub const DIRECTORY_SEED: &str = "freebird-directory-v1";

/// ponytail: single hot contract; ~1KB/listing (attestation chain) ≈ 1MB at
/// cap. Shard by author-key prefix if it ever fills.
pub const MAX_LISTINGS: usize = 1000;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct DirectoryParametersV1 {
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

/// Listing + signature by the author's posting key + the Ghost Key
/// attestation binding that posting key (the write gate).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedListing {
    pub listing: ListingV1,
    pub signature: Signature,
    pub attestation: AttestationV1,
}

impl AuthorizedListing {
    pub fn new(listing: ListingV1, sk: &SigningKey, attestation: AttestationV1) -> Self {
        use ed25519_dalek::Signer;
        let bytes = freebird_core::to_cbor(&listing).expect("listing serializes");
        Self {
            signature: sk.sign(&bytes),
            listing,
            attestation,
        }
    }

    /// Full validity: author key parses, signature verifies, attestation
    /// chain verifies and binds this posting key.
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

    /// Per-author LWW winner: max `(last_active, content hash)` — the hash
    /// breaks equal-time ties deterministically (e.g. re-minted attestation).
    pub fn lww_key(&self) -> (u64, [u8; 32]) {
        let bytes = freebird_core::to_cbor(self).expect("listing serializes");
        (self.listing.last_active, *blake3::hash(&bytes).as_bytes())
    }
}

/// Eviction/horizon order across authors: oldest `(last_active, author)` first.
pub type ListingOrderKey = (u64, [u8; 32]);

fn order_key(l: &AuthorizedListing) -> ListingOrderKey {
    (l.listing.last_active, l.listing.author)
}

/// See `feed::RetentionHorizon` for the derivation: a capped set at capacity
/// must advertise the oldest key it retains or peers re-offer pruned entries
/// forever.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub enum DirectoryHorizon {
    #[default]
    Open,
    OldestRetained(ListingOrderKey),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct DirectorySummaryV1 {
    /// author → per-author LWW key held (BTreeMap: canonical summary bytes).
    pub entries: BTreeMap<[u8; 32], (u64, [u8; 32])>,
    pub horizon: DirectoryHorizon,
}

pub type DirectoryDeltaV1 = Vec<AuthorizedListing>;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct DirectoryStateV1 {
    /// One listing per author, keyed by posting key.
    pub listings: BTreeMap<[u8; 32], AuthorizedListing>,
}

impl DirectoryStateV1 {
    pub fn verify(&self, parameters: &DirectoryParametersV1) -> Result<(), String> {
        if self.listings.len() > MAX_LISTINGS {
            return Err(format!("more than {MAX_LISTINGS} listings"));
        }
        for (key, l) in &self.listings {
            if key != &l.listing.author {
                return Err("listing stored under wrong author key".into());
            }
            l.check(&parameters.ghostkey_master)?;
        }
        Ok(())
    }

    /// Evict oldest `(last_active, author)` beyond the cap. Idempotent.
    pub fn canonicalize(&mut self) {
        while self.listings.len() > MAX_LISTINGS {
            let oldest = self
                .listings
                .values()
                .map(order_key)
                .min()
                .expect("non-empty over cap");
            self.listings.remove(&oldest.1);
        }
    }

    /// Clock-dependent scrub, called by the contract shell only (host clock
    /// lives there, never inside the pure merge).
    pub fn scrub_future(&mut self, now_ms: u64) {
        self.listings
            .retain(|_, l| l.listing.last_active <= now_ms.saturating_add(MAX_FUTURE_MS));
    }

    fn horizon(&self) -> DirectoryHorizon {
        if self.listings.len() < MAX_LISTINGS {
            DirectoryHorizon::Open
        } else {
            DirectoryHorizon::OldestRetained(
                self.listings.values().map(order_key).min().expect("at cap"),
            )
        }
    }

    pub fn summarize(&self) -> DirectorySummaryV1 {
        DirectorySummaryV1 {
            entries: self
                .listings
                .iter()
                .map(|(k, l)| (*k, l.lww_key()))
                .collect(),
            horizon: self.horizon(),
        }
    }

    /// Listings the peer lacks (or holds older), and would retain.
    pub fn delta(&self, theirs: &DirectorySummaryV1) -> Option<DirectoryDeltaV1> {
        let delta: Vec<AuthorizedListing> = self
            .listings
            .values()
            .filter(|l| match theirs.entries.get(&l.listing.author) {
                None => true,
                Some(held) => l.lww_key() > *held,
            })
            .filter(|l| match &theirs.horizon {
                DirectoryHorizon::Open => true,
                DirectoryHorizon::OldestRetained(oldest) => order_key(l) > *oldest,
            })
            .cloned()
            .collect();
        (!delta.is_empty()).then_some(delta)
    }

    /// Verify and merge incoming listings: newer per author wins, then cap.
    pub fn apply_delta(
        &mut self,
        parameters: &DirectoryParametersV1,
        delta: &[AuthorizedListing],
    ) -> Result<(), String> {
        // Bound the work one delta can demand: each listing costs an RSA
        // chain verification inside wasm.
        if delta.len() > MAX_LISTINGS {
            return Err("listing delta too large".into());
        }
        for l in delta {
            l.check(&parameters.ghostkey_master)?;
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

    /// Full-state merge = apply the other side's listings as a delta.
    pub fn merge(
        &mut self,
        parameters: &DirectoryParametersV1,
        other: &DirectoryStateV1,
    ) -> Result<(), String> {
        let entries: Vec<AuthorizedListing> = other.listings.values().cloned().collect();
        self.apply_delta(parameters, &entries)
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
    fn scrub_delta(delta: &mut DirectoryDeltaV1, now: u64) {
        delta.retain(|l| l.listing.last_active <= now.saturating_add(MAX_FUTURE_MS));
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
            let dir: DirectoryStateV1 = deser(bytes, "state")?;
            let parameters: DirectoryParametersV1 = deser(parameters.as_ref(), "parameters")?;

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
            let parameters: DirectoryParametersV1 = deser(parameters.as_ref(), "parameters")?;
            let mut dir: DirectoryStateV1 = if state.as_ref().is_empty() {
                DirectoryStateV1::default()
            } else {
                deser(state.as_ref(), "state")?
            };
            let now = now_ms();
            dir.scrub_future(now);

            for update in data {
                match update {
                    UpdateData::State(new_state) => {
                        let mut incoming: DirectoryStateV1 =
                            deser(new_state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        dir.merge(&parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::Delta(d) => {
                        if d.as_ref().is_empty() {
                            continue;
                        }
                        let mut delta: DirectoryDeltaV1 = deser(d.as_ref(), "delta")?;
                        scrub_delta(&mut delta, now);
                        dir.apply_delta(&parameters, &delta)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::StateAndDelta { state, delta } => {
                        let mut incoming: DirectoryStateV1 =
                            deser(state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        dir.merge(&parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                        if !delta.as_ref().is_empty() {
                            let mut delta: DirectoryDeltaV1 = deser(delta.as_ref(), "delta")?;
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
            let dir: DirectoryStateV1 = deser(bytes, "state")?;
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
            let dir: DirectoryStateV1 = deser(state.as_ref(), "state")?;
            // Zero-byte summary = "peer has nothing" (summarize of empty
            // state emits it); parsing it as CBOR would abort the sync.
            let summary: DirectorySummaryV1 = if summary.as_ref().is_empty() {
                DirectorySummaryV1::default()
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
        att: AttestationV1,
    }

    fn author(authority: &TestAuthority) -> Author {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Author {
            key: vk.to_bytes(),
            att: authority.attest(&vk),
            sk,
        }
    }

    fn params(authority: &TestAuthority) -> DirectoryParametersV1 {
        DirectoryParametersV1 {
            seed: DIRECTORY_SEED.into(),
            ghostkey_master: authority.master_vk,
        }
    }

    fn listing(a: &Author, time: u64) -> AuthorizedListing {
        AuthorizedListing::new(
            ListingV1 {
                author: a.key,
                last_active: time,
            },
            &a.sk,
            a.att.clone(),
        )
    }

    /// Structurally valid, never verified — for cap/horizon tests where
    /// minting one real attestation per author would take minutes.
    fn fake_listing(att: &AttestationV1, author: [u8; 32], time: u64) -> AuthorizedListing {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        AuthorizedListing::new(
            ListingV1 {
                author,
                last_active: time,
            },
            &sk,
            att.clone(),
        )
    }

    #[test]
    fn attested_listing_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let mut s = DirectoryStateV1::default();
        s.apply_delta(&p, &[listing(&a, 5)]).expect("apply ok");
        assert_eq!(s.listings.len(), 1);
        s.verify(&p).expect("verifies");
    }

    #[test]
    fn wrong_master_attestation_rejected() {
        let authority = TestAuthority::new();
        let rogue = TestAuthority::new();
        let p = params(&authority);
        let a = author(&rogue); // attested under the wrong master
        let mut s = DirectoryStateV1::default();
        assert!(s.apply_delta(&p, &[listing(&a, 5)]).is_err());
    }

    #[test]
    fn forged_signature_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let other = SigningKey::generate(&mut OsRng);
        // Claims a's identity but signed by another key.
        let forged = AuthorizedListing::new(
            ListingV1 {
                author: a.key,
                last_active: 5,
            },
            &other,
            a.att.clone(),
        );
        let mut s = DirectoryStateV1::default();
        assert!(s.apply_delta(&p, &[forged]).is_err());
    }

    #[test]
    fn lww_newer_wins_stale_noop() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let mut s = DirectoryStateV1::default();
        s.apply_delta(&p, &[listing(&a, 5)]).unwrap();
        s.apply_delta(&p, &[listing(&a, 3)]).unwrap(); // stale: no-op
        assert_eq!(s.listings[&a.key].listing.last_active, 5);
        s.apply_delta(&p, &[listing(&a, 7)]).unwrap(); // newer: wins
        assert_eq!(s.listings[&a.key].listing.last_active, 7);
        assert_eq!(s.listings.len(), 1);
    }

    #[test]
    fn cap_evicts_oldest_last_active() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut s = DirectoryStateV1::default();
        for i in 0..(MAX_LISTINGS as u64 + 5) {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&i.to_be_bytes());
            let l = fake_listing(&a.att, key, i);
            s.listings.insert(key, l);
        }
        s.canonicalize();
        assert_eq!(s.listings.len(), MAX_LISTINGS);
        // The 5 oldest last_active entries are gone; the newest survive.
        let min = s
            .listings
            .values()
            .map(|l| l.listing.last_active)
            .min()
            .unwrap();
        assert_eq!(min, 5);
    }

    #[test]
    fn horizon_prevents_reoffer_of_pruned_listings() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        // Receiver at capacity with entries newer than everything the
        // sender could offer.
        let mut receiver = DirectoryStateV1::default();
        for i in 0..MAX_LISTINGS as u64 {
            let mut key = [1u8; 32];
            key[..8].copy_from_slice(&i.to_be_bytes());
            receiver.listings.insert(key, fake_listing(&a.att, key, 1000 + i));
        }
        // Sender holds one old listing the receiver would immediately prune.
        let mut sender = DirectoryStateV1::default();
        let old_key = [2u8; 32];
        sender.listings.insert(old_key, fake_listing(&a.att, old_key, 1));

        let summary = receiver.summarize();
        assert!(matches!(summary.horizon, DirectoryHorizon::OldestRetained(_)));
        assert!(
            sender.delta(&summary).is_none(),
            "sender must not re-offer listings below the receiver's horizon"
        );
    }

    #[test]
    fn oversized_delta_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let a = author(&authority);
        let delta: Vec<AuthorizedListing> = (0..(MAX_LISTINGS as u64 + 1))
            .map(|i| {
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&i.to_be_bytes());
                fake_listing(&a.att, key, i)
            })
            .collect();
        let mut s = DirectoryStateV1::default();
        assert!(s.apply_delta(&p, &delta).is_err());
    }

    #[test]
    fn scrub_future_removes_far_future_listings() {
        let authority = TestAuthority::new();
        let a = author(&authority);
        let mut s = DirectoryStateV1::default();
        let ok_key = [3u8; 32];
        let bad_key = [4u8; 32];
        s.listings.insert(ok_key, fake_listing(&a.att, ok_key, 1_000));
        s.listings
            .insert(bad_key, fake_listing(&a.att, bad_key, 1_000 + MAX_FUTURE_MS + 1));
        s.scrub_future(1_000);
        assert_eq!(s.listings.len(), 1);
        assert!(s.listings.contains_key(&ok_key));
    }
}
