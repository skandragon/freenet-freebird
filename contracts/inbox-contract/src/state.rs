//! Inbox v2 (issue #23): two-tier reply inbox with anonymous parity.
//!
//! V1 (in `freebird-core::inbox`, byte-frozen with the rest of that crate)
//! used the Ghost Key attestation as the write gate: no checkmark, no
//! pointer. V2 replaces the gate with a slot POLICY — everything is still
//! signed by the posting key (the attestation never carried authenticity),
//! but now unattested credentials are accepted and fingerprinted by
//! `blake3(posting_key)`:
//!
//! - Attested writers keep the v1 fairness cap (MAX_PER_FINGERPRINT per
//!   Ghost Key purchase) and may fill every one of the MAX_POINTERS slots.
//! - Anonymous writers share a bounded remainder (ANON_POINTER_SLOTS) with a
//!   low per-key cap (MAX_PER_ANON_KEY — keygen is free, so per-key means
//!   per-sybil; the share cap is what actually bounds a keygen flood).
//! - Eviction is tiered: anonymous pointers evict each other (deterministic
//!   `(time, reply_post)` order) but NEVER an attested one; attested
//!   pointers evict anonymous ones at the global cap. The checkmark's
//!   functional meaning becomes "durable, uncrowdable presence".
//!
//! Credentials remain keyed by POSTING key, and the same delta/summary
//! horizon discipline as v1 applies, per tier (see `TierHorizon`).

use freenet_scaffold_macro::composable;

pub use inbox_v2_components::*;

pub const MAX_POINTERS: usize = 300;
/// Slots anonymous pointers may occupy at most (attested writers may use all
/// MAX_POINTERS; anonymous never grow past this share).
pub const ANON_POINTER_SLOTS: usize = 100;
pub const MAX_PER_FINGERPRINT: usize = 8;
pub const MAX_PER_ANON_KEY: usize = 3;

/// Namespace prefix for anonymous fingerprints. Attested fingerprints are
/// bs58 (ghostkeys convention, no colon), so the tiers can never collide;
/// `verify`/`apply` enforce `pointer.fingerprint == cred.fingerprint()`, so
/// the prefix cannot be spoofed to switch tiers.
pub const ANON_FP_PREFIX: &str = "anon:";

/// Anonymous fairness-cap group: the full posting-key hash. A truncated hash
/// would make targeted collisions (joining a stranger's cap group to eat
/// their slots) borderline feasible.
pub fn anon_fingerprint(posting_key: &[u8; 32]) -> String {
    format!(
        "{ANON_FP_PREFIX}{}",
        bs58::encode(blake3::hash(posting_key).as_bytes()).into_string()
    )
}

pub fn is_anon_fingerprint(fp: &str) -> bool {
    fp.starts_with(ANON_FP_PREFIX)
}

/// Inbox v2 state. Field order is load-bearing: creds must apply before
/// pointers so a single delta carrying both validates its own pointers.
#[composable(post_apply_delta = "post_apply_cleanup")]
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct InboxStateV2 {
    pub creds: CredsV2,
    pub pointers: PointersV2,
}

impl InboxStateV2 {
    /// Idempotent: enforce caps and drop credentials no pointer references.
    ///
    /// Also drops pointers whose fingerprint no longer matches their
    /// credential: an anonymous cred upgrading to attested (same posting
    /// key, new fingerprint) is a NORMAL flow in v2, and replicas that saw
    /// the upgrade and the old pointers in different orders must converge on
    /// "stale pointers gone".
    pub fn post_apply_cleanup(
        &mut self,
        _parameters: &InboxParametersV2,
    ) -> Result<(), String> {
        let creds = &self.creds.creds;
        self.pointers.pointers.retain(|p| {
            creds
                .get(&p.ptr.replier)
                .is_some_and(|c| c.fingerprint() == p.ptr.fingerprint)
        });
        self.pointers.canonicalize();
        let referenced: std::collections::BTreeSet<[u8; 32]> = self
            .pointers
            .pointers
            .iter()
            .map(|p| p.ptr.replier)
            .collect();
        self.creds.creds.retain(|k, _| referenced.contains(k));
        Ok(())
    }

    /// Clock-dependent scrub, called by the contract shell only.
    pub fn scrub_future(&mut self, now_ms: u64) {
        self.pointers.pointers.retain(|p| {
            p.ptr.time <= now_ms.saturating_add(freebird_core::feed::MAX_FUTURE_MS)
        });
    }
}

mod inbox_v2_components {
    use ed25519_dalek::{Signature, VerifyingKey};
    use freebird_core::attestation::AttestationV1;
    use freebird_core::types::PostId;
    use freenet_scaffold::ComposableState;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        anon_fingerprint, is_anon_fingerprint, InboxStateV2, ANON_POINTER_SLOTS,
        MAX_PER_ANON_KEY, MAX_PER_FINGERPRINT, MAX_POINTERS,
    };

    /// CBOR-identical shape to the v1 params (owner + trust anchor); a
    /// distinct type because the two schemas must never be conflated in code.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct InboxParametersV2 {
        /// The inbox owner's posting key — only used to derive the address.
        pub owner: VerifyingKey,
        /// Ghost Key trust anchor; see `FeedParametersV1::ghostkey_master`.
        pub ghostkey_master: VerifyingKey,
    }

    /// A replier's credential. `attestation: None` = anonymous tier.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct ReplierCredV2 {
        pub posting_key: VerifyingKey,
        pub attestation: Option<AttestationV1>,
    }

    impl ReplierCredV2 {
        fn check(&self, map_key: &[u8; 32], master: &VerifyingKey) -> Result<(), String> {
            if self.posting_key.as_bytes() != map_key {
                return Err("credential stored under wrong posting key".into());
            }
            if let Some(att) = &self.attestation {
                att.verify(&self.posting_key, Some(master))
                    .map_err(|e| format!("replier credential invalid: {e}"))?;
            }
            Ok(())
        }

        pub fn fingerprint(&self) -> String {
            match &self.attestation {
                Some(att) => att.fingerprint(),
                None => anon_fingerprint(self.posting_key.as_bytes()),
            }
        }

        /// LWW order for one posting key: attested content hash, with the
        /// anonymous cred hashing as all-zeroes so an attestation always
        /// upgrades an anonymous cred in place and never the reverse.
        pub fn content_hash(&self) -> [u8; 32] {
            match &self.attestation {
                Some(att) => att.content_hash(),
                None => [0u8; 32],
            }
        }
    }

    // ---- creds: map keyed by posting key; LWW per entry by content hash ----

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct CredsV2 {
        pub creds: BTreeMap<[u8; 32], ReplierCredV2>,
    }

    impl ComposableState for CredsV2 {
        type ParentState = InboxStateV2;
        /// posting key → cred content hash: peers holding DIFFERENT creds
        /// for one key must look different, or they never reconcile.
        type Summary = BTreeMap<[u8; 32], [u8; 32]>;
        type Delta = BTreeMap<[u8; 32], ReplierCredV2>;
        type Parameters = InboxParametersV2;

        fn verify(
            &self,
            parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            if self.creds.len() > MAX_POINTERS {
                return Err("more credentials than pointers can reference".into());
            }
            // A cred no pointer references would be pruned by
            // post_apply_cleanup: accepting it caches a state that is not a
            // cleanup fixpoint, and its holder re-offers the pruned creds
            // forever (issue #49). Reject BEFORE the RSA check — each
            // attested cred costs a chain verification in wasm.
            let referenced: BTreeSet<[u8; 32]> =
                parent.pointers.pointers.iter().map(|p| p.ptr.replier).collect();
            for (key, cred) in &self.creds {
                if !referenced.contains(key) {
                    return Err("credential referenced by no pointer".into());
                }
                cred.check(key, &parameters.ghostkey_master)?;
            }
            Ok(())
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            self.creds
                .iter()
                .map(|(k, c)| (*k, c.content_hash()))
                .collect()
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let delta: BTreeMap<[u8; 32], ReplierCredV2> = self
                .creds
                .iter()
                .filter(|(k, c)| {
                    match old_summary.get(*k) {
                        None => true,
                        // Deterministic winner: max content hash.
                        Some(theirs) => c.content_hash() > *theirs,
                    }
                })
                .map(|(k, c)| (*k, c.clone()))
                .collect();
            (!delta.is_empty()).then_some(delta)
        }

        fn apply_delta(
            &mut self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(delta) = delta else { return Ok(()) };
            // Bound the work one delta can demand: each attested cred costs
            // an RSA chain verification inside wasm.
            if delta.len() > MAX_POINTERS {
                return Err("credential delta too large".into());
            }
            for (key, cred) in delta {
                cred.check(key, &parameters.ghostkey_master)?;
                match self.creds.get(key) {
                    Some(existing) if existing.content_hash() >= cred.content_hash() => {}
                    _ => {
                        self.creds.insert(*key, cred.clone());
                    }
                }
            }
            Ok(())
        }
    }

    // ---- pointers: capped log, tiered caps and eviction ----

    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub struct ReplyPointerV2 {
        /// The replier's posting key; must resolve in `creds`.
        pub replier: [u8; 32],
        /// Fairness-cap group: the credential's fingerprint (ghost key
        /// fingerprint, or `anon:`-prefixed posting-key hash). Must equal
        /// `creds[replier].fingerprint()`.
        pub fingerprint: String,
        /// The post in the inbox owner's feed being replied to.
        pub target_post: PostId,
        /// The reply post in the REPLIER's feed.
        pub reply_post: PostId,
        pub time: u64,
    }

    /// Pointer + signature by the replier's POSTING key.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct AuthorizedReplyPointerV2 {
        pub ptr: ReplyPointerV2,
        pub signature: Signature,
    }

    impl AuthorizedReplyPointerV2 {
        pub fn new(ptr: ReplyPointerV2, signing_key: &ed25519_dalek::SigningKey) -> Self {
            use ed25519_dalek::Signer;
            let bytes = freebird_core::to_cbor(&ptr).expect("pointer serializes");
            Self {
                signature: signing_key.sign(&bytes),
                ptr,
            }
        }

        pub fn verify_signature(&self, posting_key: &VerifyingKey) -> Result<(), String> {
            let bytes = freebird_core::to_cbor(&self.ptr)?;
            posting_key
                .verify_strict(&bytes, &self.signature)
                .map_err(|e| format!("pointer signature invalid: {e}"))
        }

        fn is_anon(&self) -> bool {
            is_anon_fingerprint(&self.ptr.fingerprint)
        }
    }

    pub type PointerOrderKey = (u64, PostId);

    fn order_key(p: &AuthorizedReplyPointerV2) -> PointerOrderKey {
        (p.ptr.time, p.ptr.reply_post)
    }

    fn fp_cap(fp: &str) -> usize {
        if is_anon_fingerprint(fp) {
            MAX_PER_ANON_KEY
        } else {
            MAX_PER_FINGERPRINT
        }
    }

    /// Check a pointer against the credential map of the (in-progress)
    /// state. A missing cred OR a fingerprint mismatch drops the pointer
    /// rather than failing the delta: the mismatch happens honestly when a
    /// posting key's cred upgrades anon→attested while old pointers are
    /// still circulating, and an honest peer's delta must never be
    /// poison-pilled by it. Only a bad signature is fatal.
    fn check_pointer(
        p: &AuthorizedReplyPointerV2,
        creds: &BTreeMap<[u8; 32], ReplierCredV2>,
    ) -> Result<bool, String> {
        let Some(cred) = creds.get(&p.ptr.replier) else {
            return Ok(false);
        };
        p.verify_signature(&cred.posting_key)?;
        Ok(p.ptr.fingerprint == cred.fingerprint())
    }

    /// Per-tier retention horizon. Same livelock rationale as v1's
    /// `RetentionHorizon`, split by tier because the tiers evict
    /// independently. `Closed` = this tier retains nothing and accepts
    /// nothing (attested writers hold every slot) — without it a sender
    /// re-offers anonymous pointers forever to a receiver that can never
    /// keep one.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
    pub enum TierHorizon {
        #[default]
        Open,
        OldestRetained(PointerOrderKey),
        Closed,
    }

    impl TierHorizon {
        fn admits(&self, key: PointerOrderKey) -> bool {
            match self {
                TierHorizon::Open => true,
                TierHorizon::OldestRetained(oldest) => key > *oldest,
                TierHorizon::Closed => false,
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct PointersV2Summary {
        pub ids: BTreeSet<PostId>,
        pub attested_horizon: TierHorizon,
        pub anon_horizon: TierHorizon,
        /// Per-fingerprint retention: for every fingerprint AT its tier cap,
        /// the oldest key retained for it (see v1 for the livelock class
        /// this prevents).
        pub fp_horizons: BTreeMap<String, PointerOrderKey>,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct PointersV2 {
        /// Sorted ascending by `(time, reply_post)`.
        pub pointers: Vec<AuthorizedReplyPointerV2>,
    }

    impl PointersV2 {
        /// Sort, dedupe, then enforce the tiered caps. Idempotent, and a pure
        /// function of the pointer SET — merge order cannot change the
        /// outcome.
        ///
        /// 1. per-fingerprint cap (newest kept; 8 attested / 3 anonymous)
        /// 2. anonymous share cap (newest ANON_POINTER_SLOTS anon kept)
        /// 3. global cap: evict the oldest ANONYMOUS pointer first; only
        ///    when none remain, the oldest attested. Verified is never
        ///    crowded out by anonymous.
        pub fn canonicalize(&mut self) {
            self.pointers.sort_by_key(order_key);
            // Set-based dedup, NOT dedup_by_key: the sort is by (time,
            // reply_post), so equal reply_posts with different times are not
            // adjacent — adjacency-only dedup would let a free anonymous key
            // craft a state that apply accepts and verify rejects
            // ("duplicate reply pointer"), bricking the inbox. Keeping the
            // lowest order key is the deterministic winner.
            let mut seen = BTreeSet::new();
            self.pointers.retain(|p| seen.insert(p.ptr.reply_post));

            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            let mut keep: Vec<bool> = vec![false; self.pointers.len()];
            for (i, p) in self.pointers.iter().enumerate().rev() {
                let c = counts.entry(p.ptr.fingerprint.clone()).or_insert(0);
                if *c < fp_cap(&p.ptr.fingerprint) {
                    *c += 1;
                    keep[i] = true;
                }
            }
            let mut it = keep.iter();
            self.pointers.retain(|_| *it.next().unwrap());

            let anon_count = self.pointers.iter().filter(|p| p.is_anon()).count();
            if anon_count > ANON_POINTER_SLOTS {
                let mut drop = anon_count - ANON_POINTER_SLOTS;
                // retain scans ascending: drops the OLDEST anon first.
                self.pointers.retain(|p| {
                    if drop > 0 && p.is_anon() {
                        drop -= 1;
                        false
                    } else {
                        true
                    }
                });
            }

            while self.pointers.len() > MAX_POINTERS {
                let victim = self
                    .pointers
                    .iter()
                    .position(|p| p.is_anon())
                    .unwrap_or(0); // no anon left: oldest attested
                self.pointers.remove(victim);
            }
        }

        fn tier_horizons(&self) -> (TierHorizon, TierHorizon) {
            let attested: Vec<PointerOrderKey> = self
                .pointers
                .iter()
                .filter(|p| !p.is_anon())
                .map(order_key)
                .collect();
            let anon: Vec<PointerOrderKey> = self
                .pointers
                .iter()
                .filter(|p| p.is_anon())
                .map(order_key)
                .collect();

            let attested_h = if attested.len() >= MAX_POINTERS {
                TierHorizon::OldestRetained(attested[0])
            } else {
                TierHorizon::Open
            };
            // How many anon slots exist RIGHT NOW: the share cap, shrunk by
            // however far attested writers reach past their reserved
            // majority.
            let effective = ANON_POINTER_SLOTS.min(MAX_POINTERS.saturating_sub(attested.len()));
            let anon_h = if effective == 0 {
                TierHorizon::Closed
            } else if anon.len() >= effective {
                TierHorizon::OldestRetained(anon[0])
            } else {
                TierHorizon::Open
            };
            (attested_h, anon_h)
        }

        fn fp_horizons(&self) -> BTreeMap<String, PointerOrderKey> {
            let mut groups: BTreeMap<String, Vec<PointerOrderKey>> = BTreeMap::new();
            for p in &self.pointers {
                groups
                    .entry(p.ptr.fingerprint.clone())
                    .or_default()
                    .push(order_key(p));
            }
            groups
                .into_iter()
                .filter(|(fp, keys)| keys.len() >= fp_cap(fp))
                .map(|(fp, keys)| {
                    let oldest = keys.iter().min().cloned().expect("non-empty group");
                    (fp, oldest)
                })
                .collect()
        }
    }

    impl ComposableState for PointersV2 {
        type ParentState = InboxStateV2;
        type Summary = PointersV2Summary;
        type Delta = Vec<AuthorizedReplyPointerV2>;
        type Parameters = InboxParametersV2;

        fn verify(
            &self,
            parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Result<(), String> {
            if self.pointers.len() > MAX_POINTERS {
                return Err(format!("more than {MAX_POINTERS} pointers"));
            }
            let anon_count = self.pointers.iter().filter(|p| p.is_anon()).count();
            if anon_count > ANON_POINTER_SLOTS {
                return Err(format!(
                    "more than {ANON_POINTER_SLOTS} anonymous pointers"
                ));
            }
            // The fairness caps are load-bearing in the two-tier design: a
            // fabricated full state must not seat one sybil across the whole
            // anonymous share (canonicalize would only heal it on the NEXT
            // update).
            let mut per_fp: BTreeMap<&str, usize> = BTreeMap::new();
            for p in &self.pointers {
                let c = per_fp.entry(p.ptr.fingerprint.as_str()).or_insert(0);
                *c += 1;
                if *c > fp_cap(&p.ptr.fingerprint) {
                    return Err("fingerprint over its fairness cap".into());
                }
            }
            for pair in self.pointers.windows(2) {
                if order_key(&pair[0]) > order_key(&pair[1]) {
                    return Err("pointers not sorted".into());
                }
            }
            let mut seen = BTreeSet::new();
            for p in &self.pointers {
                if !check_pointer(p, &parent.creds.creds)? {
                    return Err("pointer without matching credential".into());
                }
                if !seen.insert(p.ptr.reply_post) {
                    return Err("duplicate reply pointer".into());
                }
            }
            Ok(())
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            let (attested_horizon, anon_horizon) = self.tier_horizons();
            PointersV2Summary {
                ids: self.pointers.iter().map(|p| p.ptr.reply_post).collect(),
                attested_horizon,
                anon_horizon,
                fp_horizons: self.fp_horizons(),
            }
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let retained = |p: &AuthorizedReplyPointerV2| {
                let tier = if p.is_anon() {
                    &old_summary.anon_horizon
                } else {
                    &old_summary.attested_horizon
                };
                let above_fp = match old_summary.fp_horizons.get(&p.ptr.fingerprint) {
                    None => true,
                    Some(oldest) => order_key(p) > *oldest,
                };
                tier.admits(order_key(p)) && above_fp
            };
            let delta: Vec<AuthorizedReplyPointerV2> = self
                .pointers
                .iter()
                .filter(|p| !old_summary.ids.contains(&p.ptr.reply_post))
                .filter(|p| retained(p))
                .cloned()
                .collect();
            (!delta.is_empty()).then_some(delta)
        }

        fn apply_delta(
            &mut self,
            parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(delta) = delta else { return Ok(()) };
            // parent here is the in-progress state: the macro applies creds
            // first (field order), so a self-contained delta's creds are
            // visible. Pointers with no credential are dropped, not fatal.
            let mut accepted: Vec<AuthorizedReplyPointerV2> = Vec::new();
            for p in delta {
                if check_pointer(p, &parent.creds.creds)? {
                    accepted.push(p.clone());
                }
            }
            self.pointers.extend(accepted);
            self.canonicalize();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey};
    use freebird_core::attestation::fixtures::TestAuthority;
    use freebird_core::types::PostId;
    use freenet_scaffold::ComposableState;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    struct Replier {
        sk: SigningKey,
        cred: ReplierCredV2,
        key: [u8; 32],
    }

    fn attested_replier(authority: &TestAuthority) -> Replier {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let attestation = authority.attest(&vk);
        Replier {
            key: vk.to_bytes(),
            cred: ReplierCredV2 {
                posting_key: vk,
                attestation: Some(attestation),
            },
            sk,
        }
    }

    fn anon_replier() -> Replier {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Replier {
            key: vk.to_bytes(),
            cred: ReplierCredV2 {
                posting_key: vk,
                attestation: None,
            },
            sk,
        }
    }

    fn params(authority: &TestAuthority) -> InboxParametersV2 {
        InboxParametersV2 {
            owner: SigningKey::generate(&mut OsRng).verifying_key(),
            ghostkey_master: authority.master_vk,
        }
    }

    fn pointer(r: &Replier, time: u64, tag: u64) -> AuthorizedReplyPointerV2 {
        let ptr = ReplyPointerV2 {
            replier: r.key,
            fingerprint: r.cred.fingerprint(),
            target_post: PostId([1u8; 16]),
            reply_post: PostId::compute(&r.sk.verifying_key(), time, &format!("r{tag}"), &None),
            time,
        };
        AuthorizedReplyPointerV2::new(ptr, &r.sk)
    }

    fn delta_of(
        creds: Vec<&Replier>,
        pointers: Vec<AuthorizedReplyPointerV2>,
    ) -> Option<InboxStateV2Delta> {
        let creds_map: std::collections::BTreeMap<[u8; 32], ReplierCredV2> = creds
            .into_iter()
            .map(|r| (r.key, r.cred.clone()))
            .collect();
        Some(InboxStateV2Delta {
            creds: (!creds_map.is_empty()).then_some(creds_map),
            pointers: (!pointers.is_empty()).then_some(pointers),
        })
    }

    fn apply(state: &mut InboxStateV2, p: &InboxParametersV2, delta: Option<InboxStateV2Delta>) {
        let clone = state.clone();
        state.apply_delta(&clone, p, &delta).expect("apply ok");
    }

    // ---- crypto path ----

    #[test]
    fn anon_pointer_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer(&r, 5, 0)]));
        assert_eq!(s.pointers.pointers.len(), 1);
        assert!(is_anon_fingerprint(&s.pointers.pointers[0].ptr.fingerprint));
        s.verify(&s.clone(), &p).expect("verifies");
    }

    #[test]
    fn attested_pointer_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&authority);
        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer(&r, 5, 0)]));
        assert_eq!(s.pointers.pointers.len(), 1);
        s.verify(&s.clone(), &p).expect("verifies");
    }

    #[test]
    fn pointer_without_cred_is_dropped() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![], vec![pointer(&r, 5, 0)]));
        assert!(s.pointers.pointers.is_empty());
    }

    #[test]
    fn cred_with_bad_attestation_rejected() {
        let authority = TestAuthority::new();
        let rogue_authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&rogue_authority); // wrong master
        let mut s = InboxStateV2::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![pointer(&r, 5, 0)]))
            .is_err());
    }

    #[test]
    fn forged_pointer_signature_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let other = anon_replier();
        let mut s = InboxStateV2::default();
        // Pointer claims r's identity but is signed by other's key.
        let mut fake = pointer(&other, 5, 0);
        fake.ptr.replier = r.key;
        fake.ptr.fingerprint = r.cred.fingerprint();
        let fake = AuthorizedReplyPointerV2::new(fake.ptr, &other.sk);
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![fake]))
            .is_err());
    }

    /// An anonymous key must not be able to claim an attested-style
    /// fingerprint (or any fingerprint other than its own hash): the
    /// pointer is dropped, and a fabricated full state carrying one is
    /// invalid.
    #[test]
    fn wrong_tier_fingerprint_dropped() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut forged = pointer(&r, 5, 0);
        forged.ptr.fingerprint = "NotMyHash".into(); // unprefixed = attested tier
        let forged = AuthorizedReplyPointerV2::new(forged.ptr, &r.sk);
        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![forged.clone()]));
        assert!(s.pointers.pointers.is_empty(), "forged-tier pointer dropped");

        // A full state holding a mismatched fingerprint must not verify.
        let mut fabricated = InboxStateV2::default();
        fabricated.creds.creds.insert(r.key, r.cred.clone());
        fabricated.pointers.pointers.push(forged);
        assert!(fabricated.verify(&fabricated.clone(), &p).is_err());
    }

    /// One Ghost Key attesting a SECOND posting key must not orphan pointers
    /// from the first (v1 regression, still holds in v2).
    #[test]
    fn same_ghostkey_second_posting_key_does_not_brick_inbox() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r1 = attested_replier(&authority);
        let r2 = attested_replier(&authority);

        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&r1], vec![pointer(&r1, 5, 0)]));
        s.verify(&s.clone(), &p).expect("valid after first reply");

        apply(&mut s, &p, delta_of(vec![&r2], vec![]));
        apply(&mut s, &p, delta_of(vec![&r2], vec![pointer(&r2, 6, 1)]));

        s.verify(&s.clone(), &p)
            .expect("old pointers must still verify after another cred arrives");
        assert_eq!(s.pointers.pointers.len(), 2);
    }

    /// The same posting key verifying later: the attested cred must replace
    /// the anonymous one deterministically (never the reverse), and the
    /// key's old anonymous pointers drop (their fingerprint no longer
    /// matches) rather than brick the state.
    #[test]
    fn attested_cred_beats_anon_cred_for_same_key() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let anon = anon_replier();
        let attested = Replier {
            cred: ReplierCredV2 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk.verifying_key())),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };

        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&anon], vec![pointer(&anon, 5, 0)]));
        apply(
            &mut s,
            &p,
            delta_of(vec![&attested], vec![pointer(&attested, 6, 1)]),
        );
        assert!(s.creds.creds[&anon.key].attestation.is_some());
        // The anon-fingerprint pointer is orphaned by the upgrade; the
        // attested pointer survives and the state stays valid.
        s.verify(&s.clone(), &p).expect("verifies after upgrade");
        // Downgrade attempt: anon cred re-offered must not win.
        apply(&mut s, &p, delta_of(vec![&anon], vec![]));
        assert!(s.creds.creds[&anon.key].attestation.is_some());
    }

    #[test]
    fn anon_per_key_cap() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let spammer = anon_replier();
        let honest = anon_replier();

        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&honest], vec![pointer(&honest, 1, 0)]));
        let flood: Vec<_> = (0..20).map(|i| pointer(&spammer, 100 + i, i)).collect();
        apply(&mut s, &p, delta_of(vec![&spammer], flood));

        let spam_count = s
            .pointers
            .pointers
            .iter()
            .filter(|x| x.ptr.fingerprint == spammer.cred.fingerprint())
            .count();
        assert_eq!(spam_count, MAX_PER_ANON_KEY);
        assert!(
            s.pointers
                .pointers
                .iter()
                .any(|x| x.ptr.fingerprint == honest.cred.fingerprint()),
            "honest anon pointer must survive the flood"
        );
    }

    #[test]
    fn orphan_creds_pruned() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV2::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![]));
        assert!(s.creds.creds.is_empty());
    }

    /// Issue #49: a state carrying creds no pointer references must fail
    /// verify — post_apply_cleanup prunes them, so accepting one caches a
    /// state that is not a cleanup fixpoint.
    #[test]
    fn unreferenced_creds_fail_verify() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV2::default();
        s.creds.creds.insert(r.key, r.cred.clone());
        assert!(s.verify(&s.clone(), &p).is_err());
    }

    /// Issue #49 quiescence: an attacker state of unreferenced creds is
    /// rejected at validate (never cached, so no holder re-offers it), and
    /// even a delta smuggling them in leaves the receiver valid and its
    /// exchange with an honest replica quiescent.
    #[test]
    fn unreferenced_cred_offer_goes_quiescent() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let honest = anon_replier();

        let mut attacker = InboxStateV2::default();
        for _ in 0..5 {
            let r = anon_replier();
            attacker.creds.creds.insert(r.key, r.cred.clone());
        }
        assert!(
            attacker.verify(&attacker.clone(), &p).is_err(),
            "attacker state must be rejected at validate"
        );

        let mut receiver = InboxStateV2::default();
        apply(
            &mut receiver,
            &p,
            delta_of(vec![&honest], vec![pointer(&honest, 5, 0)]),
        );
        let clone = receiver.clone();
        receiver.merge(&clone, &p, &attacker).expect("merge ok");
        receiver
            .verify(&receiver.clone(), &p)
            .expect("receiver stays valid after smuggled creds are pruned");
        assert_eq!(receiver.creds.creds.len(), 1);

        // Full exchange with an honest replica goes quiescent.
        let mut peer = InboxStateV2::default();
        let clone = peer.clone();
        peer.merge(&clone, &p, &receiver).expect("merge ok");
        let clone = receiver.clone();
        receiver.merge(&clone, &p, &peer).expect("merge ok");
        let ps = peer.summarize(&peer.clone(), &p);
        assert!(receiver.delta(&receiver.clone(), &p, &ps).is_none());
        let rs = receiver.summarize(&receiver.clone(), &p);
        assert!(peer.delta(&peer.clone(), &p, &rs).is_none());
    }

    #[test]
    fn oversized_cred_delta_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut creds_map = std::collections::BTreeMap::new();
        for i in 0..(MAX_POINTERS + 1) {
            let mut key = r.key;
            key[0] = (i % 256) as u8;
            key[1] = (i / 256) as u8;
            creds_map.insert(key, r.cred.clone());
        }
        let mut s = InboxStateV2::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(
                &clone,
                &p,
                &Some(InboxStateV2Delta {
                    creds: Some(creds_map),
                    pointers: None,
                }),
            )
            .is_err());
    }

    // ---- policy path: fabricated pointers, no crypto ----
    // canonicalize/summarize/delta only read fingerprints and order keys, so
    // these use dummy signatures and synthetic fingerprints (the same trick
    // as directory-contract's fake_listing) — minting hundreds of real RSA
    // attestation chains would take minutes.

    fn fake(fingerprint: &str, time: u64, tag: u64) -> AuthorizedReplyPointerV2 {
        let mut reply = [0u8; 16];
        reply[..8].copy_from_slice(&time.to_be_bytes());
        reply[8..].copy_from_slice(&tag.to_be_bytes());
        AuthorizedReplyPointerV2 {
            ptr: ReplyPointerV2 {
                replier: [9u8; 32],
                fingerprint: fingerprint.into(),
                target_post: PostId([1u8; 16]),
                reply_post: PostId(reply),
                time,
            },
            signature: Signature::from_bytes(&[0u8; 64]),
        }
    }

    fn anon_fp(i: u64) -> String {
        format!("{ANON_FP_PREFIX}key{i}")
    }

    fn gk_fp(i: u64) -> String {
        format!("gk{i}")
    }

    fn pointers_of(v: Vec<AuthorizedReplyPointerV2>) -> PointersV2 {
        let mut p = PointersV2 { pointers: v };
        p.canonicalize();
        p
    }

    fn count_anon(p: &PointersV2) -> usize {
        p.pointers
            .iter()
            .filter(|x| is_anon_fingerprint(&x.ptr.fingerprint))
            .count()
    }

    #[test]
    fn anon_share_capped() {
        // 150 distinct anon keys, one pointer each: only the newest 100 stay.
        let v: Vec<_> = (0..150).map(|i| fake(&anon_fp(i), i, i)).collect();
        let p = pointers_of(v);
        assert_eq!(count_anon(&p), ANON_POINTER_SLOTS);
        assert!(p.pointers.iter().all(|x| x.ptr.time >= 50), "oldest dropped");
    }

    #[test]
    fn anon_never_evicts_attested() {
        // 250 attested (32 fingerprints × ≤8) + 200 newer anon.
        let mut v: Vec<_> = (0..250).map(|i| fake(&gk_fp(i / 8), i, i)).collect();
        v.extend((0..200).map(|i| fake(&anon_fp(i), 1000 + i, 1000 + i)));
        let p = pointers_of(v);
        let attested = p.pointers.len() - count_anon(&p);
        assert_eq!(attested, 250, "every attested pointer survives");
        assert_eq!(count_anon(&p), 50, "anon squeezed into the remainder");
        assert_eq!(p.pointers.len(), MAX_POINTERS);
    }

    #[test]
    fn attested_evicts_anon_at_global_cap() {
        // 100 old anon + 300 newer attested: checkmark is uncrowdable, anon
        // is fully evicted.
        let mut v: Vec<_> = (0..100).map(|i| fake(&anon_fp(i), i, i)).collect();
        v.extend((0..300).map(|i| fake(&gk_fp(i / 8), 1000 + i, 1000 + i)));
        let p = pointers_of(v);
        assert_eq!(count_anon(&p), 0);
        assert_eq!(p.pointers.len(), MAX_POINTERS);
    }

    #[test]
    fn attested_only_eviction_when_no_anon_left() {
        let v: Vec<_> = (0..310).map(|i| fake(&gk_fp(i / 8), i, i)).collect();
        let p = pointers_of(v);
        assert_eq!(p.pointers.len(), MAX_POINTERS);
        assert!(p.pointers.iter().all(|x| x.ptr.time >= 10), "oldest attested dropped");
    }

    fn summarize_pointers(p: &PointersV2) -> PointersV2Summary {
        let parent = InboxStateV2 {
            creds: Default::default(),
            pointers: p.clone(),
        };
        let params = InboxParametersV2 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        p.summarize(&parent, &params)
    }

    fn delta_against(p: &PointersV2, summary: &PointersV2Summary) -> Option<Vec<AuthorizedReplyPointerV2>> {
        let parent = InboxStateV2 {
            creds: Default::default(),
            pointers: p.clone(),
        };
        let params = InboxParametersV2 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        p.delta(&parent, &params, summary)
    }

    /// Receiver full of attested pointers ⇒ anon tier Closed ⇒ a sender
    /// holding anon pointers offers nothing (no livelock, no wasted bytes).
    #[test]
    fn closed_anon_horizon_prevents_reoffer_livelock() {
        let receiver = pointers_of((0..300).map(|i| fake(&gk_fp(i / 8), i, i)).collect());
        let summary = summarize_pointers(&receiver);
        assert_eq!(summary.anon_horizon, TierHorizon::Closed);

        let sender = pointers_of((0..5).map(|i| fake(&anon_fp(i), 1000 + i, i)).collect());
        assert!(
            delta_against(&sender, &summary).is_none(),
            "sender must not offer anon pointers to a closed tier"
        );
    }

    /// Receiver's anon share full ⇒ sender must not re-offer older anon
    /// pointers the receiver pruned.
    #[test]
    fn anon_share_horizon_prevents_reoffer() {
        let receiver = pointers_of((0..100).map(|i| fake(&anon_fp(i), 1000 + i, i)).collect());
        let summary = summarize_pointers(&receiver);
        assert!(matches!(summary.anon_horizon, TierHorizon::OldestRetained(_)));

        // Sender holds only OLDER anon pointers.
        let sender = pointers_of((0..5).map(|i| fake(&anon_fp(500 + i), i, 500 + i)).collect());
        assert!(delta_against(&sender, &summary).is_none());

        // But a NEWER anon pointer is still offered.
        let newer = pointers_of(vec![fake(&anon_fp(999), 5000, 999)]);
        assert!(delta_against(&newer, &summary).is_some());
    }

    /// A peer that pruned an anon key's excess pointers must not be
    /// re-offered them forever (fp-horizon, anon tier cap 3).
    #[test]
    fn anon_fp_horizon_prevents_flood_reoffer_livelock() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let spammer = anon_replier();

        let mut sender = InboxStateV2::default();
        apply(
            &mut sender,
            &p,
            delta_of(
                vec![&spammer],
                (0..MAX_PER_ANON_KEY as u64 + 5)
                    .map(|i| pointer(&spammer, 100 + i, i))
                    .collect(),
            ),
        );
        let mut receiver = InboxStateV2::default();
        let clone = receiver.clone();
        receiver.merge(&clone, &p, &sender).expect("first merge ok");

        let summary = receiver.summarize(&receiver.clone(), &p);
        let delta = sender.delta(&sender.clone(), &p, &summary);
        assert!(
            delta.is_none() || delta.as_ref().unwrap().pointers.is_none(),
            "sender must not re-offer capped-out pointers: {delta:?}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Any permutation of pointer deltas converges byte-identically,
        /// with anonymous and attested writers mixed.
        #[test]
        fn merge_commutative(times in proptest::collection::vec(0u64..100, 1..20), seed in 0u64..100) {
            let authority = TestAuthority::new();
            let p = params(&authority);
            let r1 = attested_replier(&authority);
            let r2 = anon_replier();
            let r3 = anon_replier();

            let pointers: Vec<_> = times.iter().enumerate().map(|(i, t)| {
                let r = match i % 3 { 0 => &r1, 1 => &r2, _ => &r3 };
                pointer(r, *t, i as u64)
            }).collect();
            let mut order2 = pointers.clone();
            let n = order2.len();
            for i in 0..n {
                let j = ((seed as usize).wrapping_mul(17).wrapping_add(i * 3)) % n;
                order2.swap(i, j);
            }

            let mut s1 = InboxStateV2::default();
            apply(&mut s1, &p, delta_of(vec![&r1, &r2, &r3], vec![]));
            let mut s2 = s1.clone();

            for chunk in pointers.chunks(3) {
                apply(&mut s1, &p, delta_of(vec![], chunk.to_vec()));
            }
            for chunk in order2.chunks(4) {
                apply(&mut s2, &p, delta_of(vec![], chunk.to_vec()));
            }
            prop_assert_eq!(freebird_core::to_cbor(&s1).unwrap(), freebird_core::to_cbor(&s2).unwrap());
        }

        /// cleanup(cleanup(s)) == cleanup(s), mixed tiers.
        #[test]
        fn cleanup_idempotent(times in proptest::collection::vec(0u64..100, 0..40)) {
            let mut pointers = PointersV2 {
                pointers: times.iter().enumerate().map(|(i, t)| {
                    let fp = if i % 2 == 0 { anon_fp((i % 6) as u64) } else { gk_fp((i % 4) as u64) };
                    fake(&fp, *t, i as u64)
                }).collect(),
            };
            pointers.canonicalize();
            let once = freebird_core::to_cbor(&pointers).unwrap();
            pointers.canonicalize();
            prop_assert_eq!(once, freebird_core::to_cbor(&pointers).unwrap());
        }

        /// Convergence AT AND ABOVE the caps: ~400 mixed-tier pointers —
        /// enough to cross the per-fp caps, the 100-slot anon share, and
        /// the 300 global cap — arriving in two different orders and chunk
        /// sizes, canonicalized incrementally (the lossy path). The tiered
        /// three-pass eviction must still be history-independent. Policy
        /// path (fake pointers): cases are cheap, so this can actually
        /// exercise cap scale.
        #[test]
        fn canonicalize_incremental_convergence_at_caps(
            times in proptest::collection::vec(0u64..2000, 300..400),
            seed in 0u64..1000,
        ) {
            let pointers: Vec<_> = times.iter().enumerate().map(|(i, t)| {
                let fp = if i % 3 == 0 { gk_fp((i % 40) as u64) } else { anon_fp((i % 60) as u64) };
                fake(&fp, *t, i as u64)
            }).collect();
            let mut order2 = pointers.clone();
            let n = order2.len();
            for i in 0..n {
                let j = ((seed as usize).wrapping_mul(31).wrapping_add(i * 7)) % n;
                order2.swap(i, j);
            }

            let mut s1 = PointersV2::default();
            for chunk in pointers.chunks(7) {
                s1.pointers.extend(chunk.iter().cloned());
                s1.canonicalize();
            }
            let mut s2 = PointersV2::default();
            for chunk in order2.chunks(11) {
                s2.pointers.extend(chunk.iter().cloned());
                s2.canonicalize();
            }
            prop_assert_eq!(
                freebird_core::to_cbor(&s1).unwrap(),
                freebird_core::to_cbor(&s2).unwrap()
            );
        }
    }

    // Orphaned-cred check must hold for anon creds too: an anon cred whose
    // pointers were evicted by the share cap gets pruned by cleanup.
    #[test]
    fn verify_rejects_over_anon_share() {
        let s = InboxStateV2 {
            creds: Default::default(),
            pointers: PointersV2 {
                pointers: {
                    let mut v: Vec<_> =
                        (0..101).map(|i| fake(&anon_fp(i), i, i)).collect();
                    v.sort_by_key(|p| (p.ptr.time, p.ptr.reply_post));
                    v
                },
            },
        };
        let params = InboxParametersV2 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        assert!(s.pointers.verify(&s, &params).is_err());
    }

    /// Regression (PR #24 review): duplicate reply_posts with DIFFERENT
    /// times are not adjacent after the (time, reply_post) sort — an
    /// adjacency-only dedup let a free anonymous key craft a delta that
    /// apply accepted and verify rejected, bricking the inbox permanently.
    #[test]
    fn duplicate_reply_post_across_times_deduped_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mk = |time: u64, reply: PostId| {
            AuthorizedReplyPointerV2::new(
                ReplyPointerV2 {
                    replier: r.key,
                    fingerprint: r.cred.fingerprint(),
                    target_post: PostId([1u8; 16]),
                    reply_post: reply,
                    time,
                },
                &r.sk,
            )
        };
        let dup = PostId([7u8; 16]);
        let other = PostId([8u8; 16]);
        let mut s = InboxStateV2::default();
        // (t=50, other) sorts BETWEEN the two dup entries.
        apply(
            &mut s,
            &p,
            delta_of(vec![&r], vec![mk(1, dup), mk(50, other), mk(100, dup)]),
        );
        assert_eq!(s.pointers.pointers.len(), 2);
        s.verify(&s.clone(), &p)
            .expect("a state produced by apply must always verify");
    }

    /// The tier discriminator rests on attested fingerprints being bs58
    /// (no colon): pin that a real attestation's fingerprint can never be
    /// mistaken for the anonymous tier.
    #[test]
    fn attested_fingerprint_never_anon_prefixed() {
        let authority = TestAuthority::new();
        let r = attested_replier(&authority);
        assert!(!is_anon_fingerprint(&r.cred.fingerprint()));
        assert!(is_anon_fingerprint(&anon_replier().cred.fingerprint()));
    }

    /// A fabricated full state seating one key across more than its
    /// fairness cap must be rejected by verify — canonicalize would only
    /// heal it on the NEXT update.
    #[test]
    fn verify_rejects_over_per_fingerprint_cap() {
        let params = InboxParametersV2 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        let over_anon = InboxStateV2 {
            creds: Default::default(),
            pointers: PointersV2 {
                pointers: (0..MAX_PER_ANON_KEY as u64 + 1)
                    .map(|i| fake(&anon_fp(0), i, i))
                    .collect(),
            },
        };
        assert!(over_anon.pointers.verify(&over_anon, &params).is_err());
        let over_gk = InboxStateV2 {
            creds: Default::default(),
            pointers: PointersV2 {
                pointers: (0..MAX_PER_FINGERPRINT as u64 + 1)
                    .map(|i| fake(&gk_fp(0), i, i))
                    .collect(),
            },
        };
        assert!(over_gk.pointers.verify(&over_gk, &params).is_err());
    }

    /// The MIDDLE horizon regime: attested past their reserved majority
    /// (250) shrinks the effective anon share to 50. The anon horizon must
    /// be OldestRetained there — an Open horizon would re-offer pruned anon
    /// pointers forever, exactly the livelock the machinery exists to stop.
    #[test]
    fn shrunken_anon_horizon_is_oldest_retained() {
        let mut v: Vec<_> = (0..250).map(|i| fake(&gk_fp(i / 8), i, i)).collect();
        v.extend((0..50).map(|i| fake(&anon_fp(i), 1000 + i, 1000 + i)));
        let receiver = pointers_of(v);
        assert_eq!(receiver.pointers.len(), MAX_POINTERS);
        let summary = summarize_pointers(&receiver);
        assert_eq!(summary.attested_horizon, TierHorizon::Open);
        assert!(
            matches!(summary.anon_horizon, TierHorizon::OldestRetained(k) if k.0 == 1000),
            "shrunken share must close below the oldest retained anon: {:?}",
            summary.anon_horizon
        );

        // Older anon pointer: not offered. Newer: offered.
        let older = pointers_of(vec![fake(&anon_fp(99), 500, 99)]);
        assert!(delta_against(&older, &summary).is_none());
        let newer = pointers_of(vec![fake(&anon_fp(98), 2000, 98)]);
        assert!(delta_against(&newer, &summary).is_some());
    }

    /// Attested-tier fp horizon (cap 8), the v1 livelock regression kept
    /// alive in v2: a receiver holding a fingerprint's full cap must not be
    /// re-offered that fingerprint's older pointers.
    #[test]
    fn attested_fp_horizon_prevents_reoffer() {
        let receiver = pointers_of(
            (0..MAX_PER_FINGERPRINT as u64)
                .map(|i| fake(&gk_fp(0), 100 + i, i))
                .collect(),
        );
        let summary = summarize_pointers(&receiver);
        assert!(summary.fp_horizons.contains_key(&gk_fp(0)));

        let older = pointers_of(vec![fake(&gk_fp(0), 50, 99)]);
        assert!(delta_against(&older, &summary).is_none());
        let newer = pointers_of(vec![fake(&gk_fp(0), 500, 98)]);
        assert!(delta_against(&newer, &summary).is_some());
    }

    #[test]
    fn scrub_future_drops_far_future_keeps_boundary() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let now = 1_000;
        let boundary = now + freebird_core::feed::MAX_FUTURE_MS;
        let mut s = InboxStateV2::default();
        apply(
            &mut s,
            &p,
            delta_of(
                vec![&r],
                vec![pointer(&r, boundary, 0), pointer(&r, boundary + 1, 1)],
            ),
        );
        assert_eq!(s.pointers.pointers.len(), 2);
        s.scrub_future(now);
        assert_eq!(s.pointers.pointers.len(), 1, "exactly the boundary survives");
        assert_eq!(s.pointers.pointers[0].ptr.time, boundary);
    }

    /// Cross-replica anon→attested upgrade, realistic bundled deltas (the
    /// client always ships cred + pointer together), applied in BOTH
    /// orders: the stale anon pointer dies via check_pointer on one replica
    /// and via post_apply_cleanup on the other — the two code paths must
    /// land on byte-identical state.
    #[test]
    fn upgrade_order_independent_across_replicas() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let anon = anon_replier();
        let attested = Replier {
            cred: ReplierCredV2 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk.verifying_key())),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };
        let anon_delta = delta_of(vec![&anon], vec![pointer(&anon, 5, 0)]);
        let att_delta = delta_of(vec![&attested], vec![pointer(&attested, 6, 1)]);

        let mut a = InboxStateV2::default();
        apply(&mut a, &p, anon_delta.clone());
        apply(&mut a, &p, att_delta.clone());

        let mut b = InboxStateV2::default();
        apply(&mut b, &p, att_delta);
        apply(&mut b, &p, anon_delta);

        assert_eq!(
            freebird_core::to_cbor(&a).unwrap(),
            freebird_core::to_cbor(&b).unwrap()
        );
        a.verify(&a.clone(), &p).expect("verifies");
        assert_eq!(a.pointers.pointers.len(), 1, "only the attested pointer survives");
    }

    /// Healing after the upgrade: a sender still holding the pre-upgrade
    /// anon state converges once the upgraded state flows back, and the
    /// exchange goes quiescent (no eternal re-offer of the dead pointers).
    #[test]
    fn upgrade_propagation_heals_and_goes_quiescent() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let anon = anon_replier();
        let attested = Replier {
            cred: ReplierCredV2 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk.verifying_key())),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };

        // Sender: pre-upgrade anon state. Receiver: post-upgrade state.
        let mut sender = InboxStateV2::default();
        apply(&mut sender, &p, delta_of(vec![&anon], vec![pointer(&anon, 5, 0)]));
        let mut receiver = InboxStateV2::default();
        apply(
            &mut receiver,
            &p,
            delta_of(vec![&attested], vec![pointer(&attested, 6, 1)]),
        );

        // Full exchange both ways.
        let clone = receiver.clone();
        receiver.merge(&clone, &p, &sender).expect("merge ok");
        let clone = sender.clone();
        sender.merge(&clone, &p, &receiver).expect("merge ok");

        assert_eq!(
            freebird_core::to_cbor(&sender).unwrap(),
            freebird_core::to_cbor(&receiver).unwrap(),
            "sender heals to the upgraded state"
        );
        // Quiescence: neither side offers anything anymore.
        let rs = receiver.summarize(&receiver.clone(), &p);
        assert!(sender.delta(&sender.clone(), &p, &rs).is_none());
        let ss = sender.summarize(&sender.clone(), &p);
        assert!(receiver.delta(&receiver.clone(), &p, &ss).is_none());
    }
}
