//! Per-author reply inbox: an open-write contract where Ghost Key–attested
//! repliers leave pointers to replies that live in their own feeds.
//!
//! Credentials are keyed by the replier's POSTING key — the true authority a
//! pointer's signature verifies against. Keying by ghost-key fingerprint is
//! wrong: one Ghost Key may attest many posting keys (re-verification after a
//! reinstall does exactly this), and a cred swap under a shared key would
//! orphan every stored pointer and brick the inbox network-wide.
//!
//! The ghost-key fingerprint still rides in each pointer for the fairness
//! cap: one purchase gets at most MAX_PER_FINGERPRINT slots regardless of
//! how many posting keys it attests.

use freenet_scaffold_macro::composable;

pub use inbox_components::*;

pub const MAX_POINTERS: usize = 300;
pub const MAX_PER_FINGERPRINT: usize = 8;

/// Reply-inbox state. Field order is load-bearing: creds must apply before
/// pointers so a single delta carrying both validates its own pointers.
#[composable(post_apply_delta = "post_apply_cleanup")]
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct InboxStateV1 {
    pub creds: CredsV1,
    pub pointers: PointersV1,
}

impl InboxStateV1 {
    /// Idempotent: enforce caps and drop credentials no pointer references.
    pub fn post_apply_cleanup(
        &mut self,
        _parameters: &InboxParametersV1,
    ) -> Result<(), String> {
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
        self.pointers
            .pointers
            .retain(|p| p.ptr.time <= now_ms.saturating_add(crate::feed::MAX_FUTURE_MS));
    }
}

mod inbox_components {
    use crate::attestation::AttestationV1;
    use crate::feed::RetentionHorizon;
    use crate::types::PostId;
    use ed25519_dalek::{Signature, VerifyingKey};
    use freenet_scaffold::ComposableState;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    use super::{InboxStateV1, MAX_PER_FINGERPRINT, MAX_POINTERS};

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct InboxParametersV1 {
        /// The inbox owner's posting key — only used to derive the address
        /// (same key as the owner's feed params, different wasm).
        pub owner: VerifyingKey,
        /// Ghost Key trust anchor; see `FeedParametersV1::ghostkey_master`.
        pub ghostkey_master: VerifyingKey,
    }

    /// A replier's credential: posting key + Ghost Key attestation over it.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct ReplierCred {
        pub posting_key: VerifyingKey,
        pub attestation: AttestationV1,
    }

    impl ReplierCred {
        fn check(&self, map_key: &[u8; 32], master: &VerifyingKey) -> Result<(), String> {
            if self.posting_key.as_bytes() != map_key {
                return Err("credential stored under wrong posting key".into());
            }
            self.attestation
                .verify(&self.posting_key, Some(master))
                .map_err(|e| format!("replier credential invalid: {e}"))?;
            Ok(())
        }

        pub fn fingerprint(&self) -> String {
            self.attestation.fingerprint()
        }
    }

    // ---- creds: map keyed by posting key; LWW per entry by content hash ----

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct CredsV1 {
        pub creds: BTreeMap<[u8; 32], ReplierCred>,
    }

    impl ComposableState for CredsV1 {
        type ParentState = InboxStateV1;
        /// posting key → attestation content hash: peers holding DIFFERENT
        /// creds for one key must look different, or they never reconcile.
        type Summary = BTreeMap<[u8; 32], [u8; 32]>;
        type Delta = BTreeMap<[u8; 32], ReplierCred>;
        type Parameters = InboxParametersV1;

        fn verify(
            &self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            if self.creds.len() > MAX_POINTERS {
                return Err("more credentials than pointers can reference".into());
            }
            for (key, cred) in &self.creds {
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
                .map(|(k, c)| (*k, c.attestation.content_hash()))
                .collect()
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let delta: BTreeMap<[u8; 32], ReplierCred> = self
                .creds
                .iter()
                .filter(|(k, c)| {
                    match old_summary.get(*k) {
                        None => true,
                        // Deterministic winner: max content hash.
                        Some(theirs) => c.attestation.content_hash() > *theirs,
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
            // Bound the work one delta can demand: each cred costs an RSA
            // chain verification inside wasm.
            if delta.len() > MAX_POINTERS {
                return Err("credential delta too large".into());
            }
            for (key, cred) in delta {
                cred.check(key, &parameters.ghostkey_master)?;
                match self.creds.get(key) {
                    Some(existing)
                        if existing.attestation.content_hash()
                            >= cred.attestation.content_hash() => {}
                    _ => {
                        self.creds.insert(*key, cred.clone());
                    }
                }
            }
            Ok(())
        }
    }

    // ---- pointers: capped log, per-fingerprint fairness cap ----

    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub struct ReplyPointer {
        /// The replier's posting key; must resolve in `creds`.
        pub replier: [u8; 32],
        /// Ghost key fingerprint of the replier's credential — the fairness-
        /// cap group. Must equal `creds[replier].fingerprint()`.
        pub fingerprint: String,
        /// The post in the inbox owner's feed being replied to.
        pub target_post: PostId,
        /// The reply post in the REPLIER's feed.
        pub reply_post: PostId,
        pub time: u64,
    }

    /// Pointer + signature by the replier's POSTING key (not the ghost key —
    /// replies never round-trip through the ghostkey delegate).
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct AuthorizedReplyPointer {
        pub ptr: ReplyPointer,
        pub signature: Signature,
    }

    impl AuthorizedReplyPointer {
        pub fn new(ptr: ReplyPointer, signing_key: &ed25519_dalek::SigningKey) -> Self {
            use ed25519_dalek::Signer;
            let bytes = crate::to_cbor(&ptr).expect("pointer serializes");
            Self {
                signature: signing_key.sign(&bytes),
                ptr,
            }
        }

        pub fn verify_signature(&self, posting_key: &VerifyingKey) -> Result<(), String> {
            let bytes = crate::to_cbor(&self.ptr)?;
            posting_key
                .verify_strict(&bytes, &self.signature)
                .map_err(|e| format!("pointer signature invalid: {e}"))
        }
    }

    pub type PointerOrderKey = (u64, PostId);

    fn order_key(p: &AuthorizedReplyPointer) -> PointerOrderKey {
        (p.ptr.time, p.ptr.reply_post)
    }

    /// Check a pointer against the credential map of the (in-progress) state.
    fn check_pointer(
        p: &AuthorizedReplyPointer,
        creds: &BTreeMap<[u8; 32], super::ReplierCred>,
    ) -> Result<bool, String> {
        let Some(cred) = creds.get(&p.ptr.replier) else {
            return Ok(false); // no credential: dropped, not fatal
        };
        p.verify_signature(&cred.posting_key)?;
        if p.ptr.fingerprint != cred.fingerprint() {
            return Err("pointer fingerprint does not match credential".into());
        }
        Ok(true)
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct PointersSummary {
        pub ids: BTreeSet<PostId>,
        pub horizon: RetentionHorizon,
        /// Per-fingerprint retention: for every fingerprint AT its cap, the
        /// oldest key retained for it. Without this, a peer that dropped a
        /// flooder's excess pointers advertises appetite it doesn't have and
        /// senders re-offer the same entries every round — the same livelock
        /// class the global horizon prevents, triggered exactly during spam.
        pub fp_horizons: BTreeMap<String, PointerOrderKey>,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct PointersV1 {
        /// Sorted ascending by `(time, reply_post)`.
        pub pointers: Vec<AuthorizedReplyPointer>,
    }

    impl PointersV1 {
        /// Sort, dedupe, then enforce the per-fingerprint cap (newest kept)
        /// and the global cap. Idempotent.
        pub fn canonicalize(&mut self) {
            self.pointers.sort_by_key(order_key);
            self.pointers.dedup_by_key(|p| p.ptr.reply_post);

            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            let mut keep: Vec<bool> = vec![false; self.pointers.len()];
            for (i, p) in self.pointers.iter().enumerate().rev() {
                let c = counts.entry(p.ptr.fingerprint.clone()).or_insert(0);
                if *c < MAX_PER_FINGERPRINT {
                    *c += 1;
                    keep[i] = true;
                }
            }
            let mut it = keep.iter();
            self.pointers.retain(|_| *it.next().unwrap());

            if self.pointers.len() > MAX_POINTERS {
                let excess = self.pointers.len() - MAX_POINTERS;
                self.pointers.drain(0..excess);
            }
        }

        fn retention_horizon(&self) -> RetentionHorizon {
            if self.pointers.len() < MAX_POINTERS {
                RetentionHorizon::Open
            } else {
                RetentionHorizon::OldestRetained(order_key(&self.pointers[0]))
            }
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
                .filter(|(_, keys)| keys.len() >= MAX_PER_FINGERPRINT)
                .map(|(fp, keys)| {
                    let oldest = keys.iter().min().cloned().expect("non-empty group");
                    (fp, oldest)
                })
                .collect()
        }
    }

    impl ComposableState for PointersV1 {
        type ParentState = InboxStateV1;
        type Summary = PointersSummary;
        type Delta = Vec<AuthorizedReplyPointer>;
        type Parameters = InboxParametersV1;

        fn verify(
            &self,
            parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Result<(), String> {
            if self.pointers.len() > MAX_POINTERS {
                return Err(format!("more than {MAX_POINTERS} pointers"));
            }
            for pair in self.pointers.windows(2) {
                if order_key(&pair[0]) > order_key(&pair[1]) {
                    return Err("pointers not sorted".into());
                }
            }
            let mut seen = BTreeSet::new();
            for p in &self.pointers {
                if !check_pointer(p, &parent.creds.creds)? {
                    return Err("pointer without credential".into());
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
            PointersSummary {
                ids: self.pointers.iter().map(|p| p.ptr.reply_post).collect(),
                horizon: self.retention_horizon(),
                fp_horizons: self.fp_horizons(),
            }
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let retained = |p: &AuthorizedReplyPointer| {
                let above_global = match &old_summary.horizon {
                    RetentionHorizon::Open => true,
                    RetentionHorizon::OldestRetained(oldest) => order_key(p) > *oldest,
                };
                let above_fp = match old_summary.fp_horizons.get(&p.ptr.fingerprint) {
                    None => true,
                    Some(oldest) => order_key(p) > *oldest,
                };
                above_global && above_fp
            };
            let delta: Vec<AuthorizedReplyPointer> = self
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
            // visible. Pointers with no credential are dropped, not fatal —
            // a peer that pruned a cred must not be able to poison-pill
            // another peer's otherwise-valid delta.
            let mut accepted: Vec<AuthorizedReplyPointer> = Vec::new();
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
    use crate::attestation::fixtures::TestAuthority;
    use crate::types::PostId;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use freenet_scaffold::ComposableState;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    struct Replier {
        sk: SigningKey,
        cred: ReplierCred,
        key: [u8; 32],
    }

    fn replier(authority: &TestAuthority) -> Replier {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let attestation = authority.attest_v1(&vk);
        Replier {
            key: vk.to_bytes(),
            cred: ReplierCred {
                posting_key: vk,
                attestation,
            },
            sk,
        }
    }

    fn owner() -> VerifyingKey {
        SigningKey::generate(&mut OsRng).verifying_key()
    }

    fn params(authority: &TestAuthority) -> InboxParametersV1 {
        InboxParametersV1 {
            owner: owner(),
            ghostkey_master: authority.master_vk,
        }
    }

    fn pointer(r: &Replier, time: u64, tag: u64) -> AuthorizedReplyPointer {
        let ptr = ReplyPointer {
            replier: r.key,
            fingerprint: r.cred.fingerprint(),
            target_post: PostId([1u8; 16]),
            reply_post: PostId::compute(&r.sk.verifying_key(), time, &format!("r{tag}"), &None),
            time,
        };
        AuthorizedReplyPointer::new(ptr, &r.sk)
    }

    fn delta_of(
        creds: Vec<&Replier>,
        pointers: Vec<AuthorizedReplyPointer>,
    ) -> Option<InboxStateV1Delta> {
        let creds_map: std::collections::BTreeMap<[u8; 32], ReplierCred> = creds
            .into_iter()
            .map(|r| (r.key, r.cred.clone()))
            .collect();
        Some(InboxStateV1Delta {
            creds: (!creds_map.is_empty()).then_some(creds_map),
            pointers: (!pointers.is_empty()).then_some(pointers),
        })
    }

    fn apply(state: &mut InboxStateV1, p: &InboxParametersV1, delta: Option<InboxStateV1Delta>) {
        let clone = state.clone();
        state.apply_delta(&clone, p, &delta).expect("apply ok");
    }

    #[test]
    fn attested_pointer_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&authority);
        let mut s = InboxStateV1::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer(&r, 5, 0)]));
        assert_eq!(s.pointers.pointers.len(), 1);
        s.verify(&s.clone(), &p).expect("verifies");
    }

    #[test]
    fn pointer_without_cred_is_dropped() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&authority);
        let mut s = InboxStateV1::default();
        apply(&mut s, &p, delta_of(vec![], vec![pointer(&r, 5, 0)]));
        assert!(s.pointers.pointers.is_empty());
    }

    #[test]
    fn cred_with_bad_attestation_rejected() {
        let authority = TestAuthority::new();
        let rogue_authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&rogue_authority); // attested under the wrong master
        let mut s = InboxStateV1::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![pointer(&r, 5, 0)]))
            .is_err());
    }

    #[test]
    fn forged_pointer_signature_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&authority);
        let other = replier(&authority);
        let mut s = InboxStateV1::default();
        // Pointer claims r's identity but is signed by other's key.
        let mut fake = pointer(&other, 5, 0);
        fake.ptr.replier = r.key;
        fake.ptr.fingerprint = r.cred.fingerprint();
        let fake = AuthorizedReplyPointer::new(fake.ptr, &other.sk);
        let mut delta = delta_of(vec![&r], vec![fake]);
        let clone = s.clone();
        assert!(s.apply_delta(&clone, &p, &mut delta).is_err());
    }

    /// Regression (review finding #1): one Ghost Key attesting a SECOND
    /// posting key must not orphan pointers from the first — both creds
    /// coexist under their own posting keys and the state stays valid.
    #[test]
    fn same_ghostkey_second_posting_key_does_not_brick_inbox() {
        let authority = TestAuthority::new();
        let p = params(&authority);

        // Two posting keys attested by chains from the same authority.
        let r1 = replier(&authority);
        let r2 = replier(&authority);

        let mut s = InboxStateV1::default();
        apply(&mut s, &p, delta_of(vec![&r1], vec![pointer(&r1, 5, 0)]));
        s.verify(&s.clone(), &p).expect("valid after first reply");

        // Second identity replies later — including a cred-only delta first
        // (the shape that used to swap the shared-fingerprint cred).
        apply(&mut s, &p, delta_of(vec![&r2], vec![]));
        apply(&mut s, &p, delta_of(vec![&r2], vec![pointer(&r2, 6, 1)]));

        s.verify(&s.clone(), &p)
            .expect("old pointers must still verify after another cred arrives");
        assert_eq!(s.pointers.pointers.len(), 2);
    }

    #[test]
    fn per_fingerprint_cap_cannot_evict_others() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let spammer = replier(&authority);
        let honest = replier(&authority);

        let mut s = InboxStateV1::default();
        apply(&mut s, &p, delta_of(vec![&honest], vec![pointer(&honest, 1, 0)]));
        let flood: Vec<_> = (0..50).map(|i| pointer(&spammer, 100 + i, i)).collect();
        apply(&mut s, &p, delta_of(vec![&spammer], flood));

        let spam_count = s
            .pointers
            .pointers
            .iter()
            .filter(|x| x.ptr.fingerprint == spammer.cred.fingerprint())
            .count();
        assert_eq!(spam_count, MAX_PER_FINGERPRINT);
        assert!(
            s.pointers
                .pointers
                .iter()
                .any(|x| x.ptr.fingerprint == honest.cred.fingerprint()),
            "honest pointer must survive the flood"
        );
    }

    /// Regression (review finding #4): a peer that pruned a flooder's excess
    /// pointers must not be re-offered them forever. After one exchange the
    /// sender has nothing left to offer.
    #[test]
    fn fp_horizon_prevents_flood_reoffer_livelock() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let spammer = replier(&authority);

        // Sender holds a flood (as separate states so nothing was pruned).
        let mut sender = InboxStateV1::default();
        apply(
            &mut sender,
            &p,
            delta_of(
                vec![&spammer],
                (0..MAX_PER_FINGERPRINT as u64 + 5)
                    .map(|i| pointer(&spammer, 100 + i, i))
                    .collect(),
            ),
        );
        // sender itself caps at MAX_PER_FINGERPRINT — build receiver from it.
        let mut receiver = InboxStateV1::default();
        let clone = receiver.clone();
        receiver
            .merge(&clone, &p, &sender)
            .expect("first merge ok");

        // Steady state: sender must now produce NO pointer delta.
        let summary = receiver.summarize(&receiver.clone(), &p);
        let delta = sender.delta(&sender.clone(), &p, &summary);
        assert!(
            delta.is_none() || delta.as_ref().unwrap().pointers.is_none(),
            "sender must not re-offer capped-out pointers: {delta:?}"
        );
    }

    #[test]
    fn orphan_creds_pruned() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&authority);
        let mut s = InboxStateV1::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![]));
        assert!(s.creds.creds.is_empty());
    }

    #[test]
    fn oversized_cred_delta_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = replier(&authority);
        // Fabricate a delta with more creds than can ever be referenced.
        let mut creds_map = std::collections::BTreeMap::new();
        for i in 0..(MAX_POINTERS + 1) {
            let mut key = r.key;
            key[0] = (i % 256) as u8;
            key[1] = (i / 256) as u8;
            creds_map.insert(key, r.cred.clone());
        }
        let mut s = InboxStateV1::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(
                &clone,
                &p,
                &Some(InboxStateV1Delta {
                    creds: Some(creds_map),
                    pointers: None,
                }),
            )
            .is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Any permutation of pointer deltas converges byte-identically.
        #[test]
        fn merge_commutative(times in proptest::collection::vec(0u64..100, 1..20), seed in 0u64..100) {
            let authority = TestAuthority::new();
            let p = params(&authority);
            let r1 = replier(&authority);
            let r2 = replier(&authority);

            let pointers: Vec<_> = times.iter().enumerate().map(|(i, t)| {
                let r = if i % 2 == 0 { &r1 } else { &r2 };
                pointer(r, *t, i as u64)
            }).collect();
            let mut order2 = pointers.clone();
            let n = order2.len();
            for i in 0..n {
                let j = ((seed as usize).wrapping_mul(17).wrapping_add(i * 3)) % n;
                order2.swap(i, j);
            }

            let mut s1 = InboxStateV1::default();
            apply(&mut s1, &p, delta_of(vec![&r1, &r2], vec![]));
            let mut s2 = s1.clone();

            for chunk in pointers.chunks(3) {
                apply(&mut s1, &p, delta_of(vec![], chunk.to_vec()));
            }
            for chunk in order2.chunks(4) {
                apply(&mut s2, &p, delta_of(vec![], chunk.to_vec()));
            }
            prop_assert_eq!(crate::to_cbor(&s1).unwrap(), crate::to_cbor(&s2).unwrap());
        }

        /// cleanup(cleanup(s)) == cleanup(s)
        #[test]
        fn cleanup_idempotent(times in proptest::collection::vec(0u64..100, 0..20)) {
            let authority = TestAuthority::new();
            let p = params(&authority);
            let r = replier(&authority);
            let mut s = InboxStateV1::default();
            let pointers: Vec<_> = times.iter().enumerate().map(|(i, t)| pointer(&r, *t, i as u64)).collect();
            apply(&mut s, &p, delta_of(vec![&r], pointers));
            let once = crate::to_cbor(&s).unwrap();
            s.post_apply_cleanup(&p).unwrap();
            prop_assert_eq!(once, crate::to_cbor(&s).unwrap());
        }
    }
}
