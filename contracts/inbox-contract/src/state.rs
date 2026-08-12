//! Inbox v3 (issues #45/#46/#47, formerly v2 / issue #23): two-tier reply
//! inbox with anonymous parity. V3 binds every pointer to its inbox instance
//! (owner in the signed bytes — cross-inbox replay dies), signs pointers
//! over a domain-tagged manual canonical layout instead of bare CBOR, and
//! carries v2 attestations (proof of possession + requestor binding).
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

use freenet_scaffold::ComposableState;

pub use inbox_v3_components::*;

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
///
/// The `ComposableState` impl is hand-written (issue #49) instead of
/// `#[composable]`: the cred delta must be gated on the pointer delta, and
/// the macro gives each component only its own summary slice.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct InboxStateV3 {
    pub creds: CredsV3,
    pub pointers: PointersV3,
}

/// Same shape the `#[composable]` macro generated.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct InboxStateV3Summary {
    pub creds: <CredsV3 as ComposableState>::Summary,
    pub pointers: <PointersV3 as ComposableState>::Summary,
}

/// Same shape the `#[composable]` macro generated, plus the optional
/// publisher-signed difficulty record (issue #51) the writer solved against.
/// The record rides the ORIGINAL client write only; node-to-node gossip
/// (`delta()`) emits `pow_difficulty: None`, so replicas always re-admit at
/// the compiled floor and stay convergent.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct InboxStateV3Delta {
    pub creds: Option<<CredsV3 as ComposableState>::Delta>,
    pub pointers: Option<<PointersV3 as ComposableState>::Delta>,
    #[serde(default)]
    pub pow_difficulty: Option<cell_contract::SignedCellV1>,
}

impl ComposableState for InboxStateV3 {
    type ParentState = InboxStateV3;
    type Summary = InboxStateV3Summary;
    type Delta = InboxStateV3Delta;
    type Parameters = InboxParametersV3;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        self.creds.verify(parent_state, parameters)?;
        self.pointers.verify(parent_state, parameters)?;
        Ok(())
    }

    fn summarize(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Self::Summary {
        InboxStateV3Summary {
            creds: self.creds.summarize(parent_state, parameters),
            pointers: self.pointers.summarize(parent_state, parameters),
        }
    }

    /// The cred delta is gated on the pointer delta (issue #49): a cred the
    /// peer lacks is offered only alongside a pointer referencing it in the
    /// SAME delta (a cred the peer already holds is an upgrade and always
    /// flows). Otherwise the peer's post_apply_cleanup prunes the cred, its
    /// cred summary never changes, and we re-offer it forever — the honest
    /// case being a sender whose pointers all fall below the peer's
    /// retention horizons.
    fn delta(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let pointers =
            self.pointers
                .delta(parent_state, parameters, &old_state_summary.pointers);
        let creds = self
            .creds
            .delta(parent_state, parameters, &old_state_summary.creds)
            .map(|mut c| {
                c.retain(|k, _| {
                    old_state_summary.creds.contains_key(k)
                        || pointers
                            .as_ref()
                            .is_some_and(|ps| ps.iter().any(|p| p.ptr.replier == *k))
                });
                c
            })
            .filter(|c| !c.is_empty());
        (creds.is_some() || pointers.is_some())
            .then_some(InboxStateV3Delta { creds, pointers, pow_difficulty: None })
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else { return Ok(()) };
        // PoW admission (issue #51): drop anonymous pointers below the
        // effective difficulty — the compiled floor, raised by a valid
        // publisher-signed control-cell record if this write carries one.
        // Attested pointers skip PoW (ghost key = accelerator). Drop-not-fatal,
        // same doctrine as a missing credential: an honest peer never forwards
        // an under-bar stamp. Wrong-inbox pointers are LEFT IN so the staple
        // loop / check_pointer can fatal on them (issue #46), never silently
        // dropped by a binding-mismatched PoW check.
        let owner = parameters.owner.to_bytes();
        let bits = freebird_pow::difficulty_bits(delta.pow_difficulty.as_ref());
        let admitted: Option<Vec<AuthorizedReplyPointerV3>> = delta.pointers.as_ref().map(|ps| {
            ps.iter()
                .filter(|p| {
                    !is_anon_fingerprint(&p.ptr.fingerprint)
                        || p.ptr.owner != owner
                        || freebird_pow::meets_inbox(&owner, &p.ptr.replier, p.pow_nonce, bits)
                })
                .cloned()
                .collect()
        });
        // A delta cred no existing or incoming pointer references would be
        // pruned by post_apply_cleanup anyway — skip it BEFORE apply pays
        // its RSA verification (issue #49). An incoming pointer vouches for
        // its cred only after its ed25519 signature verifies (a junk staple
        // fails the delta with no RSA paid; a validly signed one buys one
        // RSA check — the floor for accepting attested creds at all). The
        // size bound stays a hard reject, ahead of the filter's linear scan.
        let creds = match &delta.creds {
            Some(c) if c.len() > MAX_POINTERS => {
                return Err("credential delta too large".into())
            }
            Some(c) => {
                // Bad staple signatures stay FATAL (same doctrine as
                // check_pointer), and the verified ones vouch for their
                // creds — one ed25519 verify gates each RSA check.
                let mut stapled = std::collections::BTreeSet::new();
                if let Some(ps) = &admitted {
                    for ptr in ps {
                        // Wrong-inbox staples fail here, BEFORE any RSA is
                        // paid (issue #46) — same doctrine as bad signatures.
                        if ptr.ptr.owner != parameters.owner.to_bytes() {
                            return Err("pointer bound to another inbox".into());
                        }
                        if let Some(cred) = c.get(&ptr.ptr.replier) {
                            ptr.verify_signature(&cred.posting_key)?;
                            stapled.insert(ptr.ptr.replier);
                        }
                    }
                }
                let mut c = c.clone();
                c.retain(|k, _| {
                    stapled.contains(k)
                        || self.pointers.pointers.iter().any(|p| p.ptr.replier == *k)
                });
                (!c.is_empty()).then_some(c)
            }
            None => None,
        };
        // Creds before pointers, each seeing the in-progress state, then the
        // idempotent cleanup — same order the macro generated.
        let self_clone = self.clone();
        self.creds.apply_delta(&self_clone, parameters, &creds)?;
        let self_clone = self.clone();
        self.pointers
            .apply_delta(&self_clone, parameters, &admitted)?;
        self.post_apply_cleanup(parameters)?;
        Ok(())
    }
}

impl InboxStateV3 {
    /// Idempotent: enforce caps and drop credentials no pointer references.
    ///
    /// Also drops pointers whose fingerprint no longer matches their
    /// credential: an anonymous cred upgrading to attested (same posting
    /// key, new fingerprint) is a NORMAL flow in v2, and replicas that saw
    /// the upgrade and the old pointers in different orders must converge on
    /// "stale pointers gone".
    pub fn post_apply_cleanup(
        &mut self,
        _parameters: &InboxParametersV3,
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

mod inbox_v3_components {
    use ed25519_dalek::{Signature, VerifyingKey};
    use freebird_core::attestation::AttestationV2;
    use freebird_core::types::PostId;
    use freenet_scaffold::ComposableState;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        anon_fingerprint, is_anon_fingerprint, InboxStateV3, ANON_POINTER_SLOTS,
        MAX_PER_ANON_KEY, MAX_PER_FINGERPRINT, MAX_POINTERS,
    };

    /// CBOR-identical shape to the v1 params (owner + trust anchor); a
    /// distinct type because the two schemas must never be conflated in code.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct InboxParametersV3 {
        /// The inbox owner's posting key — only used to derive the address.
        pub owner: VerifyingKey,
        /// Ghost Key trust anchor; see `FeedParametersV1::ghostkey_master`.
        pub ghostkey_master: VerifyingKey,
    }

    /// A replier's credential. `attestation: None` = anonymous tier.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct ReplierCredV3 {
        pub posting_key: VerifyingKey,
        pub attestation: Option<AttestationV2>,
    }

    impl ReplierCredV3 {
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
    pub struct CredsV3 {
        pub creds: BTreeMap<[u8; 32], ReplierCredV3>,
    }

    impl ComposableState for CredsV3 {
        type ParentState = InboxStateV3;
        /// posting key → cred content hash: peers holding DIFFERENT creds
        /// for one key must look different, or they never reconcile.
        type Summary = BTreeMap<[u8; 32], [u8; 32]>;
        type Delta = BTreeMap<[u8; 32], ReplierCredV3>;
        type Parameters = InboxParametersV3;

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
            let delta: BTreeMap<[u8; 32], ReplierCredV3> = self
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
                // LWW first (issue #52): a losing or already-held cred is
                // never verified, so replaying known creds costs no RSA.
                if self
                    .creds
                    .get(key)
                    .is_some_and(|existing| existing.content_hash() >= cred.content_hash())
                {
                    continue;
                }
                cred.check(key, &parameters.ghostkey_master)?;
                self.creds.insert(*key, cred.clone());
            }
            Ok(())
        }
    }

    // ---- pointers: capped log, tiered caps and eviction ----

    /// Domain tag for pointer signatures (issue #47); the version suffix
    /// doubles as the inbox-generation discriminator.
    pub const INBOX_PTR_SIGN_DOMAIN: &[u8] = b"freebird-inbox-ptr-v3";

    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub struct ReplyPointerV3 {
        /// The INBOX OWNER's posting key bytes (issue #46): part of the
        /// signed payload and checked against `parameters.owner`, so a
        /// pointer signed for one inbox is invalid in every other. Also what
        /// makes the v3 pointer CBOR-distinct from v2.
        pub owner: [u8; 32],
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

    impl ReplyPointerV3 {
        /// The exact bytes the replier signs (issue #47): domain tag +
        /// canonical field layout, never bare CBOR.
        pub fn signing_payload(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(
                INBOX_PTR_SIGN_DOMAIN.len() + 32 + 32 + 4 + self.fingerprint.len() + 16 + 16 + 8,
            );
            out.extend_from_slice(INBOX_PTR_SIGN_DOMAIN);
            out.extend_from_slice(&self.owner);
            out.extend_from_slice(&self.replier);
            out.extend_from_slice(&(self.fingerprint.len() as u32).to_le_bytes());
            out.extend_from_slice(self.fingerprint.as_bytes());
            out.extend_from_slice(&self.target_post.0);
            out.extend_from_slice(&self.reply_post.0);
            out.extend_from_slice(&self.time.to_le_bytes());
            out
        }
    }

    /// Pointer + signature by the replier's POSTING key.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct AuthorizedReplyPointerV3 {
        pub ptr: ReplyPointerV3,
        pub signature: Signature,
        /// Anonymous proof-of-work nonce (issue #51): solved over the inbox
        /// owner + replier key (see `freebird_pow::meets_inbox`). Ignored for
        /// attested pointers — the ghost key skips PoW. Not covered by the
        /// signature: tampering only breaks the PoW check, never the binding.
        #[serde(default)]
        pub pow_nonce: u64,
    }

    impl AuthorizedReplyPointerV3 {
        pub fn new(ptr: ReplyPointerV3, signing_key: &ed25519_dalek::SigningKey) -> Self {
            use ed25519_dalek::Signer;
            Self {
                signature: signing_key.sign(&ptr.signing_payload()),
                ptr,
                pow_nonce: 0,
            }
        }

        /// An anonymous pointer carrying a proof-of-work stamp solved to
        /// `bits` (issue #51). Solving is a pure integer loop; keep it off the
        /// UI thread.
        pub fn new_anon(
            ptr: ReplyPointerV3,
            signing_key: &ed25519_dalek::SigningKey,
            bits: u8,
        ) -> Self {
            let nonce = freebird_pow::solve_inbox(&ptr.owner, &ptr.replier, bits);
            let mut p = Self::new(ptr, signing_key);
            p.pow_nonce = nonce;
            p
        }

        pub fn verify_signature(&self, posting_key: &VerifyingKey) -> Result<(), String> {
            posting_key
                .verify_strict(&self.ptr.signing_payload(), &self.signature)
                .map_err(|e| format!("pointer signature invalid: {e}"))
        }

        fn is_anon(&self) -> bool {
            is_anon_fingerprint(&self.ptr.fingerprint)
        }
    }

    pub type PointerOrderKey = (u64, PostId);

    fn order_key(p: &AuthorizedReplyPointerV3) -> PointerOrderKey {
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
    /// state and its inbox binding (issue #46). A missing cred OR a
    /// fingerprint mismatch drops the pointer rather than failing the delta:
    /// the mismatch happens honestly when a posting key's cred upgrades
    /// anon→attested while old pointers are still circulating, and an honest
    /// peer's delta must never be poison-pilled by it. A bad signature or a
    /// pointer bound to ANOTHER inbox is fatal — no honest peer ever holds
    /// one.
    fn check_pointer(
        p: &AuthorizedReplyPointerV3,
        creds: &BTreeMap<[u8; 32], ReplierCredV3>,
        parameters: &InboxParametersV3,
    ) -> Result<bool, String> {
        if p.ptr.owner != parameters.owner.to_bytes() {
            return Err("pointer bound to another inbox".into());
        }
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
    pub struct PointersV3Summary {
        pub ids: BTreeSet<PostId>,
        pub attested_horizon: TierHorizon,
        pub anon_horizon: TierHorizon,
        /// Per-fingerprint retention: for every fingerprint AT its tier cap,
        /// the oldest key retained for it (see v1 for the livelock class
        /// this prevents).
        pub fp_horizons: BTreeMap<String, PointerOrderKey>,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct PointersV3 {
        /// Sorted ascending by `(time, reply_post)`.
        pub pointers: Vec<AuthorizedReplyPointerV3>,
    }

    impl PointersV3 {
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

    impl ComposableState for PointersV3 {
        type ParentState = InboxStateV3;
        type Summary = PointersV3Summary;
        type Delta = Vec<AuthorizedReplyPointerV3>;
        type Parameters = InboxParametersV3;

        fn verify(
            &self,
            parent: &Self::ParentState,
            parameters: &Self::Parameters,
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
                if !check_pointer(p, &parent.creds.creds, parameters)? {
                    return Err("pointer without matching credential".into());
                }
                // Every seated anonymous pointer must clear the COMPILED PoW
                // floor (issue #51): the convergent, adversary-facing check
                // that a fabricated full state cannot seat a free anonymous
                // share. check_pointer already bound `owner` to this inbox.
                // The control-cell difficulty is enforced at admission only,
                // so raising it never retroactively bricks seated pointers.
                if p.is_anon()
                    && !freebird_pow::meets_inbox(
                        &parameters.owner.to_bytes(),
                        &p.ptr.replier,
                        p.pow_nonce,
                        freebird_pow::POW_FLOOR_BITS,
                    )
                {
                    return Err("anonymous pointer below the proof-of-work floor".into());
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
            PointersV3Summary {
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
            let retained = |p: &AuthorizedReplyPointerV3| {
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
            let delta: Vec<AuthorizedReplyPointerV3> = self
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
            parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(delta) = delta else { return Ok(()) };
            // parent here is the in-progress state: the macro applies creds
            // first (field order), so a self-contained delta's creds are
            // visible. Pointers with no credential are dropped, not fatal.
            let mut accepted: Vec<AuthorizedReplyPointerV3> = Vec::new();
            for p in delta {
                if check_pointer(p, &parent.creds.creds, parameters)? {
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
        cred: ReplierCredV3,
        key: [u8; 32],
    }

    fn attested_replier(authority: &TestAuthority) -> Replier {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let attestation = authority.attest(&sk);
        Replier {
            key: vk.to_bytes(),
            cred: ReplierCredV3 {
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
            cred: ReplierCredV3 {
                posting_key: vk,
                attestation: None,
            },
            sk,
        }
    }

    fn params(authority: &TestAuthority) -> InboxParametersV3 {
        InboxParametersV3 {
            owner: SigningKey::generate(&mut OsRng).verifying_key(),
            ghostkey_master: authority.master_vk,
        }
    }

    fn pointer_for(
        r: &Replier,
        p: &InboxParametersV3,
        time: u64,
        tag: u64,
    ) -> AuthorizedReplyPointerV3 {
        let ptr = ReplyPointerV3 {
            owner: p.owner.to_bytes(),
            replier: r.key,
            fingerprint: r.cred.fingerprint(),
            target_post: PostId([1u8; 16]),
            reply_post: PostId::compute(&r.sk.verifying_key(), time, &format!("r{tag}"), &None),
            time,
        };
        // Anonymous pointers carry a floor-difficulty PoW stamp (issue #51);
        // attested pointers skip PoW.
        if r.cred.attestation.is_none() {
            AuthorizedReplyPointerV3::new_anon(ptr, &r.sk, freebird_pow::POW_FLOOR_BITS)
        } else {
            AuthorizedReplyPointerV3::new(ptr, &r.sk)
        }
    }

    fn delta_of(
        creds: Vec<&Replier>,
        pointers: Vec<AuthorizedReplyPointerV3>,
    ) -> Option<InboxStateV3Delta> {
        let creds_map: std::collections::BTreeMap<[u8; 32], ReplierCredV3> = creds
            .into_iter()
            .map(|r| (r.key, r.cred.clone()))
            .collect();
        Some(InboxStateV3Delta {
            creds: (!creds_map.is_empty()).then_some(creds_map),
            pointers: (!pointers.is_empty()).then_some(pointers),
            pow_difficulty: None,
        })
    }

    fn apply(state: &mut InboxStateV3, p: &InboxParametersV3, delta: Option<InboxStateV3Delta>) {
        let clone = state.clone();
        state.apply_delta(&clone, p, &delta).expect("apply ok");
    }

    // ---- crypto path ----

    #[test]
    fn anon_pointer_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer_for(&r, &p, 5, 0)]));
        assert_eq!(s.pointers.pointers.len(), 1);
        assert!(is_anon_fingerprint(&s.pointers.pointers[0].ptr.fingerprint));
        s.verify(&s.clone(), &p).expect("verifies");
    }

    #[test]
    fn attested_pointer_accepted_and_state_verifies() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&authority);
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer_for(&r, &p, 5, 0)]));
        assert_eq!(s.pointers.pointers.len(), 1);
        s.verify(&s.clone(), &p).expect("verifies");
    }

    #[test]
    fn pointer_without_cred_is_dropped() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![], vec![pointer_for(&r, &p, 5, 0)]));
        assert!(s.pointers.pointers.is_empty());
    }

    #[test]
    fn cred_with_bad_attestation_rejected() {
        let authority = TestAuthority::new();
        let rogue_authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&rogue_authority); // wrong master
        let mut s = InboxStateV3::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![pointer_for(&r, &p, 5, 0)]))
            .is_err());
    }

    /// Issue #52: a cred losing the per-key LWW is skipped before
    /// verification — a malformed losing cred no longer fails the delta,
    /// and replaying held creds costs no RSA.
    #[test]
    fn losing_cred_never_verified() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&authority);
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![pointer_for(&r, &p, 5, 0)]));
        // Anonymous cred under r's map key but the WRONG posting key:
        // check() would be fatal, but it loses the LWW (anon hashes as
        // zero) and must be skipped.
        let stranger = anon_replier();
        let clone = s.clone();
        s.apply_delta(
            &clone,
            &p,
            &Some(InboxStateV3Delta {
                creds: Some([(r.key, stranger.cred.clone())].into_iter().collect()),
                pointers: None,
                pow_difficulty: None,
            }),
        )
        .expect("losing cred skipped, not verified");
        assert!(s.creds.creds[&r.key].attestation.is_some());
    }

    #[test]
    fn forged_pointer_signature_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        let other = anon_replier();
        let mut s = InboxStateV3::default();
        // Pointer claims r's identity but is signed by other's key. A valid
        // PoW stamp (over r's key) clears admission so the FORGED SIGNATURE is
        // what fails — otherwise the under-PoW drop would mask it.
        let mut fake = pointer_for(&other, &p, 5, 0);
        fake.ptr.replier = r.key;
        fake.ptr.fingerprint = r.cred.fingerprint();
        let mut fake = AuthorizedReplyPointerV3::new(fake.ptr, &other.sk);
        fake.pow_nonce =
            freebird_pow::solve_inbox(&fake.ptr.owner, &fake.ptr.replier, freebird_pow::POW_FLOOR_BITS);
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![fake]))
            .is_err());
    }

    // ---- proof-of-work (issue #51) ----

    /// An anonymous pointer with a missing/invalid stamp is dropped at
    /// admission and makes a fabricated full state fail verify.
    #[test]
    fn anon_without_valid_pow_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = anon_replier();
        // Build a valid anon pointer, then strip the stamp.
        let mut ptr = pointer_for(&r, &p, 5, 0);
        ptr.pow_nonce = 0; // nonce 0 clears 20 bits with prob 2^-20

        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![ptr.clone()]));
        assert!(s.pointers.pointers.is_empty(), "unstamped anon pointer dropped");

        // A fabricated full state carrying it must not verify.
        let mut fabricated = InboxStateV3::default();
        fabricated.creds.creds.insert(r.key, r.cred.clone());
        fabricated.pointers.pointers.push(ptr);
        assert!(fabricated.verify(&fabricated.clone(), &p).is_err());
    }

    /// The ghost-key (attested) path skips PoW: an attested pointer with no
    /// stamp is admitted and verifies.
    #[test]
    fn attested_skips_pow() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let r = attested_replier(&authority);
        let ptr = pointer_for(&r, &p, 5, 0);
        assert_eq!(ptr.pow_nonce, 0, "attested pointers carry no stamp");
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![ptr]));
        assert_eq!(s.pointers.pointers.len(), 1);
        s.verify(&s.clone(), &p).expect("verifies");
    }

    /// A stamp solved for inbox A is worthless in inbox B (bound to the owner).
    #[test]
    fn pow_stamp_not_reusable_across_inboxes() {
        let authority = TestAuthority::new();
        let pa = params(&authority);
        let pb = params(&authority);
        assert_ne!(pa.owner, pb.owner);
        let r = anon_replier();
        // A pointer legitimately signed for inbox B, but stamped for inbox A's
        // owner. The signature stays valid (owner is unchanged); only the PoW
        // binding is wrong, so admission drops it.
        let mut ptr = pointer_for(&r, &pb, 5, 0);
        ptr.pow_nonce =
            freebird_pow::solve_inbox(&pa.owner.to_bytes(), &r.key, freebird_pow::POW_FLOOR_BITS);
        let mut s = InboxStateV3::default();
        apply(&mut s, &pb, delta_of(vec![&r], vec![ptr]));
        assert!(s.pointers.pointers.is_empty(), "A's stamp must not admit in B");
    }

    /// Difficulty sourced from the control cell: a publisher-signed record
    /// raises the admission bar, so a floor-only stamp is dropped while one
    /// solved to the control difficulty is admitted.
    #[test]
    fn control_cell_difficulty_raises_bar() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let publisher = SigningKey::from_bytes(&freebird_pow::PUBLISHER_TEST_SECRET);
        let control = 22u8; // > POW_FLOOR_BITS (20)
        let record = cell_contract::SignedCellV1::new(
            &publisher,
            freebird_pow::POW_PURPOSE,
            1,
            freebird_pow::difficulty_body(control),
        );
        let r = anon_replier();

        // Stamp pinned to the [floor, control) band → provably under the
        // raised bar. A plain floor solve also clears `control` ~2^-(control-
        // floor) of the time, which would flake.
        let mut weak = pointer_for(&r, &p, 5, 0);
        weak.pow_nonce = freebird_pow::solve_inbox_band(
            &p.owner.to_bytes(),
            &r.key,
            freebird_pow::POW_FLOOR_BITS,
            control,
        );
        let mut s = InboxStateV3::default();
        let clone = s.clone();
        s.apply_delta(
            &clone,
            &p,
            &Some(InboxStateV3Delta {
                creds: Some([(r.key, r.cred.clone())].into_iter().collect()),
                pointers: Some(vec![weak]),
                pow_difficulty: Some(record.clone()),
            }),
        )
        .expect("delta ok");
        assert!(s.pointers.pointers.is_empty(), "floor stamp rejected under raised difficulty");

        // Solved to the control difficulty → admitted.
        let ptr = ReplyPointerV3 {
            owner: p.owner.to_bytes(),
            replier: r.key,
            fingerprint: r.cred.fingerprint(),
            target_post: PostId([1u8; 16]),
            reply_post: PostId::compute(&r.sk.verifying_key(), 6, "strong", &None),
            time: 6,
        };
        let strong = AuthorizedReplyPointerV3::new_anon(ptr, &r.sk, control);
        let clone = s.clone();
        s.apply_delta(
            &clone,
            &p,
            &Some(InboxStateV3Delta {
                creds: Some([(r.key, r.cred.clone())].into_iter().collect()),
                pointers: Some(vec![strong]),
                pow_difficulty: Some(record),
            }),
        )
        .expect("delta ok");
        assert_eq!(s.pointers.pointers.len(), 1, "control-difficulty stamp accepted");
    }

    /// Issue #46: a pointer signed for inbox A must fail validation in
    /// inbox B — cross-inbox replay is dead.
    #[test]
    fn cross_inbox_replay_rejected() {
        let authority = TestAuthority::new();
        let pa = params(&authority);
        let pb = params(&authority); // different random owner
        assert_ne!(pa.owner, pb.owner);
        let r = anon_replier();
        let harvested = pointer_for(&r, &pa, 5, 0);

        // Replayed verbatim into inbox B: fatal at apply.
        let mut b = InboxStateV3::default();
        let clone = b.clone();
        let err = b
            .apply_delta(&clone, &pb, &delta_of(vec![&r], vec![harvested.clone()]))
            .expect_err("replay must fail");
        assert!(err.contains("another inbox"), "{err}");

        // A fabricated full state carrying it must not verify either.
        let mut fabricated = InboxStateV3::default();
        fabricated.creds.creds.insert(r.key, r.cred.clone());
        fabricated.pointers.pointers.push(harvested.clone());
        assert!(fabricated.verify(&fabricated.clone(), &pb).is_err());

        // Rewriting the owner field breaks the signature instead. Re-stamp
        // for inbox B so the pointer clears PoW admission and the BROKEN
        // SIGNATURE is what fails (otherwise the wrong-binding stamp would be
        // dropped first, masking the signature check).
        let mut rewritten = harvested;
        rewritten.ptr.owner = pb.owner.to_bytes();
        rewritten.pow_nonce =
            freebird_pow::solve_inbox(&pb.owner.to_bytes(), &r.key, freebird_pow::POW_FLOOR_BITS);
        let mut b = InboxStateV3::default();
        let clone = b.clone();
        assert!(b
            .apply_delta(&clone, &pb, &delta_of(vec![&r], vec![rewritten]))
            .is_err());
    }

    /// Issue #46: the v3 pointer wire type is CBOR-distinct from v2.
    #[test]
    fn v3_pointer_cbor_distinct_from_v2() {
        // The exact v2 wire shape (no `owner`), as the retired v2 contract
        // serialized it.
        #[derive(serde::Serialize)]
        struct ReplyPointerV2Wire {
            replier: [u8; 32],
            fingerprint: String,
            target_post: PostId,
            reply_post: PostId,
            time: u64,
        }
        let v2 = freebird_core::to_cbor(&ReplyPointerV2Wire {
            replier: [9u8; 32],
            fingerprint: "gk".into(),
            target_post: PostId([1u8; 16]),
            reply_post: PostId([2u8; 16]),
            time: 5,
        })
        .unwrap();
        assert!(
            freebird_core::from_cbor::<ReplyPointerV3>(&v2).is_err(),
            "a v2 pointer must not decode as v3"
        );
    }

    /// Wire-format KAT (issue #47) for the pointer signing payload.
    #[test]
    fn pointer_signing_payload_kat() {
        let ptr = ReplyPointerV3 {
            owner: [0xAAu8; 32],
            replier: [0xBBu8; 32],
            fingerprint: "fp".into(),
            target_post: PostId([0x11; 16]),
            reply_post: PostId([0x22; 16]),
            time: 0x0102030405060708,
        };
        assert_eq!(
            data_encoding::HEXLOWER.encode(&ptr.signing_payload()),
            "66726565626972642d696e626f782d7074722d7633aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02000000667011111111111111111111111111111111222222222222222222222222222222220807060504030201"
        );
    }

    /// Issue #45 "cred-slot seizure": an attacker minting an attestation
    /// over the victim's posting key WITHOUT the victim's cooperation must
    /// not be able to seize the victim's cred slot (the attested cred would
    /// out-rank the victim's anon cred in the LWW and orphan every honest
    /// pointer).
    #[test]
    fn cred_slot_seizure_without_consent_rejected() {
        let authority = TestAuthority::new();
        let p = params(&authority);
        let victim = anon_replier();
        let attacker_sk = SigningKey::generate(&mut OsRng);

        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&victim], vec![pointer_for(&victim, &p, 5, 0)]));
        s.verify(&s.clone(), &p).expect("honest state valid");

        // Attacker's forged cred: attestation over the victim's key, pop by
        // the attacker.
        let forged = ReplierCredV3 {
            posting_key: victim.sk.verifying_key(),
            attestation: Some(authority.mint_v2(
                TestAuthority::freebird_requestor(),
                &freebird_core::attestation::AttestationV2::payload_for(
                    &victim.sk.verifying_key(),
                ),
                &attacker_sk,
            )),
        };
        let clone = s.clone();
        assert!(s
            .apply_delta(
                &clone,
                &p,
                &Some(InboxStateV3Delta {
                    creds: Some([(victim.key, forged)].into_iter().collect()),
                    pointers: None,
                    pow_difficulty: None,
                }),
            )
            .is_err());
        // The victim's anon cred and pointer are untouched.
        assert!(s.creds.creds[&victim.key].attestation.is_none());
        assert_eq!(s.pointers.pointers.len(), 1);
        s.verify(&s.clone(), &p).expect("still valid");
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
        let mut forged = pointer_for(&r, &p, 5, 0);
        forged.ptr.fingerprint = "NotMyHash".into(); // unprefixed = attested tier
        let forged = AuthorizedReplyPointerV3::new(forged.ptr, &r.sk);
        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r], vec![forged.clone()]));
        assert!(s.pointers.pointers.is_empty(), "forged-tier pointer dropped");

        // A full state holding a mismatched fingerprint must not verify.
        let mut fabricated = InboxStateV3::default();
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

        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&r1], vec![pointer_for(&r1, &p, 5, 0)]));
        s.verify(&s.clone(), &p).expect("valid after first reply");

        apply(&mut s, &p, delta_of(vec![&r2], vec![]));
        apply(&mut s, &p, delta_of(vec![&r2], vec![pointer_for(&r2, &p, 6, 1)]));

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
            cred: ReplierCredV3 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk)),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };

        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&anon], vec![pointer_for(&anon, &p, 5, 0)]));
        apply(
            &mut s,
            &p,
            delta_of(vec![&attested], vec![pointer_for(&attested, &p, 6, 1)]),
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

        let mut s = InboxStateV3::default();
        apply(&mut s, &p, delta_of(vec![&honest], vec![pointer_for(&honest, &p, 1, 0)]));
        let flood: Vec<_> = (0..20).map(|i| pointer_for(&spammer, &p, 100 + i, i)).collect();
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
        let mut s = InboxStateV3::default();
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
        let mut s = InboxStateV3::default();
        s.creds.creds.insert(r.key, r.cred.clone());
        assert!(s.verify(&s.clone(), &p).is_err());
    }

    /// Issue #49 quiescence, attacker variant: delta→apply round-trips
    /// against a holder of orphan creds shrink to empty instead of
    /// re-offering the pruned creds forever.
    #[test]
    fn attacker_orphan_cred_offers_go_quiescent() {
        let authority = TestAuthority::new();
        let p = params(&authority);

        // Attacker: one legitimate cred+pointer plus 5 orphan creds.
        let legit = anon_replier();
        let mut attacker = InboxStateV3::default();
        apply(
            &mut attacker,
            &p,
            delta_of(vec![&legit], vec![pointer_for(&legit, &p, 5, 0)]),
        );
        for _ in 0..5 {
            let r = anon_replier();
            attacker.creds.creds.insert(r.key, r.cred.clone());
        }
        assert!(
            attacker.verify(&attacker.clone(), &p).is_err(),
            "attacker state must be rejected at validate"
        );

        // Round 1: only the referenced cred and its pointer are offered.
        let mut receiver = InboxStateV3::default();
        let rs = receiver.summarize(&receiver.clone(), &p);
        let d = attacker.delta(&attacker.clone(), &p, &rs).expect("offers");
        assert_eq!(d.creds.as_ref().map(|c| c.len()), Some(1), "orphans withheld");
        apply(&mut receiver, &p, Some(d));
        receiver.verify(&receiver.clone(), &p).expect("receiver valid");

        // Round 2: nothing left to offer — the loop is closed.
        let rs = receiver.summarize(&receiver.clone(), &p);
        assert!(attacker.delta(&attacker.clone(), &p, &rs).is_none());

        // A raw delta smuggling the orphans is pruned without changing the
        // receiver's summary — no progress an attacker can force.
        let before = receiver.summarize(&receiver.clone(), &p);
        apply(
            &mut receiver,
            &p,
            Some(InboxStateV3Delta {
                creds: Some(attacker.creds.creds.clone()),
                pointers: None,
                pow_difficulty: None,
            }),
        );
        assert_eq!(receiver.summarize(&receiver.clone(), &p), before);
        receiver.verify(&receiver.clone(), &p).expect("receiver valid");
    }

    /// Issue #49: a junk-signature stapling pointer must not buy the cred's
    /// RSA verification — the delta fails on the pointer signature, never
    /// reaching cred.check.
    #[test]
    fn junk_staple_pointer_does_not_buy_rsa_check() {
        let authority = TestAuthority::new();
        let rogue = TestAuthority::new();
        let p = params(&authority);
        // Invalid attestation under p's master: cred.check would error at
        // the RSA stage if it ever ran.
        let r = attested_replier(&rogue);
        let mut staple = pointer_for(&r, &p, 5, 0);
        staple.signature = Signature::from_bytes(&[0u8; 64]);
        let mut s = InboxStateV3::default();
        let clone = s.clone();
        let err = s
            .apply_delta(&clone, &p, &delta_of(vec![&r], vec![staple]))
            .expect_err("junk staple must fail the delta");
        assert!(
            err.contains("pointer signature invalid"),
            "must fail at the pointer stage, not the RSA cred stage: {err}"
        );
        assert!(s.creds.creds.is_empty());
        assert!(s.pointers.pointers.is_empty());
    }

    /// Issue #49 quiescence, honest-traffic variant: a sender whose only
    /// pointer falls below the receiver's anon horizon must not re-offer
    /// its cred every round (the receiver would prune it each time).
    #[test]
    fn below_horizon_cred_not_reoffered() {
        let authority = TestAuthority::new();
        let p = params(&authority);

        // Receiver: anon share at cap (ANON_POINTER_SLOTS), all newer than
        // the sender's pointer.
        let mut receiver = InboxStateV3::default();
        let mut seated = 0;
        while seated < ANON_POINTER_SLOTS {
            let r = anon_replier();
            let n = MAX_PER_ANON_KEY.min(ANON_POINTER_SLOTS - seated);
            let ptrs: Vec<_> = (0..n)
                .map(|i| pointer_for(&r, &p, 1000 + (seated + i) as u64, (seated + i) as u64))
                .collect();
            apply(&mut receiver, &p, delta_of(vec![&r], ptrs));
            seated += n;
        }
        assert_eq!(receiver.pointers.pointers.len(), ANON_POINTER_SLOTS);

        // Sender: one honest cred+pointer, older than everything retained.
        let old = anon_replier();
        let mut sender = InboxStateV3::default();
        apply(&mut sender, &p, delta_of(vec![&old], vec![pointer_for(&old, &p, 5, 0)]));
        sender.verify(&sender.clone(), &p).expect("sender valid");

        // The pointer is below the horizon, so the cred must be withheld
        // too: the round-trip is quiescent immediately.
        let rs = receiver.summarize(&receiver.clone(), &p);
        assert!(
            sender.delta(&sender.clone(), &p, &rs).is_none(),
            "below-horizon cred re-offered: honest livelock"
        );
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
        let mut s = InboxStateV3::default();
        let clone = s.clone();
        assert!(s
            .apply_delta(
                &clone,
                &p,
                &Some(InboxStateV3Delta {
                    creds: Some(creds_map),
                    pointers: None,
                    pow_difficulty: None,
                }),
            )
            .is_err());
    }

    // ---- policy path: fabricated pointers, no crypto ----
    // canonicalize/summarize/delta only read fingerprints and order keys, so
    // these use dummy signatures and synthetic fingerprints (the same trick
    // as directory-contract's fake_listing) — minting hundreds of real RSA
    // attestation chains would take minutes.

    fn fake(fingerprint: &str, time: u64, tag: u64) -> AuthorizedReplyPointerV3 {
        let mut reply = [0u8; 16];
        reply[..8].copy_from_slice(&time.to_be_bytes());
        reply[8..].copy_from_slice(&tag.to_be_bytes());
        AuthorizedReplyPointerV3 {
            ptr: ReplyPointerV3 {
                owner: [0u8; 32],
                replier: [9u8; 32],
                fingerprint: fingerprint.into(),
                target_post: PostId([1u8; 16]),
                reply_post: PostId(reply),
                time,
            },
            signature: Signature::from_bytes(&[0u8; 64]),
            pow_nonce: 0,
        }
    }

    fn anon_fp(i: u64) -> String {
        format!("{ANON_FP_PREFIX}key{i}")
    }

    fn gk_fp(i: u64) -> String {
        format!("gk{i}")
    }

    fn pointers_of(v: Vec<AuthorizedReplyPointerV3>) -> PointersV3 {
        let mut p = PointersV3 { pointers: v };
        p.canonicalize();
        p
    }

    fn count_anon(p: &PointersV3) -> usize {
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

    fn summarize_pointers(p: &PointersV3) -> PointersV3Summary {
        let parent = InboxStateV3 {
            creds: Default::default(),
            pointers: p.clone(),
        };
        let params = InboxParametersV3 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        p.summarize(&parent, &params)
    }

    fn delta_against(p: &PointersV3, summary: &PointersV3Summary) -> Option<Vec<AuthorizedReplyPointerV3>> {
        let parent = InboxStateV3 {
            creds: Default::default(),
            pointers: p.clone(),
        };
        let params = InboxParametersV3 {
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

        let mut sender = InboxStateV3::default();
        apply(
            &mut sender,
            &p,
            delta_of(
                vec![&spammer],
                (0..MAX_PER_ANON_KEY as u64 + 5)
                    .map(|i| pointer_for(&spammer, &p, 100 + i, i))
                    .collect(),
            ),
        );
        let mut receiver = InboxStateV3::default();
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
                pointer_for(r, &p, *t, i as u64)
            }).collect();
            let mut order2 = pointers.clone();
            let n = order2.len();
            for i in 0..n {
                let j = ((seed as usize).wrapping_mul(17).wrapping_add(i * 3)) % n;
                order2.swap(i, j);
            }

            let mut s1 = InboxStateV3::default();
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
            let mut pointers = PointersV3 {
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

            let mut s1 = PointersV3::default();
            for chunk in pointers.chunks(7) {
                s1.pointers.extend(chunk.iter().cloned());
                s1.canonicalize();
            }
            let mut s2 = PointersV3::default();
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
        let s = InboxStateV3 {
            creds: Default::default(),
            pointers: PointersV3 {
                pointers: {
                    let mut v: Vec<_> =
                        (0..101).map(|i| fake(&anon_fp(i), i, i)).collect();
                    v.sort_by_key(|p| (p.ptr.time, p.ptr.reply_post));
                    v
                },
            },
        };
        let params = InboxParametersV3 {
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
            AuthorizedReplyPointerV3::new_anon(
                ReplyPointerV3 {
                    owner: p.owner.to_bytes(),
                    replier: r.key,
                    fingerprint: r.cred.fingerprint(),
                    target_post: PostId([1u8; 16]),
                    reply_post: reply,
                    time,
                },
                &r.sk,
                freebird_pow::POW_FLOOR_BITS,
            )
        };
        let dup = PostId([7u8; 16]);
        let other = PostId([8u8; 16]);
        let mut s = InboxStateV3::default();
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
        let params = InboxParametersV3 {
            owner: SigningKey::from_bytes(&[1u8; 32]).verifying_key(),
            ghostkey_master: SigningKey::from_bytes(&[2u8; 32]).verifying_key(),
        };
        let over_anon = InboxStateV3 {
            creds: Default::default(),
            pointers: PointersV3 {
                pointers: (0..MAX_PER_ANON_KEY as u64 + 1)
                    .map(|i| fake(&anon_fp(0), i, i))
                    .collect(),
            },
        };
        assert!(over_anon.pointers.verify(&over_anon, &params).is_err());
        let over_gk = InboxStateV3 {
            creds: Default::default(),
            pointers: PointersV3 {
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
        let mut s = InboxStateV3::default();
        apply(
            &mut s,
            &p,
            delta_of(
                vec![&r],
                vec![pointer_for(&r, &p, boundary, 0), pointer_for(&r, &p, boundary + 1, 1)],
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
            cred: ReplierCredV3 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk)),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };
        let anon_delta = delta_of(vec![&anon], vec![pointer_for(&anon, &p, 5, 0)]);
        let att_delta = delta_of(vec![&attested], vec![pointer_for(&attested, &p, 6, 1)]);

        let mut a = InboxStateV3::default();
        apply(&mut a, &p, anon_delta.clone());
        apply(&mut a, &p, att_delta.clone());

        let mut b = InboxStateV3::default();
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
            cred: ReplierCredV3 {
                posting_key: anon.sk.verifying_key(),
                attestation: Some(authority.attest(&anon.sk)),
            },
            sk: SigningKey::from_bytes(&anon.sk.to_bytes()),
            key: anon.key,
        };

        // Sender: pre-upgrade anon state. Receiver: post-upgrade state.
        let mut sender = InboxStateV3::default();
        apply(&mut sender, &p, delta_of(vec![&anon], vec![pointer_for(&anon, &p, 5, 0)]));
        let mut receiver = InboxStateV3::default();
        apply(
            &mut receiver,
            &p,
            delta_of(vec![&attested], vec![pointer_for(&attested, &p, 6, 1)]),
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
