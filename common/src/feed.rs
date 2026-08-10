//! Per-author feed state: profile + follows + optional attestation + capped
//! post log. Structured as freenet-scaffold composable components, patterned
//! on River's room state (see the design spec for which of River's hard-won
//! lessons are load-bearing here: retention horizon, canonical summaries,
//! idempotent cleanup).

use freenet_scaffold_macro::composable;

pub use components::*;

pub const MAX_POSTS: usize = 300;
pub const MAX_POST_BYTES: usize = 2048;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_BIO_BYTES: usize = 512;
pub const MAX_FOLLOWS: usize = 2000;
/// Entries stamped further than this past the local clock are scrubbed by the
/// contract shell (which has the host clock) — never inside the pure merge.
pub const MAX_FUTURE_MS: u64 = 600_000;

/// The full feed state. Field order is load-bearing: the composable macro
/// applies deltas in declaration order.
#[composable(post_apply_delta = "post_apply_cleanup")]
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct FeedStateV1 {
    pub profile: crate::types::AuthorizedProfile,
    pub follows: crate::types::AuthorizedFollows,
    pub attestation: AttestationSlot,
    pub posts: PostsV1,
}

impl FeedStateV1 {
    /// Idempotent canonicalization run after every delta application.
    /// Invariant: cleanup(s) == cleanup(cleanup(s)) — Freenet runs this a
    /// variable number of times per peer.
    pub fn post_apply_cleanup(
        &mut self,
        _parameters: &FeedParametersV1,
    ) -> Result<(), String> {
        self.posts.canonicalize();
        Ok(())
    }

    /// Drop entries stamped beyond `now_ms + MAX_FUTURE_MS`. Called by the
    /// contract shell (host clock) before validation/merge, and on stored
    /// state so pre-fix poison self-heals. Deliberately OUTSIDE the pure
    /// merge: a clock-dependent clamp inside the fold breaks convergence.
    pub fn scrub_future(&mut self, now_ms: u64) {
        self.posts
            .posts
            .retain(|p| p.post.time <= now_ms.saturating_add(MAX_FUTURE_MS));
    }
}

mod components {
    use crate::attestation::AttestationV1;
    use crate::types::{
        AuthorizedFollows, AuthorizedPost, AuthorizedProfile, PostId,
    };
    use ed25519_dalek::VerifyingKey;
    use freenet_scaffold::ComposableState;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeSet;

    use super::{FeedStateV1, MAX_BIO_BYTES, MAX_FOLLOWS, MAX_NAME_BYTES, MAX_POSTS, MAX_POST_BYTES};

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct FeedParametersV1 {
        /// The author's posting verifying key. Determines the contract
        /// address together with the master key below.
        pub author: VerifyingKey,
        /// Ghost Key trust anchor. Canonical clients derive feed addresses
        /// with the real Freenet master key, so an instance minted with a
        /// bogus anchor is simply unreachable from canonical clients — no
        /// in-contract allowlist needed.
        pub ghostkey_master: VerifyingKey,
    }

    // ---- profile: single-writer LWW by version ----

    impl ComposableState for AuthorizedProfile {
        type ParentState = FeedStateV1;
        type Summary = u32;
        type Delta = AuthorizedProfile;
        type Parameters = FeedParametersV1;

        fn verify(
            &self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            check_profile(self, &parameters.author)
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            self.profile.version
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_version: &Self::Summary,
        ) -> Option<Self::Delta> {
            (self.profile.version > *old_version).then(|| self.clone())
        }

        fn apply_delta(
            &mut self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(delta) = delta else { return Ok(()) };
            check_profile(delta, &parameters.author)?;
            // Stale/equal versions are a no-op (commutativity), except an
            // equal-version conflict, which resolves by canonical bytes so
            // every peer picks the same winner.
            if delta.profile.version > self.profile.version
                || (delta.profile.version == self.profile.version
                    && crate::to_cbor(delta)? > crate::to_cbor(self)?)
            {
                *self = delta.clone();
            }
            Ok(())
        }
    }

    fn check_profile(p: &AuthorizedProfile, author: &VerifyingKey) -> Result<(), String> {
        if p.profile.name.len() > MAX_NAME_BYTES {
            return Err("profile name too long".into());
        }
        if p.profile.bio.len() > MAX_BIO_BYTES {
            return Err("profile bio too long".into());
        }
        p.verify_signature(author)
    }

    // ---- follows: single-writer LWW by version ----

    impl ComposableState for AuthorizedFollows {
        type ParentState = FeedStateV1;
        type Summary = u32;
        type Delta = AuthorizedFollows;
        type Parameters = FeedParametersV1;

        fn verify(
            &self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            check_follows(self, &parameters.author)
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            self.follows.version
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_version: &Self::Summary,
        ) -> Option<Self::Delta> {
            (self.follows.version > *old_version).then(|| self.clone())
        }

        fn apply_delta(
            &mut self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(delta) = delta else { return Ok(()) };
            check_follows(delta, &parameters.author)?;
            if delta.follows.version > self.follows.version
                || (delta.follows.version == self.follows.version
                    && crate::to_cbor(delta)? > crate::to_cbor(self)?)
            {
                *self = delta.clone();
            }
            Ok(())
        }
    }

    fn check_follows(f: &AuthorizedFollows, author: &VerifyingKey) -> Result<(), String> {
        if f.follows.follows.len() > MAX_FOLLOWS {
            return Err("too many follows".into());
        }
        f.verify_signature(author)
    }

    // ---- attestation: optional, valid-beats-none, deterministic tie ----

    /// Check-mark slot. `None` = anonymous account. Merge rule: a verified
    /// attestation beats none; two different valid attestations tie-break by
    /// max content hash so all peers converge on the same one.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct AttestationSlot(pub Option<AttestationV1>);

    impl ComposableState for AttestationSlot {
        type ParentState = FeedStateV1;
        type Summary = Option<[u8; 32]>;
        type Delta = AttestationV1;
        type Parameters = FeedParametersV1;

        fn verify(
            &self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            match &self.0 {
                None => Ok(()),
                Some(att) => att
                    .verify(&parameters.author, Some(&parameters.ghostkey_master))
                    .map(|_tier| ()),
            }
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            self.0.as_ref().map(|a| a.content_hash())
        }

        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let mine = self.0.as_ref()?;
            match old_summary {
                None => Some(mine.clone()),
                Some(theirs) if mine.content_hash() > *theirs => Some(mine.clone()),
                Some(_) => None,
            }
        }

        fn apply_delta(
            &mut self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
            delta: &Option<Self::Delta>,
        ) -> Result<(), String> {
            let Some(incoming) = delta else { return Ok(()) };
            incoming.verify(&parameters.author, Some(&parameters.ghostkey_master))?;
            let replace = match &self.0 {
                None => true,
                Some(current) => incoming.content_hash() > current.content_hash(),
            };
            if replace {
                self.0 = Some(incoming.clone());
            }
            Ok(())
        }
    }

    // ---- posts: capped log with retention horizon ----

    pub type PostOrderKey = (u64, PostId);

    /// See River `message.rs` for the full derivation: a capped log's merge
    /// is non-monotonic, so a peer at capacity must publish the oldest key it
    /// retains or senders re-offer pruned entries forever (the 2026-07-25
    /// network incident).
    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
    pub enum RetentionHorizon {
        /// Below capacity; retains anything.
        Open,
        /// At capacity; discards anything ordering at or before this key.
        OldestRetained(PostOrderKey),
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct PostsSummary {
        /// BTreeSet so summary bytes are canonical (freenet-core#4857).
        pub ids: BTreeSet<PostId>,
        pub horizon: RetentionHorizon,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
    pub struct PostsV1 {
        /// Kept sorted ascending by `(time, id)`; newest last.
        pub posts: Vec<AuthorizedPost>,
    }

    fn order_key(p: &AuthorizedPost) -> PostOrderKey {
        (p.post.time, p.post.id)
    }

    fn check_post(p: &AuthorizedPost, author: &VerifyingKey) -> Result<(), String> {
        if p.post.content.len() > MAX_POST_BYTES {
            return Err(format!("post over {MAX_POST_BYTES} bytes"));
        }
        if p.post.id != PostId::compute(author, p.post.time, &p.post.content) {
            return Err("post id does not match content".into());
        }
        p.verify_signature(author)
    }

    impl PostsV1 {
        /// Sort, dedupe, truncate to cap. Idempotent.
        pub fn canonicalize(&mut self) {
            self.posts.sort_by_key(order_key);
            self.posts.dedup_by_key(|p| p.post.id);
            if self.posts.len() > MAX_POSTS {
                let excess = self.posts.len() - MAX_POSTS;
                self.posts.drain(0..excess);
            }
        }

        fn retention_horizon(&self) -> RetentionHorizon {
            if self.posts.len() < MAX_POSTS {
                RetentionHorizon::Open
            } else {
                // Sorted ascending, so the first entry is the oldest held.
                RetentionHorizon::OldestRetained(order_key(&self.posts[0]))
            }
        }
    }

    impl ComposableState for PostsV1 {
        type ParentState = FeedStateV1;
        type Summary = PostsSummary;
        type Delta = Vec<AuthorizedPost>;
        type Parameters = FeedParametersV1;

        fn verify(
            &self,
            _parent: &Self::ParentState,
            parameters: &Self::Parameters,
        ) -> Result<(), String> {
            if self.posts.len() > MAX_POSTS {
                return Err(format!("more than {MAX_POSTS} posts"));
            }
            let mut seen = BTreeSet::new();
            for pair in self.posts.windows(2) {
                if order_key(&pair[0]) > order_key(&pair[1]) {
                    return Err("posts not sorted".into());
                }
            }
            for p in &self.posts {
                check_post(p, &parameters.author)?;
                if !seen.insert(p.post.id) {
                    return Err("duplicate post id".into());
                }
            }
            Ok(())
        }

        fn summarize(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
        ) -> Self::Summary {
            PostsSummary {
                ids: self.posts.iter().map(|p| p.post.id).collect(),
                horizon: self.retention_horizon(),
            }
        }

        /// Deliberately does NOT read `parent_state`: in `merge` the receiver's
        /// state is passed while asking the sender for a delta. Everything
        /// needed about the receiver travels in the summary.
        fn delta(
            &self,
            _parent: &Self::ParentState,
            _parameters: &Self::Parameters,
            old_summary: &Self::Summary,
        ) -> Option<Self::Delta> {
            let retained_by_receiver = |p: &AuthorizedPost| match &old_summary.horizon {
                RetentionHorizon::Open => true,
                RetentionHorizon::OldestRetained(oldest) => order_key(p) > *oldest,
            };
            let delta: Vec<AuthorizedPost> = self
                .posts
                .iter()
                .filter(|p| !old_summary.ids.contains(&p.post.id))
                .filter(|p| retained_by_receiver(p))
                .cloned()
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
            for p in delta {
                check_post(p, &parameters.author)?;
            }
            self.posts.extend(delta.iter().cloned());
            self.canonicalize();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::fixtures::TestAuthority;
    use crate::types::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use freenet_scaffold::ComposableState;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    fn author() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn params(author_vk: VerifyingKey, master: VerifyingKey) -> FeedParametersV1 {
        FeedParametersV1 {
            author: author_vk,
            ghostkey_master: master,
        }
    }

    fn make_post(sk: &SigningKey, time: u64, content: &str) -> AuthorizedPost {
        let vk = sk.verifying_key();
        let post = PostV1 {
            id: PostId::compute(&vk, time, content),
            time,
            content: content.to_string(),
            in_reply_to: None,
        };
        AuthorizedPost::new(post, sk)
    }

    fn base_state(sk: &SigningKey) -> FeedStateV1 {
        FeedStateV1 {
            profile: AuthorizedProfile::new(
                ProfileV1 {
                    name: "a".into(),
                    bio: String::new(),
                    version: 1,
                },
                sk,
            ),
            follows: AuthorizedFollows::new(FollowsV1::default(), sk),
            attestation: AttestationSlot(None),
            posts: PostsV1::default(),
        }
    }

    fn posts_delta(posts: Vec<AuthorizedPost>) -> Option<FeedStateV1Delta> {
        Some(FeedStateV1Delta {
            profile: None,
            follows: None,
            attestation: None,
            posts: Some(posts),
        })
    }

    fn apply(state: &mut FeedStateV1, p: &FeedParametersV1, delta: Option<FeedStateV1Delta>) {
        let clone = state.clone();
        state.apply_delta(&clone, p, &delta).expect("apply ok");
    }

    #[test]
    fn post_roundtrip_and_verify() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        apply(&mut s, &p, posts_delta(vec![make_post(&sk, 10, "hello")]));
        assert_eq!(s.posts.posts.len(), 1);
        s.verify(&s.clone(), &p).expect("state verifies");
    }

    #[test]
    fn bad_signature_rejected() {
        let (sk, vk) = author();
        let (other_sk, _) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        let forged = make_post(&other_sk, 10, "forged");
        let clone = s.clone();
        assert!(s
            .apply_delta(&clone, &p, &posts_delta(vec![forged]))
            .is_err());
    }

    #[test]
    fn oversize_post_rejected() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        let big = make_post(&sk, 10, &"x".repeat(MAX_POST_BYTES + 1));
        let clone = s.clone();
        assert!(s.apply_delta(&clone, &p, &posts_delta(vec![big])).is_err());
    }

    #[test]
    fn post_cap_evicts_oldest() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        let posts: Vec<_> = (0..MAX_POSTS as u64 + 1)
            .map(|t| make_post(&sk, t, &format!("p{t}")))
            .collect();
        let oldest_id = posts[0].post.id;
        apply(&mut s, &p, posts_delta(posts));
        assert_eq!(s.posts.posts.len(), MAX_POSTS);
        assert!(s.posts.posts.iter().all(|x| x.post.id != oldest_id));
    }

    #[test]
    fn scrub_future_removes_far_future_posts() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        apply(
            &mut s,
            &p,
            posts_delta(vec![
                make_post(&sk, 1_000, "ok"),
                make_post(&sk, 1_000 + MAX_FUTURE_MS + 1, "from the future"),
            ]),
        );
        s.scrub_future(1_000);
        assert_eq!(s.posts.posts.len(), 1);
        assert_eq!(s.posts.posts[0].post.content, "ok");
    }

    #[test]
    fn profile_lww_newer_wins_stale_noop() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let mut s = base_state(&sk);
        let v3 = AuthorizedProfile::new(
            ProfileV1 {
                name: "v3".into(),
                bio: String::new(),
                version: 3,
            },
            &sk,
        );
        let v2 = AuthorizedProfile::new(
            ProfileV1 {
                name: "v2".into(),
                bio: String::new(),
                version: 2,
            },
            &sk,
        );
        for delta_profile in [v3.clone(), v2] {
            let clone = s.clone();
            s.apply_delta(
                &clone,
                &p,
                &Some(FeedStateV1Delta {
                    profile: Some(delta_profile),
                    follows: None,
                    attestation: None,
                    posts: None,
                }),
            )
            .unwrap();
        }
        assert_eq!(s.profile.profile.name, "v3");
    }

    #[test]
    fn attestation_valid_beats_none_and_tie_is_deterministic() {
        let (sk, vk) = author();
        let authority = TestAuthority::new();
        let p = params(vk, authority.master_vk);
        let att_a = authority.attest(&vk);
        let att_b = authority.attest(&vk);

        let mut s1 = base_state(&sk);
        let mut s2 = base_state(&sk);
        for (s, order) in [(&mut s1, [&att_a, &att_b]), (&mut s2, [&att_b, &att_a])] {
            for att in order {
                let clone = s.clone();
                s.apply_delta(
                    &clone,
                    &p,
                    &Some(FeedStateV1Delta {
                        profile: None,
                        follows: None,
                        attestation: Some((*att).clone()),
                        posts: None,
                    }),
                )
                .unwrap();
            }
        }
        assert!(s1.attestation.0.is_some());
        assert_eq!(s1.attestation, s2.attestation);
        s1.verify(&s1.clone(), &p).expect("attested state verifies");
    }

    #[test]
    fn attestation_for_wrong_author_rejected() {
        let (sk, vk) = author();
        let (_, other_vk) = author();
        let authority = TestAuthority::new();
        let p = params(vk, authority.master_vk);
        let att = authority.attest(&other_vk);
        let mut s = base_state(&sk);
        let clone = s.clone();
        assert!(s
            .apply_delta(
                &clone,
                &p,
                &Some(FeedStateV1Delta {
                    profile: None,
                    follows: None,
                    attestation: Some(att),
                    posts: None,
                }),
            )
            .is_err());
    }

    #[test]
    fn horizon_prevents_reoffer_livelock() {
        let (sk, vk) = author();
        let (_, master) = author();
        let p = params(vk, master);
        let all: Vec<_> = (0..MAX_POSTS as u64 + 10)
            .map(|t| make_post(&sk, t, &format!("p{t}")))
            .collect();

        // Peer A holds the newest window (at capacity).
        let mut a = base_state(&sk);
        apply(&mut a, &p, posts_delta(all.clone()));
        // Peer B holds an older window.
        let mut b = base_state(&sk);
        apply(&mut b, &p, posts_delta(all[..MAX_POSTS].to_vec()));

        let a_summary = a.summarize(&a.clone(), &p);
        let delta = b.delta(&b.clone(), &p, &a_summary);
        // Everything B could offer is below A's horizon: no delta at all.
        assert!(
            delta.is_none() || delta.as_ref().unwrap().posts.is_none(),
            "B must not re-offer posts A would immediately prune"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Applying any permutation of post deltas converges byte-identically.
        #[test]
        fn merge_commutative(times in proptest::collection::vec(0u64..1000, 1..30), seed in 0u64..1000) {
            let (sk, vk) = author();
            let (_, master) = author();
            let p = params(vk, master);
            let posts: Vec<_> = times.iter().map(|t| make_post(&sk, *t, &format!("c{t}"))).collect();

            let mut order2 = posts.clone();
            // Deterministic shuffle from seed.
            let n = order2.len();
            for i in 0..n {
                let j = ((seed as usize).wrapping_mul(31).wrapping_add(i * 7)) % n;
                order2.swap(i, j);
            }

            let mut s1 = base_state(&sk);
            for chunk in posts.chunks(3) {
                apply(&mut s1, &p, posts_delta(chunk.to_vec()));
            }
            let mut s2 = base_state(&sk);
            for chunk in order2.chunks(5) {
                apply(&mut s2, &p, posts_delta(chunk.to_vec()));
            }
            prop_assert_eq!(crate::to_cbor(&s1).unwrap(), crate::to_cbor(&s2).unwrap());
        }

        /// cleanup(cleanup(s)) == cleanup(s)
        #[test]
        fn cleanup_idempotent(times in proptest::collection::vec(0u64..1000, 0..40)) {
            let (sk, vk) = author();
            let (_, master) = author();
            let p = params(vk, master);
            let mut s = base_state(&sk);
            apply(&mut s, &p, posts_delta(times.iter().map(|t| make_post(&sk, *t, &format!("c{t}"))).collect()));
            let once = crate::to_cbor(&s).unwrap();
            s.post_apply_cleanup(&p).unwrap();
            prop_assert_eq!(once, crate::to_cbor(&s).unwrap());
        }

        /// Structurally equal states summarize byte-identically.
        #[test]
        fn summary_deterministic(times in proptest::collection::vec(0u64..1000, 1..30)) {
            let (sk, vk) = author();
            let (_, master) = author();
            let p = params(vk, master);
            let posts: Vec<_> = times.iter().map(|t| make_post(&sk, *t, &format!("c{t}"))).collect();
            let mut rev = posts.clone();
            rev.reverse();

            let mut s1 = base_state(&sk);
            apply(&mut s1, &p, posts_delta(posts));
            let mut s2 = base_state(&sk);
            apply(&mut s2, &p, posts_delta(rev));

            let sum1 = crate::to_cbor(&s1.summarize(&s1.clone(), &p)).unwrap();
            let sum2 = crate::to_cbor(&s2.summarize(&s2.clone(), &p)).unwrap();
            prop_assert_eq!(sum1, sum2);
        }
    }
}
