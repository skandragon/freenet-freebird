//! Core wire types shared by contracts, delegate, and UI.
//!
//! Every signature here is over a MANUAL canonical byte layout with a domain
//! tag and length prefixes (issue #47), never bare CBOR: a ciborium encoding
//! change can no longer invalidate deployed signatures, and one posting key
//! signing many struct types can never produce interchangeable signatures.
//! The cell contract's `signing_payload` is the model. Wire-format KATs at
//! the bottom pin every layout.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const POST_SIGN_DOMAIN: &[u8] = b"freebird-post-v1";
pub const PROFILE_SIGN_DOMAIN: &[u8] = b"freebird-profile-v1";
pub const FOLLOWS_SIGN_DOMAIN: &[u8] = b"freebird-follows-v1";

/// Length-prefix a variable-length field (u32 le) — keeps every signing
/// payload injective across field boundaries.
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Post identifier: first 16 bytes of BLAKE3(author_vk ‖ time_be ‖ content).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PostId(pub [u8; 16]);

impl PostId {
    /// Binds EVERY content-bearing field — two posts differing only in
    /// `in_reply_to` must not collide, or arrival order forks peers silently
    /// (dedupe is by id).
    pub fn compute(
        author: &VerifyingKey,
        time: u64,
        content: &str,
        in_reply_to: &Option<PostRef>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(author.as_bytes());
        hasher.update(&time.to_be_bytes());
        hasher.update(content.as_bytes());
        if let Some(r) = in_reply_to {
            hasher.update(&r.author);
            hasher.update(&r.post.0);
        }
        let hash = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        PostId(id)
    }
}

/// Reference to a post in some author's feed.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PostRef {
    pub author: [u8; 32],
    pub post: PostId,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PostV1 {
    pub id: PostId,
    /// Milliseconds since the Unix epoch. Advisory; merge order uses it but
    /// far-future values are rejected outside the pure fold.
    pub time: u64,
    pub content: String,
    pub in_reply_to: Option<PostRef>,
}

impl PostV1 {
    /// The exact bytes the author signs: domain tag + canonical field layout.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(POST_SIGN_DOMAIN.len() + 16 + 8 + 4 + self.content.len() + 1 + 48);
        out.extend_from_slice(POST_SIGN_DOMAIN);
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.time.to_le_bytes());
        put_bytes(&mut out, self.content.as_bytes());
        match &self.in_reply_to {
            None => out.push(0),
            Some(r) => {
                out.push(1);
                out.extend_from_slice(&r.author);
                out.extend_from_slice(&r.post.0);
            }
        }
        out
    }
}

/// A post plus the author's signature over `post.signing_payload()`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPost {
    pub post: PostV1,
    pub signature: Signature,
}

impl AuthorizedPost {
    pub fn new(post: PostV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&post.signing_payload());
        Self { post, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        author
            .verify_strict(&self.post.signing_payload(), &self.signature)
            .map_err(|e| format!("post signature invalid: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ProfileV1 {
    pub name: String,
    pub bio: String,
    /// Strictly-increasing; highest valid version wins (LWW).
    pub version: u32,
}

impl ProfileV1 {
    /// The exact bytes the author signs: domain tag + canonical field layout.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PROFILE_SIGN_DOMAIN.len() + 4 + 8 + self.name.len() + self.bio.len(),
        );
        out.extend_from_slice(PROFILE_SIGN_DOMAIN);
        out.extend_from_slice(&self.version.to_le_bytes());
        put_bytes(&mut out, self.name.as_bytes());
        put_bytes(&mut out, self.bio.as_bytes());
        out
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedProfile {
    pub profile: ProfileV1,
    pub signature: Signature,
}

impl AuthorizedProfile {
    pub fn new(profile: ProfileV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&profile.signing_payload());
        Self { profile, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        author
            .verify_strict(&self.profile.signing_payload(), &self.signature)
            .map_err(|e| format!("profile signature invalid: {e}"))
    }
}

/// Public follow list: whole-set LWW by version. The set is small (keys only)
/// and single-writer, so per-entry CRDT ops buy nothing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct FollowsV1 {
    pub follows: BTreeSet<[u8; 32]>,
    pub version: u32,
}

impl FollowsV1 {
    /// The exact bytes the author signs. BTreeSet iterates sorted, so the
    /// layout is canonical for a given set.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FOLLOWS_SIGN_DOMAIN.len() + 8 + 32 * self.follows.len());
        out.extend_from_slice(FOLLOWS_SIGN_DOMAIN);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.follows.len() as u32).to_le_bytes());
        for key in &self.follows {
            out.extend_from_slice(key);
        }
        out
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedFollows {
    pub follows: FollowsV1,
    pub signature: Signature,
}

impl AuthorizedFollows {
    pub fn new(follows: FollowsV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&follows.signing_payload());
        Self { follows, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        author
            .verify_strict(&self.follows.signing_payload(), &self.signature)
            .map_err(|e| format!("follows signature invalid: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_post() -> PostV1 {
        PostV1 {
            id: PostId([0x11; 16]),
            time: 0x0102030405060708,
            content: "hello".into(),
            in_reply_to: Some(PostRef {
                author: [0x22; 32],
                post: PostId([0x33; 16]),
            }),
        }
    }

    fn fixed_profile() -> ProfileV1 {
        ProfileV1 {
            name: "ada".into(),
            bio: "b".into(),
            version: 7,
        }
    }

    fn fixed_follows() -> FollowsV1 {
        FollowsV1 {
            follows: [[0x44u8; 32], [0x55u8; 32]].into_iter().collect(),
            version: 9,
        }
    }

    /// Wire-format KATs (issue #47): reordering or renaming a signed field
    /// MUST fail these before it silently invalidates network signatures.
    #[test]
    fn post_signing_payload_kat() {
        assert_eq!(
            HEXLOWER.encode(&fixed_post().signing_payload()),
            "66726565626972642d706f73742d76311111111111111111111111111111111108070605040302010500000068656c6c6f01222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333"
        );
    }

    #[test]
    fn profile_signing_payload_kat() {
        assert_eq!(
            HEXLOWER.encode(&fixed_profile().signing_payload()),
            "66726565626972642d70726f66696c652d763107000000030000006164610100000062"
        );
    }

    #[test]
    fn follows_signing_payload_kat() {
        assert_eq!(
            HEXLOWER.encode(&fixed_follows().signing_payload()),
            "66726565626972642d666f6c6c6f77732d7631090000000200000044444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555"
        );
    }

    /// Domain separation: a signature over one type must not verify as any
    /// other type, even with attacker-chosen field values.
    #[test]
    fn cross_type_signature_reuse_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let post_sig = sk.sign(&fixed_post().signing_payload());

        let forged_profile = AuthorizedProfile {
            profile: fixed_profile(),
            signature: post_sig,
        };
        assert!(forged_profile.verify_signature(&vk).is_err());

        let forged_follows = AuthorizedFollows {
            follows: fixed_follows(),
            signature: post_sig,
        };
        assert!(forged_follows.verify_signature(&vk).is_err());

        // And every domain prefix is distinct by construction.
        let domains = [
            POST_SIGN_DOMAIN,
            PROFILE_SIGN_DOMAIN,
            FOLLOWS_SIGN_DOMAIN,
            crate::avatar::AVATAR_SIGN_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in &domains[i + 1..] {
                assert_ne!(a, b);
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    /// Length prefixes keep the layout injective on field boundaries.
    #[test]
    fn profile_payload_injective_on_name_bio_boundary() {
        let a = ProfileV1 {
            name: "ab".into(),
            bio: "c".into(),
            version: 1,
        };
        let b = ProfileV1 {
            name: "a".into(),
            bio: "bc".into(),
            version: 1,
        };
        assert_ne!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        assert!(AuthorizedPost::new(fixed_post(), &sk)
            .verify_signature(&vk)
            .is_ok());
        assert!(AuthorizedProfile::new(fixed_profile(), &sk)
            .verify_signature(&vk)
            .is_ok());
        assert!(AuthorizedFollows::new(fixed_follows(), &sk)
            .verify_signature(&vk)
            .is_ok());
    }
}
