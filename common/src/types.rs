//! Core wire types shared by contracts, delegate, and UI.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Post identifier: first 16 bytes of BLAKE3(author_vk ‖ time_be ‖ content).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PostId(pub [u8; 16]);

impl PostId {
    pub fn compute(author: &VerifyingKey, time: u64, content: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(author.as_bytes());
        hasher.update(&time.to_be_bytes());
        hasher.update(content.as_bytes());
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

/// A post plus the author's signature over `to_cbor(post)`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedPost {
    pub post: PostV1,
    pub signature: Signature,
}

impl AuthorizedPost {
    pub fn new(post: PostV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let bytes = crate::to_cbor(&post).expect("post serializes");
        let signature = signing_key.sign(&bytes);
        Self { post, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        let bytes = crate::to_cbor(&self.post)?;
        author
            .verify_strict(&bytes, &self.signature)
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedProfile {
    pub profile: ProfileV1,
    pub signature: Signature,
}

impl AuthorizedProfile {
    pub fn new(profile: ProfileV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let bytes = crate::to_cbor(&profile).expect("profile serializes");
        let signature = signing_key.sign(&bytes);
        Self { profile, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        let bytes = crate::to_cbor(&self.profile)?;
        author
            .verify_strict(&bytes, &self.signature)
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedFollows {
    pub follows: FollowsV1,
    pub signature: Signature,
}

impl AuthorizedFollows {
    pub fn new(follows: FollowsV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let bytes = crate::to_cbor(&follows).expect("follows serializes");
        let signature = signing_key.sign(&bytes);
        Self { follows, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        let bytes = crate::to_cbor(&self.follows)?;
        author
            .verify_strict(&bytes, &self.signature)
            .map_err(|e| format!("follows signature invalid: {e}"))
    }
}
