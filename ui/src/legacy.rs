//! Frozen wire types of the PREVIOUS LIVE generation, for the dual-read
//! window (issue #81).
//!
//! These mirror, byte-for-byte, the state the contracts vendored as
//! `ui/contracts/*_v1.wasm` actually hold on the network. They live in the
//! UI crate on purpose: a `legacy` module inside a contract crate is
//! compiled into that contract's wasm, so adding one would rotate the very
//! address the window is trying to read (the 2026-08-10 avatar incident).
//! Nothing here is ever written — decode, verify, display.
//!
//! What each type mirrors, as of the build live on 2026-08-13
//! (`scripts/live-build.txt`):
//!
//! | type                     | live source                                   |
//! |--------------------------|-----------------------------------------------|
//! | `LegacyDirectory*`       | `directory-contract` v2 (`DirectoryStateV2`)  |
//! | `LegacyInbox*`           | `inbox-contract` v2 (`InboxStateV2`)          |
//! | `check_legacy_avatar`    | `avatar-contract` pre-#47 (bare-CBOR sig)     |
//!
//! Verification repeats what the deployed contract enforced — the network
//! copy is untrusted input, and a listing/pointer/blob that fails here is
//! dropped rather than shown.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use freebird_core::attestation::AttestationV1;
use freebird_core::avatar::{AuthorizedAvatar, MAX_AVATAR_BYTES};
use freebird_core::types::PostId;
use serde::{Deserialize, Serialize};

// --------------------------------------------------------------------------
// Directory (live generation: directory-contract v2, seed "…-v2")
// --------------------------------------------------------------------------

/// Seed of the LIVE directory's params. Not `DIRECTORY_SEED_V1` — that names
/// a directory nobody has written to since before the v2 rotation, which is
/// exactly the bug in issue #81.
pub const LEGACY_DIRECTORY_SEED: &str = "freebird-directory-v2";

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyDirectoryParameters {
    pub seed: String,
    pub ghostkey_master: VerifyingKey,
}

/// Mirror of the live `AuthorizedListingV2`: the attestation is OPTIONAL
/// (anonymous parity, issue #23) and the signature covers bare-CBOR
/// `listing` only — the domain-tagged payload arrived with #47.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyAuthorizedListing {
    pub listing: directory_contract::ListingV1,
    pub signature: Signature,
    pub attestation: Option<AttestationV1>,
}

impl LegacyAuthorizedListing {
    /// The same checks the live contract runs.
    pub fn check(&self, master: &VerifyingKey) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.listing.author)
            .map_err(|e| format!("bad author key: {e}"))?;
        let bytes = freebird_core::to_cbor(&self.listing)?;
        vk.verify_strict(&bytes, &self.signature)
            .map_err(|e| format!("listing signature invalid: {e}"))?;
        if let Some(att) = &self.attestation {
            att.verify(&vk, Some(master))
                .map(|_tier| ())
                .map_err(|e| format!("listing attestation invalid: {e}"))?;
        }
        Ok(())
    }

    /// Per-author LWW winner, same key the live contract uses: an attested
    /// listing outranks a stripped copy of itself at equal `last_active`.
    pub fn lww_key(&self) -> (u64, bool, [u8; 32]) {
        let bytes = freebird_core::to_cbor(self).unwrap_or_default();
        (
            self.listing.last_active,
            self.attestation.is_some(),
            *blake3::hash(&bytes).as_bytes(),
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct LegacyDirectoryState {
    pub listings: BTreeMap<[u8; 32], LegacyAuthorizedListing>,
}

pub type LegacyDirectoryDelta = Vec<LegacyAuthorizedListing>;

impl LegacyDirectoryState {
    /// Read-side merge: verify, then keep the per-author LWW winner. New
    /// authors stop at the live contract's cap so a hostile peer cannot grow
    /// this map past what the network itself could hold; an in-place upgrade
    /// of an author already held is always allowed.
    pub fn merge(&mut self, master: &VerifyingKey, incoming: LegacyDirectoryDelta) {
        for l in incoming {
            if let Err(e) = l.check(master) {
                crate::api::log(&format!("rejected invalid legacy directory listing: {e}"));
                continue;
            }
            match self.listings.get(&l.listing.author) {
                Some(held) if held.lww_key() >= l.lww_key() => {}
                Some(_) => {
                    self.listings.insert(l.listing.author, l);
                }
                None if self.listings.len() < directory_contract::MAX_LISTINGS => {
                    self.listings.insert(l.listing.author, l);
                }
                None => {}
            }
        }
    }
}

// --------------------------------------------------------------------------
// Inbox (live generation: inbox-contract v2)
// --------------------------------------------------------------------------

/// The live inbox's anonymous fingerprint formula, frozen here rather than
/// called through `inbox_contract`: a future generation changing the formula
/// must not silently stop matching pointers the network already holds.
fn anon_fingerprint(posting_key: &[u8; 32]) -> String {
    format!(
        "anon:{}",
        bs58::encode(blake3::hash(posting_key).as_bytes()).into_string()
    )
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyInboxParameters {
    pub owner: VerifyingKey,
    pub ghostkey_master: VerifyingKey,
}

/// Mirror of the live `ReplierCredV2`. `attestation: None` = anonymous tier.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyReplierCred {
    pub posting_key: VerifyingKey,
    pub attestation: Option<AttestationV1>,
}

impl LegacyReplierCred {
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

    fn content_hash(&self) -> [u8; 32] {
        match &self.attestation {
            Some(att) => att.content_hash(),
            None => [0u8; 32],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct LegacyCreds {
    pub creds: BTreeMap<[u8; 32], LegacyReplierCred>,
}

/// Mirror of the live `ReplyPointerV2`. V3 added the inbox owner to the
/// signed bytes and moved to a domain-tagged layout, so the two signature
/// schemes are not interchangeable — hence this frozen copy.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LegacyReplyPointer {
    pub replier: [u8; 32],
    pub fingerprint: String,
    pub target_post: PostId,
    pub reply_post: PostId,
    pub time: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyAuthorizedReplyPointer {
    pub ptr: LegacyReplyPointer,
    pub signature: Signature,
}

impl LegacyAuthorizedReplyPointer {
    pub fn verify_signature(&self, posting_key: &VerifyingKey) -> Result<(), String> {
        let bytes = freebird_core::to_cbor(&self.ptr)?;
        posting_key
            .verify_strict(&bytes, &self.signature)
            .map_err(|e| format!("pointer signature invalid: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct LegacyPointers {
    pub pointers: Vec<LegacyAuthorizedReplyPointer>,
}

/// Mirror of the live `InboxStateV2` (field order is the wire order).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct LegacyInboxState {
    pub creds: LegacyCreds,
    pub pointers: LegacyPointers,
}

/// Mirror of the live `InboxStateV2Delta` (the `#[composable]` shape).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct LegacyInboxDelta {
    pub creds: Option<BTreeMap<[u8; 32], LegacyReplierCred>>,
    pub pointers: Option<Vec<LegacyAuthorizedReplyPointer>>,
}

impl LegacyInboxState {
    /// Read-side merge of a full state or a delta. Creds before pointers:
    /// a pointer is only kept once its credential is seated and its
    /// fingerprint agrees, the same gate the live contract applies.
    ///
    /// Not the contract's tiered eviction — display only, so the cheap
    /// global cap is enough to bound memory. Sorted and deduped by
    /// `reply_post` so the render order matches the live contract's.
    pub fn merge(&mut self, master: &VerifyingKey, delta: LegacyInboxDelta) {
        for (key, cred) in delta.creds.into_iter().flatten() {
            if let Err(e) = cred.check(&key, master) {
                crate::api::log(&format!("rejected legacy inbox credential: {e}"));
                continue;
            }
            match self.creds.creds.get(&key) {
                Some(held) if held.content_hash() >= cred.content_hash() => {}
                _ => {
                    self.creds.creds.insert(key, cred);
                }
            }
        }
        for p in delta.pointers.into_iter().flatten() {
            let Some(cred) = self.creds.creds.get(&p.ptr.replier) else {
                continue;
            };
            if p.verify_signature(&cred.posting_key).is_err()
                || p.ptr.fingerprint != cred.fingerprint()
            {
                continue;
            }
            if self
                .pointers
                .pointers
                .iter()
                .any(|held| held.ptr.reply_post == p.ptr.reply_post)
            {
                continue;
            }
            self.pointers.pointers.push(p);
        }
        self.pointers
            .pointers
            .sort_by_key(|p| (p.ptr.time, p.ptr.reply_post));
        // Over the live cap: drop the oldest, matching the contract's
        // "newest wins" retention closely enough for a read-only view.
        let over = self
            .pointers
            .pointers
            .len()
            .saturating_sub(freebird_core::inbox::MAX_POINTERS);
        self.pointers.pointers.drain(..over);
    }
}

impl From<LegacyInboxState> for LegacyInboxDelta {
    fn from(s: LegacyInboxState) -> Self {
        LegacyInboxDelta {
            creds: Some(s.creds.creds),
            pointers: Some(s.pointers.pointers),
        }
    }
}

// --------------------------------------------------------------------------
// Avatar (live generation: pre-#47 avatar-contract)
// --------------------------------------------------------------------------

/// `check_avatar` under the OLD signature rule: the author signed bare-CBOR
/// `AvatarV1`, not #47's domain-tagged payload. Everything else — size cap,
/// content-type allowlist, magic-byte sniff — is unchanged, and still runs:
/// the blob goes straight into an `<img>`.
pub fn check_legacy_avatar(a: &AuthorizedAvatar, author: &VerifyingKey) -> Result<(), String> {
    if a.avatar.data.len() > MAX_AVATAR_BYTES {
        return Err(format!("avatar over {MAX_AVATAR_BYTES} bytes"));
    }
    match a.avatar.content_type.as_str() {
        "image/png" | "image/jpeg" | "image/webp" => {}
        other => return Err(format!("unsupported avatar content-type: {other}")),
    }
    if freebird_core::avatar::sniff_mime(&a.avatar.data) != Some(a.avatar.content_type.as_str()) {
        return Err("avatar bytes do not match declared content-type".into());
    }
    let bytes = freebird_core::to_cbor(&a.avatar)?;
    author
        .verify_strict(&bytes, &a.signature)
        .map_err(|e| format!("legacy avatar signature invalid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freebird_core::avatar::AvatarV1;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn png(len: usize) -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.resize(len.max(8), 0);
        v
    }

    fn legacy_avatar(k: &SigningKey, time: u64) -> AuthorizedAvatar {
        let avatar = AvatarV1 {
            content_type: "image/png".into(),
            data: png(32),
            time,
        };
        let signature = k.sign(&freebird_core::to_cbor(&avatar).unwrap());
        AuthorizedAvatar { avatar, signature }
    }

    /// The whole point of the avatar leg: a blob signed the OLD way passes
    /// the legacy check and fails the current one. If this ever flips, the
    /// dual-read is either dead or accepting what the network rejects.
    #[test]
    fn legacy_avatar_checks_under_old_signature_only() {
        let k = sk(1);
        let a = legacy_avatar(&k, 7);
        assert!(check_legacy_avatar(&a, &k.verifying_key()).is_ok());
        assert!(freebird_core::avatar::check_avatar(&a, &k.verifying_key()).is_err());
    }

    #[test]
    fn legacy_avatar_rejects_other_signer() {
        let a = legacy_avatar(&sk(1), 7);
        assert!(check_legacy_avatar(&a, &sk(2).verifying_key()).is_err());
    }

    fn pointer(k: &SigningKey, reply: u8, time: u64) -> LegacyAuthorizedReplyPointer {
        let ptr = LegacyReplyPointer {
            replier: k.verifying_key().to_bytes(),
            fingerprint: anon_fingerprint(&k.verifying_key().to_bytes()),
            target_post: PostId([1u8; 16]),
            reply_post: PostId([reply; 16]),
            time,
        };
        let signature = k.sign(&freebird_core::to_cbor(&ptr).unwrap());
        LegacyAuthorizedReplyPointer { ptr, signature }
    }

    fn anon_cred(k: &SigningKey) -> LegacyReplierCred {
        LegacyReplierCred {
            posting_key: k.verifying_key(),
            attestation: None,
        }
    }

    /// Seats a signed pointer once its cred is present, and never twice.
    #[test]
    fn legacy_inbox_merges_signed_pointer_once() {
        let k = sk(3);
        let master = sk(9).verifying_key();
        let mut s = LegacyInboxState::default();
        s.merge(
            &master,
            LegacyInboxDelta {
                creds: Some([(k.verifying_key().to_bytes(), anon_cred(&k))].into()),
                pointers: Some(vec![pointer(&k, 5, 100)]),
            },
        );
        assert_eq!(s.pointers.pointers.len(), 1);
        s.merge(
            &master,
            LegacyInboxDelta {
                creds: None,
                pointers: Some(vec![pointer(&k, 5, 100)]),
            },
        );
        assert_eq!(s.pointers.pointers.len(), 1, "reply_post deduped");
    }

    /// A pointer with no seated credential, a forged signature, or a
    /// mismatched fingerprint is dropped — the same three gates the live
    /// contract applies.
    #[test]
    fn legacy_inbox_drops_uncredentialed_forged_and_mismatched() {
        let k = sk(3);
        let other = sk(4);
        let master = sk(9).verifying_key();

        let mut s = LegacyInboxState::default();
        s.merge(
            &master,
            LegacyInboxDelta {
                creds: None,
                pointers: Some(vec![pointer(&k, 5, 100)]),
            },
        );
        assert!(s.pointers.pointers.is_empty(), "no credential");

        let mut forged = pointer(&k, 6, 100);
        forged.ptr.time = 999;
        let mut mismatched = pointer(&k, 7, 100);
        mismatched.ptr.fingerprint = "anon:bogus".into();
        s.merge(
            &master,
            LegacyInboxDelta {
                creds: Some([(k.verifying_key().to_bytes(), anon_cred(&k))].into()),
                pointers: Some(vec![forged, mismatched]),
            },
        );
        assert!(s.pointers.pointers.is_empty(), "forged + mismatched dropped");

        // A cred stored under the wrong key never seats.
        s.merge(
            &master,
            LegacyInboxDelta {
                creds: Some([(other.verifying_key().to_bytes(), anon_cred(&k))].into()),
                pointers: None,
            },
        );
        assert!(
            !s.creds.creds.contains_key(&other.verifying_key().to_bytes()),
            "cred under wrong key rejected"
        );
    }
}
