//! Frozen wire types of the PREVIOUS LIVE generation, for the dual-read
//! window (issue #81).
//!
//! These mirror, byte-for-byte, the state the contracts vendored as
//! `ui/contracts/*_v1.wasm` actually hold on the network. Nothing here is
//! ever written — decode, verify, display.
//!
//! They live in the UI crate on purpose. A `legacy` module inside a contract
//! crate is compiled into that contract's wasm, so adding one would rotate
//! that contract's CURRENT address — opening a second migration window
//! instead of closing this one (the 2026-08-10 avatar incident). The frozen
//! `_v1` address itself is derived from the vendored blob and is unaffected
//! by any source change; the cascade is what makes it forbidden.
//!
//! "Frozen" is enforced by `legacy_params_wire_format_kat` and
//! `legacy_state_wire_format_kat` below, not by the type system. Every other
//! test in this module signs and verifies through the same `to_cbor`, so it
//! passes for ANY self-consistent shape — the KATs are the only thing that
//! fails when a field is renamed, reordered, or retyped. Note the module
//! deliberately inlines `LegacyListing` and the caps rather than importing
//! them from the live crates, for the same reason.
//!
//! What each type mirrors, as of the build live on 2026-08-13
//! (`d873a2a`, committed 2026-08-11; `scripts/live-build.txt` is the source
//! of truth):
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

/// Caps of the LIVE generation, frozen as literals. Reading them from
/// `directory_contract` / `freebird_core` would let a future rotation change
/// what this mirror retains — the same "a live crate silently re-aims the
/// frozen copy" trap the `anon_fingerprint` comment below is about. These
/// are the values the live build enforces; they are not ours to follow.
const LEGACY_MAX_LISTINGS: usize = 1000;
const LEGACY_ANON_LISTINGS: usize = 250;
const LEGACY_MAX_POINTERS: usize = 300;
const LEGACY_ANON_POINTER_SLOTS: usize = 100;
const LEGACY_MAX_PER_FINGERPRINT: usize = 8;
const LEGACY_MAX_PER_ANON_KEY: usize = 3;

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

/// Mirror of the live `ListingV1`. Inlined rather than imported from
/// `directory-contract`: that crate is at v3/v4 and still evolving, so a
/// field added there would silently change this mirror's CBOR — breaking
/// both the decode and the signature check — with nothing failing to
/// compile.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyListing {
    pub author: [u8; 32],
    pub last_active: u64,
}

/// Mirror of the live `AuthorizedListingV2`: the attestation is OPTIONAL
/// (anonymous parity, issue #23) and the signature covers bare-CBOR
/// `listing` only — the domain-tagged payload arrived with #47.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LegacyAuthorizedListing {
    pub listing: LegacyListing,
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
    ///
    /// `expect`, matching the contract — NOT `unwrap_or_default()`. On a
    /// serialization failure the default would make the tiebreak a constant
    /// `blake3(b"")`, so two different listings would compare EQUAL and the
    /// merge would become arrival-order dependent, which is exactly the
    /// commutativity the contract's proptest exists to guarantee.
    pub fn lww_key(&self) -> (u64, bool, [u8; 32]) {
        let bytes = freebird_core::to_cbor(self).expect("listing serializes");
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
    /// Read-side merge: verify, keep the per-author LWW winner, then apply
    /// the live contract's tiered eviction.
    ///
    /// Insert-then-evict, NOT refuse-at-cap. Refusing whatever arrives once
    /// the map is full would select the surviving set by author-key BYTE
    /// ORDER (a full state arrives as a BTreeMap), so Discover would show a
    /// permanently different set from the network's — and an anonymous
    /// keygen flood could hold every slot against attested listings.
    pub fn merge(&mut self, master: &VerifyingKey, incoming: LegacyDirectoryDelta) {
        for l in incoming {
            if let Err(e) = l.check(master) {
                crate::api::log(&format!("rejected invalid legacy directory listing: {e}"));
                continue;
            }
            let newer = self
                .listings
                .get(&l.listing.author)
                .is_none_or(|held| held.lww_key() < l.lww_key());
            if newer {
                self.listings.insert(l.listing.author, l);
            }
        }
        self.canonicalize();
    }

    /// The live contract's `canonicalize`: over the anonymous share, evict
    /// the oldest anonymous; over the global cap, evict the oldest anonymous
    /// FIRST and an attested listing only when no anonymous remain —
    /// "verified is never crowded out by anonymous". Without the tier split
    /// a keygen flood displaces every verified author from Discover.
    fn canonicalize(&mut self) {
        let oldest = |m: &BTreeMap<[u8; 32], LegacyAuthorizedListing>, anon_only: bool| {
            m.values()
                .filter(|l| !anon_only || l.attestation.is_none())
                .map(|l| (l.listing.last_active, l.listing.author))
                .min()
        };
        let anon_count =
            |m: &BTreeMap<[u8; 32], LegacyAuthorizedListing>| {
                m.values().filter(|l| l.attestation.is_none()).count()
            };
        while anon_count(&self.listings) > LEGACY_ANON_LISTINGS {
            let Some((_, victim)) = oldest(&self.listings, true) else { break };
            self.listings.remove(&victim);
        }
        while self.listings.len() > LEGACY_MAX_LISTINGS {
            let Some((_, victim)) =
                oldest(&self.listings, true).or_else(|| oldest(&self.listings, false))
            else {
                break;
            };
            self.listings.remove(&victim);
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
    /// Read-side merge of a full state or a delta. Creds before pointers: a
    /// pointer is only kept once its credential is seated and its
    /// fingerprint agrees, the same gate the live contract applies.
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
        let mut sig_failures = 0usize;
        for p in delta.pointers.into_iter().flatten() {
            // Missing cred and fingerprint mismatch are ROUTINE — they happen
            // honestly when a posting key's cred upgrades anon→attested while
            // old pointers are still circulating, so they stay silent.
            let Some(cred) = self.creds.creds.get(&p.ptr.replier) else {
                continue;
            };
            // A bad signature is not routine: the live contract rejects the
            // whole delta for it. The read side cannot do that, but it must
            // not swallow it either — the overwhelmingly likely cause is that
            // `LegacyReplyPointer` has drifted off the wire shape, which
            // would otherwise present as an inbox that is merely empty.
            if p.verify_signature(&cred.posting_key).is_err() {
                sig_failures += 1;
                continue;
            }
            if p.ptr.fingerprint != cred.fingerprint() {
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
        if sig_failures > 0 {
            crate::api::log(&format!(
                "legacy inbox: {sig_failures} pointer(s) failed signature — if this is \
                 every pointer, LegacyReplyPointer has drifted off the wire shape"
            ));
        }
        self.canonicalize();
    }

    /// The live contract's `canonicalize` plus its `post_apply_cleanup`,
    /// reduced to what a read-only view needs.
    ///
    /// The fairness caps are NOT decoration: without them a peer serving a
    /// fabricated full state of self-signed anonymous creds and pointers —
    /// every one of which passes the three gates above — fills all 300 slots,
    /// and a plain oldest-first drop then discards every real attested reply
    /// the user received. The live contract's `verify` rejects such a state
    /// outright ("fingerprint over its fairness cap"); the mirror instead
    /// enforces the caps it can and evicts anonymous first.
    fn canonicalize(&mut self) {
        let is_anon = |p: &LegacyAuthorizedReplyPointer| p.ptr.fingerprint.starts_with("anon:");
        let fp_cap = |fp: &str| {
            if fp.starts_with("anon:") {
                LEGACY_MAX_PER_ANON_KEY
            } else {
                LEGACY_MAX_PER_FINGERPRINT
            }
        };
        self.pointers
            .pointers
            .sort_by_key(|p| (p.ptr.time, p.ptr.reply_post));

        // Per-fingerprint cap, newest kept (scan in reverse, as the contract).
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut keep = vec![false; self.pointers.pointers.len()];
        for (i, p) in self.pointers.pointers.iter().enumerate().rev() {
            let c = counts.entry(p.ptr.fingerprint.clone()).or_insert(0);
            if *c < fp_cap(&p.ptr.fingerprint) {
                *c += 1;
                keep[i] = true;
            }
        }
        let mut it = keep.iter();
        self.pointers.pointers.retain(|_| *it.next().unwrap_or(&false));

        // Anonymous share cap: drop the OLDEST anonymous first.
        let anon_count = self.pointers.pointers.iter().filter(|p| is_anon(p)).count();
        if anon_count > LEGACY_ANON_POINTER_SLOTS {
            let mut drop = anon_count - LEGACY_ANON_POINTER_SLOTS;
            self.pointers.pointers.retain(|p| {
                if drop > 0 && is_anon(p) {
                    drop -= 1;
                    false
                } else {
                    true
                }
            });
        }
        // Global cap: oldest anonymous first, an attested one only when no
        // anonymous remain. Verified is never crowded out by anonymous.
        while self.pointers.pointers.len() > LEGACY_MAX_POINTERS {
            let victim = self
                .pointers
                .pointers
                .iter()
                .position(is_anon)
                .unwrap_or(0);
            self.pointers.pointers.remove(victim);
        }

        // `post_apply_cleanup`: a cred whose tier flipped changes its
        // fingerprint, so pointers seated under the old one must go — the
        // network already dropped them, and the render filters on cred
        // PRESENCE alone. This also bounds the cred map, which nothing else
        // does: each attested cred carries a full RSA certificate chain.
        let creds = &self.creds.creds;
        self.pointers.pointers.retain(|p| {
            creds
                .get(&p.ptr.replier)
                .is_some_and(|c| c.fingerprint() == p.ptr.fingerprint)
        });
        let referenced: std::collections::BTreeSet<[u8; 32]> = self
            .pointers
            .pointers
            .iter()
            .map(|p| p.ptr.replier)
            .collect();
        self.creds.creds.retain(|k, _| referenced.contains(k));
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

    fn listing(k: &SigningKey, last_active: u64) -> LegacyAuthorizedListing {
        let listing = LegacyListing {
            author: k.verifying_key().to_bytes(),
            last_active,
        };
        LegacyAuthorizedListing {
            signature: k.sign(&freebird_core::to_cbor(&listing).unwrap()),
            listing,
            attestation: None,
        }
    }

    /// Acceptance criterion #1 of issue #81: an author listed on the previous
    /// build must appear in Discover after the upgrade without doing
    /// anything. The old mirror made the attestation MANDATORY, so every
    /// anonymous listing was rejected — which is how Discover emptied. This
    /// is the regression test that was missing.
    #[test]
    fn legacy_directory_accepts_anonymous_listing() {
        let k = sk(3);
        let master = sk(9).verifying_key();
        let mut d = LegacyDirectoryState::default();
        d.merge(&master, vec![listing(&k, 100)]);
        assert_eq!(d.listings.len(), 1, "anonymous listing must be seated");
        assert!(d.listings[&k.verifying_key().to_bytes()]
            .attestation
            .is_none());
    }

    #[test]
    fn legacy_directory_rejects_forged_signature_and_keeps_newest() {
        let k = sk(3);
        let master = sk(9).verifying_key();
        let mut d = LegacyDirectoryState::default();

        let mut forged = listing(&k, 100);
        forged.listing.last_active = 999; // signature no longer covers this
        d.merge(&master, vec![forged]);
        assert!(d.listings.is_empty(), "forged listing dropped");

        d.merge(&master, vec![listing(&k, 100)]);
        d.merge(&master, vec![listing(&k, 300)]);
        d.merge(&master, vec![listing(&k, 200)]);
        assert_eq!(
            d.listings[&k.verifying_key().to_bytes()].listing.last_active,
            300,
            "per-author LWW keeps the newest last_active"
        );
    }

    /// Distinct 32-byte author key per index. NOT `[i as u8; 32]` — that
    /// wraps at 256 and silently collides, which made an earlier version of
    /// the flood test below pass while testing nothing.
    fn author_key(i: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&i.to_le_bytes());
        k
    }

    /// The anonymous share cap holds, and eviction takes the OLDEST first —
    /// so a flood of fresh anonymous listings cannot push out the ones a
    /// user is most likely to still care about arbitrarily.
    ///
    /// The attested-vs-anonymous half of the tier split is NOT asserted
    /// here: minting a real `AttestationV1` needs the native-only ghost-key
    /// fixture, which the UI crate (a wasm target) does not link. That half
    /// is exercised by `directory-contract`'s own tests against the same
    /// algorithm this mirrors.
    #[test]
    fn legacy_directory_anon_share_cap_evicts_oldest_first() {
        let mut d = LegacyDirectoryState::default();
        for i in 0..LEGACY_ANON_LISTINGS as u64 + 10 {
            let mut l = listing(&sk(3), 100 + i);
            l.listing.author = author_key(i);
            d.listings.insert(l.listing.author, l);
        }
        d.canonicalize();
        assert_eq!(d.listings.len(), LEGACY_ANON_LISTINGS);
        assert!(
            !d.listings.contains_key(&author_key(0)),
            "the oldest anonymous listing is evicted first"
        );
        assert!(
            d.listings
                .contains_key(&author_key(LEGACY_ANON_LISTINGS as u64 + 9)),
            "the newest survives"
        );
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// WIRE-FORMAT KATs — the only thing standing between this module and a
    /// silent repeat of issue #81.
    ///
    /// Every other test here is a round-trip: it signs with `to_cbor` and
    /// verifies with `to_cbor`, so ANY self-consistent shape passes. Rename
    /// or reorder one field of `LegacyReplyPointer` and every pointer the
    /// network actually holds stops decoding — the inbox renders empty,
    /// indistinguishable from "nobody replied to you" — and without these
    /// assertions the whole suite still goes green. (Verified: that exact
    /// mutation passed all 29 tests before this test existed.)
    ///
    /// The bytes below were generated from these types and checked
    /// field-by-field against the live declarations at the commit in
    /// `scripts/live-build.txt`:
    ///   git show d873a2a:contracts/inbox-contract/src/state.rs
    ///   git show d873a2a:contracts/directory-contract/src/lib.rs
    ///
    /// Note what the encoding pins, beyond names and order: a `[u8; 32]`
    /// map key encodes as a CBOR ARRAY of 32 ints (`9820…`) while a
    /// `VerifyingKey` encodes as a 32-byte STRING (`5820…`). Swapping one
    /// for the other looks harmless in Rust and is a total wire break.
    ///
    /// If one of these fails, do NOT re-generate the golden. Find out which
    /// field moved and put it back.
    #[test]
    fn legacy_params_wire_format_kat() {
        let master = sk(9).verifying_key();
        let owner = sk(3).verifying_key();

        // Determines the DIRECTORY address the dual-read window GETs.
        assert_eq!(
            hex(&freebird_core::to_cbor(&LegacyDirectoryParameters {
                seed: LEGACY_DIRECTORY_SEED.into(),
                ghostkey_master: master,
            })
            .unwrap()),
            "a264736565647566726565626972642d6469726563746f72792d76326f67686f7374\
             6b65795f6d61737465725820fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13\
             c58ed702eac835e9f618"
                .replace(['\n', ' '], "")
        );
        // Determines the INBOX address.
        assert_eq!(
            hex(&freebird_core::to_cbor(&LegacyInboxParameters {
                owner,
                ghostkey_master: master,
            })
            .unwrap()),
            "a2656f776e65725820ed4928c628d1c2c6eae90338905995612959273a5c63f93636\
             c14614ac8737d16f67686f73746b65795f6d61737465725820fd1724385aa0c75b64\
             fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn legacy_state_wire_format_kat() {
        let k = sk(3);
        let vk = k.verifying_key();

        let listing = LegacyListing {
            author: vk.to_bytes(),
            last_active: 0x0102030405060708,
        };
        let al = LegacyAuthorizedListing {
            signature: k.sign(&freebird_core::to_cbor(&listing).unwrap()),
            listing,
            attestation: None,
        };
        let dir = LegacyDirectoryState {
            listings: [(vk.to_bytes(), al)].into(),
        };
        assert_eq!(
            hex(&freebird_core::to_cbor(&dir).unwrap()),
            "a1686c697374696e6773a1982018ed1849182818c6182818d118c218c618ea18e903\
             18381890185918951861182918591827183a185c186318f91836183618c118461418\
             ac1887183718d1a3676c697374696e67a266617574686f72982018ed1849182818c6\
             182818d118c218c618ea18e90318381890185918951861182918591827183a185c18\
             6318f91836183618c118461418ac1887183718d16b6c6173745f6163746976651b01\
             02030405060708697369676e6174757265984018a0182018b9187e18af1418c918b1\
             18581875185018b118bf18cf184918191821185d18f00c1897184418851836187518\
             b218c91842185c18be18a518b0189b184b185318c118cb182e18de18a118b4184318\
             7818b4189f1872183718f1182e183518e218e818ea18940d18b71871188318851418\
             351873181b056b6174746573746174696f6ef6"
                .replace(['\n', ' '], ""),
            "legacy DIRECTORY state wire format changed"
        );

        let ptr = LegacyReplyPointer {
            replier: vk.to_bytes(),
            fingerprint: "anon:test".into(),
            target_post: PostId([0x11; 16]),
            reply_post: PostId([0x22; 16]),
            time: 0x0102030405060708,
        };
        let ap = LegacyAuthorizedReplyPointer {
            signature: k.sign(&freebird_core::to_cbor(&ptr).unwrap()),
            ptr,
        };
        let inbox = LegacyInboxState {
            creds: LegacyCreds {
                creds: [(
                    vk.to_bytes(),
                    LegacyReplierCred {
                        posting_key: vk,
                        attestation: None,
                    },
                )]
                .into(),
            },
            pointers: LegacyPointers {
                pointers: vec![ap],
            },
        };
        let inbox_hex = "a2656372656473a1656372656473a1982018ed1849182818c6182818d118c218c618ea18e9\
             0318381890185918951861182918591827183a185c186318f91836183618c118461418ac18\
             87183718d1a26b706f7374696e675f6b65795820ed4928c628d1c2c6eae903389059956129\
             59273a5c63f93636c14614ac8737d16b6174746573746174696f6ef668706f696e74657273\
             a168706f696e7465727381a263707472a5677265706c696572982018ed1849182818c61828\
             18d118c218c618ea18e90318381890185918951861182918591827183a185c186318f91836\
             183618c118461418ac1887183718d16b66696e6765727072696e7469616e6f6e3a74657374\
             6b7461726765745f706f737490111111111111111111111111111111116a7265706c795f70\
             6f737490182218221822182218221822182218221822182218221822182218221822182264\
             74696d651b0102030405060708697369676e6174757265984018ef18f418501871181f1880\
             1889189718a20a18b713186118190318ae18bc183418ce188118d3185818ce18ff186118fa\
             189618d418a918e918551869187a184318aa188718381879187b18a3189018ca18b118bb09\
             18811826188118ab18b0184818b1184b04051845185018a418fb18981835170c06"
            .replace(['\n', ' '], "");
        assert_eq!(
            hex(&freebird_core::to_cbor(&inbox).unwrap()),
            inbox_hex,
            "legacy INBOX state wire format changed"
        );
    }

    /// The full-state branch (`api.rs`) converts through `From`, and the
    /// delta branch decodes the wire delta directly. Both must round-trip,
    /// and a delta must NOT decode as a full state — that is what makes the
    /// `is_full_state` branch safe to get wrong loudly rather than quietly.
    #[test]
    fn legacy_inbox_delta_is_distinct_from_state() {
        let k = sk(3);
        let vk = k.verifying_key();
        let state = LegacyInboxState {
            creds: LegacyCreds {
                creds: [(vk.to_bytes(), anon_cred(&k))].into(),
            },
            pointers: LegacyPointers {
                pointers: vec![pointer(&k, 5, 100)],
            },
        };
        let delta: LegacyInboxDelta = state.clone().into();
        let delta_bytes = freebird_core::to_cbor(&delta).unwrap();
        let state_bytes = freebird_core::to_cbor(&state).unwrap();
        assert_ne!(delta_bytes, state_bytes);
        assert!(
            freebird_core::from_cbor::<LegacyInboxState>(&delta_bytes).is_err(),
            "a delta must not silently decode as a full state"
        );
        assert!(
            freebird_core::from_cbor::<LegacyInboxDelta>(&state_bytes).is_err(),
            "a full state must not silently decode as a delta"
        );
    }
}

