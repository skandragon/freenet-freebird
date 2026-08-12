//! Ghost Key attestation: binds a Freebird posting key to a Ghost Key.
//!
//! Chain: Freenet master (Ed25519) → notary (RSA blind-sig) → ghost key
//! (Ed25519) → this attestation (ghost key signs a domain-tagged payload
//! containing the posting verifying key). Verification is offline; the trust
//! anchor is ghostkey_lib's compiled-in master key unless a test override is
//! given.
//!
//! The signed bytes are the ghostkey delegate's `ScopedPayload` CBOR — the
//! delegate never signs a raw payload, it wraps it with the runtime-attested
//! requestor first. We verify the signature over those bytes verbatim and
//! then check the inner `payload` field. V1 decoded `requestor` loosely; V2
//! (issue #45) pins it to `SignatureRequestor::WebApp(FREEBIRD_WEBAPP_ID)`
//! and additionally requires the POSTING key's proof-of-possession
//! counter-signature, so nobody can mint an attestation over a key they
//! don't hold, and no other dApp can harvest a Freebird attestation.

use ed25519_dalek::{Signature, VerifyingKey};
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

/// Domain tag prefixed to the posting key inside the signed payload, so a
/// signature obtained for Freebird can't be replayed as some other claim.
/// v1 — kept only for the legacy (v1 inbox / v1 directory) decode paths.
pub const ATTEST_DOMAIN: &[u8] = b"freebird:attest:v1:";

/// v2 attested payload domain (issue #45): a v1 ghost-key signature can
/// never satisfy a v2 verifier.
pub const ATTEST_DOMAIN_V2: &[u8] = b"freebird:attest:v2:";

/// Domain for the posting key's proof-of-possession counter-signature.
pub const ATTEST_POP_DOMAIN: &[u8] = b"freebird:attest-pop:v1:";

/// The fdev-published Freebird site's contract instance id — stable across
/// republishes by construction (fixed container wasm + params; `fdev website
/// update` changes state, never the id). Only attestations whose
/// runtime-attested requestor is `SignatureRequestor::WebApp(<this id>)` are
/// accepted (issue #45): a signature harvested by some other dApp prompting
/// the user's vault cannot become a Freebird checkmark.
pub const FREEBIRD_WEBAPP_ID: &str = "8nXH9SDHE28yPVbudRJDnf3mJi1AFZeV9EYGsqeya1Nv";

/// Decoded [`FREEBIRD_WEBAPP_ID`] bytes.
pub fn freebird_webapp_id() -> [u8; 32] {
    bs58::decode(FREEBIRD_WEBAPP_ID)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("compiled-in webapp id parses")
}

/// Loose mirror of ghostkeys' `ScopedPayload`. Field names are the wire
/// contract; `requestor` is deliberately untyped.
#[derive(Serialize, Deserialize)]
struct ScopedPayloadWire {
    requestor: ciborium::Value,
    payload: Vec<u8>,
}

/// Pinned mirror of the one `SignatureRequestor` variant Freebird accepts
/// (ghostkeys `common/src/lib.rs`): `WebApp(ContractInstanceId)`, where the
/// id serializes as a 32-element byte array. Any other variant (current or
/// future) fails decode and is rejected — the correct default for a check
/// whose whole point is "only the Freebird webapp may mint attestations".
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
enum RequestorWire {
    WebApp([u8; 32]),
}

/// The message the posting key counter-signs: the ghost key's signature over
/// the scoped payload. Covering the ghost signature (not just the payload)
/// pins this consent to ONE specific attestation — a harvested pop can't be
/// re-stapled onto a different ghost key's attestation over the same key.
pub fn pop_message(ghost_signature: &Signature) -> Vec<u8> {
    let mut m = ATTEST_POP_DOMAIN.to_vec();
    m.extend_from_slice(&ghost_signature.to_bytes());
    m
}

#[derive(Serialize, Deserialize, Clone)]
// Manual Debug/PartialEq below: GhostkeyCertificateV1 derives neither.
pub struct AttestationV1 {
    /// CBOR-serialized ScopedPayload, exactly as returned by the ghostkey
    /// delegate's SignResult.
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature by the ghost key over `scoped_payload`.
    pub signature: Signature,
    /// Full certificate chain back to the Freenet master key.
    pub certificate: GhostkeyCertificateV1,
}

impl AttestationV1 {
    /// Verify the full chain and that this attestation binds `posting_key`.
    /// Returns the notary info string (donation tier) on success.
    /// `master_override` is for tests only; contracts pass `None`, which uses
    /// the Freenet master key compiled into ghostkey_lib.
    pub fn verify(
        &self,
        posting_key: &VerifyingKey,
        master_override: Option<&VerifyingKey>,
    ) -> Result<String, String> {
        let tier = self
            .certificate
            .verify(&master_override.cloned())
            .map_err(|e| format!("certificate chain invalid: {e}"))?;

        self.certificate
            .verifying_key
            .verify_strict(&self.scoped_payload, &self.signature)
            .map_err(|e| format!("attestation signature invalid: {e}"))?;

        let wire: ScopedPayloadWire = crate::from_cbor(&self.scoped_payload)?;
        let mut expected = ATTEST_DOMAIN.to_vec();
        expected.extend_from_slice(posting_key.as_bytes());
        if wire.payload != expected {
            return Err("attestation payload does not bind this posting key".into());
        }
        Ok(tier)
    }

    /// Ghost key fingerprint, ghostkeys convention: bs58(blake3(vk)[..8]).
    pub fn fingerprint(&self) -> String {
        let hash = blake3::hash(self.certificate.verifying_key.as_bytes());
        bs58::encode(&hash.as_bytes()[..8]).into_string()
    }

    /// The attestation payload for a posting key — what the UI asks the
    /// ghostkey delegate to sign.
    pub fn payload_for(posting_key: &VerifyingKey) -> Vec<u8> {
        let mut p = ATTEST_DOMAIN.to_vec();
        p.extend_from_slice(posting_key.as_bytes());
        p
    }
}

impl std::fmt::Debug for AttestationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationV1")
            .field("fingerprint", &self.fingerprint())
            .field("scoped_payload_len", &self.scoped_payload.len())
            .finish()
    }
}

impl PartialEq for AttestationV1 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_bytes() == other.canonical_bytes()
    }
}

impl AttestationV1 {
    /// Canonical CBOR bytes; used for equality and deterministic tie-breaks.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::to_cbor(self).expect("attestation serializes")
    }

    /// blake3 of the canonical bytes — a stable identity for summaries.
    pub fn content_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

/// v2 attestation (issue #45): v1 plus a proof-of-possession
/// counter-signature by the posting key, a v2 payload domain, and a pinned
/// requestor. CBOR-distinct from v1 (extra `pop` field).
#[derive(Serialize, Deserialize, Clone)]
// Manual Debug/PartialEq below: GhostkeyCertificateV1 derives neither.
pub struct AttestationV2 {
    /// CBOR-serialized ScopedPayload, exactly as returned by the ghostkey
    /// delegate's SignResult.
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature by the ghost key over `scoped_payload`.
    pub signature: Signature,
    /// Proof of possession: the POSTING key's signature over
    /// `pop_message(signature)` — without it anyone could mint a valid
    /// attestation over anyone else's public posting key.
    pub pop: Signature,
    /// Full certificate chain back to the Freenet master key.
    pub certificate: GhostkeyCertificateV1,
}

impl AttestationV2 {
    /// Verify the full chain, the requestor binding, that this attestation
    /// binds `posting_key`, and that the posting key consented (pop).
    /// Returns the notary info string (donation tier) on success.
    /// `master_override` is for tests only; contracts pass `None`, which uses
    /// the Freenet master key compiled into ghostkey_lib.
    pub fn verify(
        &self,
        posting_key: &VerifyingKey,
        master_override: Option<&VerifyingKey>,
    ) -> Result<String, String> {
        let tier = self
            .certificate
            .verify(&master_override.cloned())
            .map_err(|e| format!("certificate chain invalid: {e}"))?;

        self.certificate
            .verifying_key
            .verify_strict(&self.scoped_payload, &self.signature)
            .map_err(|e| format!("attestation signature invalid: {e}"))?;

        let wire: ScopedPayloadWire = crate::from_cbor(&self.scoped_payload)?;

        // Requestor: only the Freebird webapp may mint attestations. The
        // ghostkey runtime attests this field; a signature prompted by any
        // other dApp (or a delegate) is rejected here.
        let requestor_bytes = crate::to_cbor(&wire.requestor)?;
        match crate::from_cbor::<RequestorWire>(&requestor_bytes) {
            Ok(RequestorWire::WebApp(id)) if id == freebird_webapp_id() => {}
            _ => return Err("attestation requestor is not the Freebird webapp".into()),
        }

        let mut expected = ATTEST_DOMAIN_V2.to_vec();
        expected.extend_from_slice(posting_key.as_bytes());
        if wire.payload != expected {
            return Err("attestation payload does not bind this posting key".into());
        }

        // Proof of possession: the posting key counter-signed THIS ghost
        // signature, so the key's owner consented to this attestation.
        posting_key
            .verify_strict(&pop_message(&self.signature), &self.pop)
            .map_err(|e| format!("attestation proof-of-possession invalid: {e}"))?;
        Ok(tier)
    }

    /// Ghost key fingerprint, ghostkeys convention: bs58(blake3(vk)[..8]).
    pub fn fingerprint(&self) -> String {
        let hash = blake3::hash(self.certificate.verifying_key.as_bytes());
        bs58::encode(&hash.as_bytes()[..8]).into_string()
    }

    /// The attestation payload for a posting key — what the UI asks the
    /// ghostkey delegate to sign.
    pub fn payload_for(posting_key: &VerifyingKey) -> Vec<u8> {
        let mut p = ATTEST_DOMAIN_V2.to_vec();
        p.extend_from_slice(posting_key.as_bytes());
        p
    }

    /// Canonical CBOR bytes; used for equality and deterministic tie-breaks.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::to_cbor(self).expect("attestation serializes")
    }

    /// blake3 of the canonical bytes — a stable identity for summaries.
    pub fn content_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

impl std::fmt::Debug for AttestationV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationV2")
            .field("fingerprint", &self.fingerprint())
            .field("scoped_payload_len", &self.scoped_payload.len())
            .finish()
    }
}

impl PartialEq for AttestationV2 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_bytes() == other.canonical_bytes()
    }
}

/// Test fixtures: mint a full master→notary→ghostkey chain. Native-only —
/// RSA keygen needs a real RNG; never compile into wasm.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;
    use rand::rngs::OsRng;

    /// A test-only master key that can mint multiple attestations under the
    /// same trust root.
    pub struct TestAuthority {
        master_sk: SigningKey,
        pub master_vk: VerifyingKey,
    }

    impl TestAuthority {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let (master_sk, master_vk) =
                ghostkey_lib::util::create_keypair(&mut OsRng).expect("keypair");
            Self {
                master_sk,
                master_vk,
            }
        }

        /// Mint a fresh notary + ghost key and sign `payload` with it (v1
        /// shape — legacy decode tests only).
        pub fn mint(&self, payload: &[u8]) -> AttestationV1 {
            let (notary_cert, notary_sk) =
                NotaryCertificateV1::new(&self.master_sk, &"test-tier".to_string())
                    .expect("notary");
            let (ghost_cert, ghost_sk) = GhostkeyCertificateV1::new(&notary_cert, &notary_sk);

            let scoped = ScopedPayloadWire {
                requestor: ciborium::Value::Text("test".into()),
                payload: payload.to_vec(),
            };
            let scoped_bytes = crate::to_cbor(&scoped).expect("scoped payload serializes");
            let signature = ghost_sk.sign(&scoped_bytes);

            AttestationV1 {
                scoped_payload: scoped_bytes,
                signature,
                certificate: ghost_cert,
            }
        }

        pub fn attest_v1(&self, posting_key: &VerifyingKey) -> AttestationV1 {
            self.mint(&AttestationV1::payload_for(posting_key))
        }

        /// Mint a v2 attestation over an arbitrary payload/requestor, with
        /// the pop signed by `pop_signer` (negative tests vary all three).
        pub fn mint_v2(
            &self,
            requestor: ciborium::Value,
            payload: &[u8],
            pop_signer: &SigningKey,
        ) -> AttestationV2 {
            let (notary_cert, notary_sk) =
                NotaryCertificateV1::new(&self.master_sk, &"test-tier".to_string())
                    .expect("notary");
            let (ghost_cert, ghost_sk) = GhostkeyCertificateV1::new(&notary_cert, &notary_sk);

            let scoped = ScopedPayloadWire {
                requestor,
                payload: payload.to_vec(),
            };
            let scoped_bytes = crate::to_cbor(&scoped).expect("scoped payload serializes");
            let signature = ghost_sk.sign(&scoped_bytes);
            let pop = pop_signer.sign(&pop_message(&signature));

            AttestationV2 {
                scoped_payload: scoped_bytes,
                signature,
                pop,
                certificate: ghost_cert,
            }
        }

        /// The requestor value the real ghostkey runtime attests for the
        /// published Freebird webapp.
        pub fn freebird_requestor() -> ciborium::Value {
            let bytes =
                crate::to_cbor(&super::RequestorWire::WebApp(freebird_webapp_id()))
                    .expect("requestor serializes");
            crate::from_cbor(&bytes).expect("requestor round-trips")
        }

        /// A fully honest v2 attestation: Freebird requestor, payload bound
        /// to the posting key, pop by the posting key itself.
        pub fn attest(&self, posting_sk: &SigningKey) -> AttestationV2 {
            self.mint_v2(
                Self::freebird_requestor(),
                &AttestationV2::payload_for(&posting_sk.verifying_key()),
                posting_sk,
            )
        }
    }

    /// Mint a chain and a v1 attestation over `posting_key`.
    /// Returns (attestation, master verifying key).
    pub fn test_chain(posting_key: &VerifyingKey) -> (AttestationV1, VerifyingKey) {
        let authority = TestAuthority::new();
        (authority.attest_v1(posting_key), authority.master_vk)
    }

    /// Same, but with an arbitrary inner payload (for negative tests).
    pub fn test_chain_with_payload(payload: &[u8]) -> (AttestationV1, VerifyingKey) {
        let authority = TestAuthority::new();
        (authority.mint(payload), authority.master_vk)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn posting_key() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn valid_chain_verifies_and_returns_tier() {
        let (_, vk) = posting_key();
        let (att, master) = test_chain(&vk);
        let tier = att.verify(&vk, Some(&master)).expect("verifies");
        assert_eq!(tier, "test-tier");
        assert!(!att.fingerprint().is_empty());
    }

    #[test]
    fn wrong_master_rejected() {
        let (_, vk) = posting_key();
        let (att, _master) = test_chain(&vk);
        let (_, wrong_master) = posting_key();
        assert!(att.verify(&vk, Some(&wrong_master)).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let (_, vk) = posting_key();
        let (mut att, master) = test_chain(&vk);
        let last = att.scoped_payload.len() - 1;
        att.scoped_payload[last] ^= 0xff;
        assert!(att.verify(&vk, Some(&master)).is_err());
    }

    #[test]
    fn attestation_for_different_posting_key_rejected() {
        let (_, vk) = posting_key();
        let (_, other_vk) = posting_key();
        let (att, master) = test_chain(&other_vk);
        assert!(att.verify(&vk, Some(&master)).is_err());
    }

    #[test]
    fn wrong_domain_rejected() {
        let (_, vk) = posting_key();
        let mut payload = b"othertag:".to_vec();
        payload.extend_from_slice(vk.as_bytes());
        let (att, master) = test_chain_with_payload(&payload);
        assert!(att.verify(&vk, Some(&master)).is_err());
    }

    // ---- v2: proof of possession + requestor binding (issue #45) ----

    #[test]
    fn v2_valid_chain_verifies_and_returns_tier() {
        let (sk, vk) = posting_key();
        let authority = TestAuthority::new();
        let att = authority.attest(&sk);
        let tier = att.verify(&vk, Some(&authority.master_vk)).expect("verifies");
        assert_eq!(tier, "test-tier");
    }

    /// The core of #45: an attestation minted over posting key K WITHOUT
    /// K's cooperation (pop signed by the attacker's own key) must fail.
    #[test]
    fn v2_attestation_without_key_holder_cooperation_rejected() {
        let (_, victim_vk) = posting_key();
        let (attacker_sk, _) = posting_key();
        let authority = TestAuthority::new();
        let att = authority.mint_v2(
            TestAuthority::freebird_requestor(),
            &AttestationV2::payload_for(&victim_vk),
            &attacker_sk, // pop by the attacker, not the victim
        );
        let err = att.verify(&victim_vk, Some(&authority.master_vk)).unwrap_err();
        assert!(err.contains("proof-of-possession"), "{err}");
    }

    #[test]
    fn v2_wrong_requestor_rejected() {
        let (sk, vk) = posting_key();
        let authority = TestAuthority::new();
        // A different webapp's container id.
        let other = crate::to_cbor(&super::RequestorWire::WebApp([9u8; 32])).unwrap();
        let att = authority.mint_v2(
            crate::from_cbor(&other).unwrap(),
            &AttestationV2::payload_for(&vk),
            &sk,
        );
        let err = att.verify(&vk, Some(&authority.master_vk)).unwrap_err();
        assert!(err.contains("requestor"), "{err}");

        // A non-WebApp requestor (e.g. a delegate) is rejected too.
        let att = authority.mint_v2(
            ciborium::Value::Text("test".into()),
            &AttestationV2::payload_for(&vk),
            &sk,
        );
        let err = att.verify(&vk, Some(&authority.master_vk)).unwrap_err();
        assert!(err.contains("requestor"), "{err}");
    }

    #[test]
    fn v2_v1_domain_payload_rejected() {
        let (sk, vk) = posting_key();
        let authority = TestAuthority::new();
        let att = authority.mint_v2(
            TestAuthority::freebird_requestor(),
            &AttestationV1::payload_for(&vk), // v1 domain
            &sk,
        );
        assert!(att.verify(&vk, Some(&authority.master_vk)).is_err());
    }

    #[test]
    fn v2_different_posting_key_rejected() {
        let (sk, _) = posting_key();
        let (_, other_vk) = posting_key();
        let authority = TestAuthority::new();
        let att = authority.attest(&sk);
        assert!(att.verify(&other_vk, Some(&authority.master_vk)).is_err());
    }

    /// A harvested pop must not be re-stapleable onto a DIFFERENT ghost
    /// key's attestation over the same posting key.
    #[test]
    fn v2_pop_bound_to_specific_ghost_signature() {
        let (sk, vk) = posting_key();
        let authority = TestAuthority::new();
        let honest = authority.attest(&sk);
        let (attacker_sk, _) = posting_key();
        let mut forged = authority.mint_v2(
            TestAuthority::freebird_requestor(),
            &AttestationV2::payload_for(&vk),
            &attacker_sk,
        );
        forged.pop = honest.pop; // re-staple the victim's harvested pop
        assert!(forged.verify(&vk, Some(&authority.master_vk)).is_err());
    }

    /// KAT: the exact CBOR bytes of the requestor Freebird accepts —
    /// `SignatureRequestor::WebApp(FREEBIRD_WEBAPP_ID)` as ghostkeys encodes
    /// it (externally tagged enum, id as a 32-element byte array). If this
    /// hex changes, the requestor check no longer matches the real vault.
    #[test]
    fn requestor_wire_format_kat() {
        let bytes =
            crate::to_cbor(&super::RequestorWire::WebApp(freebird_webapp_id())).unwrap();
        assert_eq!(data_encoding::HEXLOWER.encode(&bytes), "a1665765624170709820187318ab182e184518e9188e18c8188718a418b8187f18a605183018bc187f18a8182b18a017184718d51856184018e5188018a218e518f418a00118bf");
    }

    #[test]
    fn v2_cbor_distinct_from_v1() {
        let (sk, vk) = posting_key();
        let authority = TestAuthority::new();
        // A v1 attestation must not decode as v2 (missing `pop` field).
        let v1 = authority.attest_v1(&vk);
        assert!(crate::from_cbor::<AttestationV2>(&v1.canonical_bytes()).is_err());
        // Serde ignores unknown fields, so v2 bytes DO decode as v1 (pop
        // dropped) — but the v2 payload domain fails every v1 verifier.
        let att = authority.attest(&sk);
        let as_v1: AttestationV1 = crate::from_cbor(&att.canonical_bytes()).unwrap();
        assert!(as_v1.verify(&vk, Some(&authority.master_vk)).is_err());
    }
}
