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
//! then check the inner `payload` field, decoding `requestor` loosely (as a
//! CBOR value) so we don't pin the ghostkeys wire enum.

use ed25519_dalek::{Signature, VerifyingKey};
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

/// Domain tag prefixed to the posting key inside the signed payload, so a
/// signature obtained for Freebird can't be replayed as some other claim.
pub const ATTEST_DOMAIN: &[u8] = b"freebird:attest:v1:";

/// Loose mirror of ghostkeys' `ScopedPayload`. Field names are the wire
/// contract; `requestor` is deliberately untyped.
#[derive(Serialize, Deserialize)]
struct ScopedPayloadWire {
    requestor: ciborium::Value,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
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

/// Test fixtures: mint a full master→notary→ghostkey chain. Native-only —
/// RSA keygen needs a real RNG; never compile into wasm.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures {
    use super::*;
    use ed25519_dalek::Signer;
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;
    use rand::rngs::OsRng;

    /// Mint a chain and an attestation over `posting_key`.
    /// Returns (attestation, master verifying key).
    pub fn test_chain(posting_key: &VerifyingKey) -> (AttestationV1, VerifyingKey) {
        test_chain_with_payload(&AttestationV1::payload_for(posting_key))
    }

    /// Same, but with an arbitrary inner payload (for negative tests).
    pub fn test_chain_with_payload(payload: &[u8]) -> (AttestationV1, VerifyingKey) {
        let (master_sk, master_vk) =
            ghostkey_lib::util::create_keypair(&mut OsRng).expect("keypair");
        let (notary_cert, notary_sk) =
            NotaryCertificateV1::new(&master_sk, &"test-tier".to_string()).expect("notary");
        let (ghost_cert, ghost_sk) = GhostkeyCertificateV1::new(&notary_cert, &notary_sk);

        let scoped = ScopedPayloadWire {
            requestor: ciborium::Value::Text("test".into()),
            payload: payload.to_vec(),
        };
        let scoped_bytes = crate::to_cbor(&scoped).expect("scoped payload serializes");
        let signature = ghost_sk.sign(&scoped_bytes);

        (
            AttestationV1 {
                scoped_payload: scoped_bytes,
                signature,
                certificate: ghost_cert,
            },
            master_vk,
        )
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
}
