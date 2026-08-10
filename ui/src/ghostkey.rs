//! Wire mirror of the ghostkey delegate's request/response types.
//!
//! ghostkey-common is not published to crates.io, so the variants Freebird
//! uses are mirrored here with identical serde shapes (CBOR enums keyed by
//! variant name; unknown fields ignored, no deny_unknown_fields upstream).
//! Source of truth: freenet/ghostkeys `common/src/lib.rs`.

use ed25519_dalek::Signature;
use freebird_core::attestation::AttestationV1;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GhostkeyRequest {
    /// Sign with the user's default ghost key; prompts the user.
    SignWithDefault { message: Vec<u8> },
    /// Ask (without prompting) whether any ghost key exists.
    HasIdentity,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GhostkeyResponse {
    SignResult {
        /// CBOR-serialized ScopedPayload
        scoped_payload: Vec<u8>,
        /// Ed25519 signature over the scoped_payload bytes
        signature: Vec<u8>,
        /// The certificate PEM, so the verifier has the full chain
        certificate_pem: String,
    },
    NoIdentityAvailable,
    IdentityPresence {
        usable: usize,
        unusable: usize,
    },
    AccessDenied {
        requestor: ciborium::Value,
    },
    Error {
        message: String,
    },
}

/// Convert a SignResult into a Freebird attestation.
pub fn attestation_from_sign_result(
    scoped_payload: Vec<u8>,
    signature: Vec<u8>,
    certificate_pem: &str,
) -> Result<AttestationV1, String> {
    let signature = Signature::from_slice(&signature)
        .map_err(|e| format!("bad signature length: {e}"))?;
    let certificate = GhostkeyCertificateV1::from_armored_string(certificate_pem)
        .map_err(|e| format!("bad certificate: {e}"))?;
    Ok(AttestationV1 {
        scoped_payload,
        signature,
        certificate,
    })
}
