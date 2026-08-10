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

/// The Identity Vault's webapp contract id — stable by construction (fixed
/// container wasm + params; republishing updates state, never the id). The
/// vault publishes `delegate-key.json` inside its bundle so apps discover
/// the CURRENT delegate instead of hardcoding one (freenet/ghostkeys#21:
/// a delegate re-key silently broke every integration that had).
pub const VAULT_CONTRACT_ID: &str = "DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N";

#[derive(Deserialize)]
struct DelegatePointer {
    schema: u32,
    code_hash_bytes: Vec<u8>,
}

/// Fetch the vault's delegate pointer from this node's gateway and resolve
/// the current ghostkey DelegateKey (params are empty, so the key is
/// blake3(code_hash) — `DelegateKey::from_params` computes exactly that).
#[cfg(target_arch = "wasm32")]
pub async fn discover_vault_delegate() -> Result<freenet_stdlib::prelude::DelegateKey, String> {
    use freenet_stdlib::prelude::{DelegateKey, Parameters};
    use wasm_bindgen::JsCast;

    let win = web_sys::window().ok_or("no window")?;
    let origin = win.location().origin().map_err(|_| "no origin")?;
    let url = format!("{origin}/v1/contract/web/{VAULT_CONTRACT_ID}/delegate-key.json");

    let response = wasm_bindgen_futures::JsFuture::from(win.fetch_with_str(&url))
        .await
        .map_err(|e| format!("vault pointer fetch failed: {e:?}"))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| "vault pointer: not a Response")?;
    if !response.ok() {
        return Err(format!("vault pointer HTTP {}", response.status()));
    }
    let text = wasm_bindgen_futures::JsFuture::from(
        response.text().map_err(|e| format!("pointer body: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("pointer body: {e:?}"))?;
    let text = text.as_string().ok_or("pointer body not text")?;

    let pointer: DelegatePointer =
        serde_json::from_str(&text).map_err(|e| format!("pointer parse: {e}"))?;
    if pointer.schema != 1 || pointer.code_hash_bytes.len() != 32 {
        return Err("unexpected pointer schema".into());
    }
    DelegateKey::from_params(
        bs58::encode(&pointer.code_hash_bytes).into_string(),
        &Parameters::from(Vec::<u8>::new()),
    )
    .map_err(|e| format!("bad code hash: {e}"))
}

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
