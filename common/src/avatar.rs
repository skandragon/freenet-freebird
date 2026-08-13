//! Per-author avatar: one signed image blob in its own contract, so profile
//! pictures never press on the feed contract's PUT budget (issue #10).
//! Single-slot LWW: newest signed `(time, content-hash)` wins, no history.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_AVATAR_BYTES: usize = 64 * 1024;

pub const AVATAR_SIGN_DOMAIN: &[u8] = b"freebird-avatar-v1";

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AvatarParametersV1 {
    /// The author's posting key; determines the contract address, so the UI
    /// derives it from the `[u8; 32]` it already has — no discovery.
    pub author: VerifyingKey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AvatarV1 {
    /// One of "image/png", "image/jpeg", "image/webp"; must match the bytes.
    pub content_type: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Milliseconds since the Unix epoch; newest signed version wins.
    pub time: u64,
}

impl AvatarV1 {
    /// The exact bytes the author signs (issue #47): domain tag + canonical
    /// layout; the blob is hashed so the signed message stays small.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(AVATAR_SIGN_DOMAIN.len() + 8 + 4 + self.content_type.len() + 32);
        out.extend_from_slice(AVATAR_SIGN_DOMAIN);
        out.extend_from_slice(&self.time.to_le_bytes());
        crate::types::put_bytes(&mut out, self.content_type.as_bytes());
        out.extend_from_slice(blake3::hash(&self.data).as_bytes());
        out
    }
}

/// An avatar plus the author's signature over `avatar.signing_payload()`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedAvatar {
    pub avatar: AvatarV1,
    pub signature: Signature,
}

impl AuthorizedAvatar {
    pub fn new(avatar: AvatarV1, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&avatar.signing_payload());
        Self { avatar, signature }
    }

    pub fn verify_signature(&self, author: &VerifyingKey) -> Result<(), String> {
        author
            .verify_strict(&self.avatar.signing_payload(), &self.signature)
            .map_err(|e| format!("avatar signature invalid: {e}"))
    }
}

/// LWW ordering: `(time, content-hash)`. Hash tie-break keeps two
/// equal-timestamp writes convergent on every peer.
pub fn order_key(a: &AuthorizedAvatar) -> (u64, [u8; 32]) {
    let bytes = crate::to_cbor(a).expect("avatar serializes");
    (a.avatar.time, *blake3::hash(&bytes).as_bytes())
}

/// Sniff the image type from magic bytes. The blob is untrusted input; the
/// declared content-type must agree with what the bytes actually are.
pub fn sniff_mime(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else if data.starts_with(b"GIF8") {
        Some("image/gif")
    } else {
        None
    }
}

/// Full validity check, shared by the contract and the UI (which runs it
/// before publishing and on every fetched blob).
pub fn check_avatar(a: &AuthorizedAvatar, author: &VerifyingKey) -> Result<(), String> {
    if a.avatar.data.len() > MAX_AVATAR_BYTES {
        return Err(format!("avatar over {MAX_AVATAR_BYTES} bytes"));
    }
    match a.avatar.content_type.as_str() {
        "image/png" | "image/jpeg" | "image/webp" => {}
        other => return Err(format!("unsupported avatar content-type: {other}")),
    }
    if sniff_mime(&a.avatar.data) != Some(a.avatar.content_type.as_str()) {
        return Err("avatar bytes do not match declared content-type".into());
    }
    a.verify_signature(author)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn jpeg_bytes(len: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF];
        v.resize(len.max(3), 0);
        v
    }

    fn make(sk: &SigningKey, time: u64, data: Vec<u8>, ct: &str) -> AuthorizedAvatar {
        AuthorizedAvatar::new(
            AvatarV1 {
                content_type: ct.into(),
                data,
                time,
            },
            sk,
        )
    }

    #[test]
    fn valid_avatar_checks() {
        let sk = SigningKey::generate(&mut OsRng);
        let a = make(&sk, 10, jpeg_bytes(100), "image/jpeg");
        check_avatar(&a, &sk.verifying_key()).expect("valid");
    }

    #[test]
    fn forged_signature_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let a = make(&other, 10, jpeg_bytes(100), "image/jpeg");
        assert!(check_avatar(&a, &sk.verifying_key()).is_err());
    }

    #[test]
    fn oversize_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let a = make(&sk, 10, jpeg_bytes(MAX_AVATAR_BYTES + 1), "image/jpeg");
        assert!(check_avatar(&a, &sk.verifying_key()).is_err());
    }

    #[test]
    fn mismatched_content_type_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let a = make(&sk, 10, jpeg_bytes(100), "image/png");
        assert!(check_avatar(&a, &sk.verifying_key()).is_err());
        let gif = make(&sk, 10, b"GIF89a-rest".to_vec(), "image/gif");
        assert!(check_avatar(&gif, &sk.verifying_key()).is_err());
    }

    /// Wire-format KAT (issue #47): reordering a signed field fails here
    /// before it silently invalidates network signatures.
    #[test]
    fn avatar_signing_payload_kat() {
        let a = AvatarV1 {
            content_type: "image/png".into(),
            data: vec![0xAA; 4],
            time: 0x0102030405060708,
        };
        assert_eq!(
            data_encoding::HEXLOWER.encode(&a.signing_payload()),
            "66726565626972642d6176617461722d7631080706050403020109000000696d6167652f706e675060d74e3a0aa7d386d56902daa27555df84c242068855e97a563d5ca05b0691"
        );
    }

    #[test]
    fn newer_time_orders_higher() {
        let sk = SigningKey::generate(&mut OsRng);
        let old = make(&sk, 10, jpeg_bytes(100), "image/jpeg");
        let new = make(&sk, 20, jpeg_bytes(50), "image/jpeg");
        assert!(order_key(&new) > order_key(&old));
    }
}
