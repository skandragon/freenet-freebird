//! Signed mutable cell: the frozen indirection kernel.
//!
//! One tiny contract, many uses: params name an owner key and a purpose
//! string, state is a single owner-signed record with an OPAQUE body. The
//! contract never decodes the body — validation is "signature by the owner
//! over (domain, purpose, seq, body hash), higher (seq, hash) wins" and
//! nothing else. That is what lets this wasm stay byte-identical forever
//! while the body schema evolves freely client-side: the control channel
//! (build number + feature flags) uses it today, and the per-author anchor /
//! routing system can reuse it later under a different purpose.
//!
//! FROZEN: after `make pin-hashes`, edits to this crate are forbidden — any
//! byte change rotates every cell address (see the Makefile's
//! check-addresses note and the 2026-08-10 avatar incident). There is no
//! freebird-core dependency for exactly that reason. Rebuilding this crate
//! is, by definition, minting a new contract.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain separator for cell signatures; also the version tag of the whole
/// kernel. A hypothetical v2 kernel would use a new domain, making v1
/// records unreplayable into it.
pub const CELL_SIGN_DOMAIN: &[u8] = b"freebird-cell-v1";

/// Body ceiling: generous for control/routing records, small enough that a
/// compromised publisher key cannot turn the cell into bulk storage.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CellParametersV1 {
    /// The only key allowed to write this cell.
    pub owner: VerifyingKey,
    /// Namespaces cells under one owner ("control", "anchor", ...); part of
    /// the signature payload so records can't cross between purposes.
    pub purpose: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SignedCellV1 {
    /// Writer-chosen monotonic counter (unix millis by convention).
    pub seq: u64,
    /// Opaque payload; the contract never decodes it.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub sig: Signature,
}

/// The exact bytes the owner signs. Length-prefixing the purpose keeps the
/// encoding injective; hashing the body keeps the signed message small.
pub fn signing_payload(purpose: &str, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CELL_SIGN_DOMAIN.len() + 4 + purpose.len() + 8 + 32);
    out.extend_from_slice(CELL_SIGN_DOMAIN);
    out.extend_from_slice(&(purpose.len() as u32).to_le_bytes());
    out.extend_from_slice(purpose.as_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out
}

impl SignedCellV1 {
    pub fn new(sk: &SigningKey, purpose: &str, seq: u64, body: Vec<u8>) -> Self {
        let sig = sk.sign(&signing_payload(purpose, seq, &body));
        Self { seq, body, sig }
    }

    pub fn check(&self, params: &CellParametersV1) -> Result<(), String> {
        if self.body.len() > MAX_BODY_BYTES {
            return Err(format!("cell body over {MAX_BODY_BYTES} bytes"));
        }
        params
            .owner
            .verify_strict(
                &signing_payload(&params.purpose, self.seq, &self.body),
                &self.sig,
            )
            .map_err(|e| format!("cell signature invalid: {e}"))
    }

    /// LWW order: higher seq wins; equal seq breaks ties by content hash so
    /// every node converges on the same record.
    pub fn order_key(&self) -> (u64, [u8; 32]) {
        let bytes = to_cbor(self).expect("cell serializes");
        (self.seq, *blake3::hash(&bytes).as_bytes())
    }
}

/// Summary = the order key held (None encoded as empty bytes upstream).
pub type CellSummaryV1 = (u64, [u8; 32]);

pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = vec![];
    ciborium::ser::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
}

/// Merge an incoming (already-checked) cell into the held one.
pub fn merge(held: &mut Option<SignedCellV1>, incoming: SignedCellV1) {
    let newer = held
        .as_ref()
        .is_none_or(|h| incoming.order_key() > h.order_key());
    if newer {
        *held = Some(incoming);
    }
}

/// Thin contract shell, same structure as the other Freebird contracts.
/// Feature-gated so clients can depend on the types without compiling (or
/// exporting) the contract entry points.
#[cfg(feature = "freenet-main-contract")]
mod contract {
    use super::*;
    use freenet_stdlib::prelude::*;

    fn deser<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ContractError> {
        from_cbor(bytes).map_err(|e| ContractError::Deser(format!("{what}: {e}")))
    }

    fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
        to_cbor(value).map_err(ContractError::Deser)
    }

    fn checked_cell(
        bytes: &[u8],
        params: &CellParametersV1,
        what: &str,
    ) -> Result<Option<SignedCellV1>, ContractError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let cell: SignedCellV1 = deser(bytes, what)?;
        cell.check(params)
            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
        Ok(Some(cell))
    }

    #[allow(dead_code)]
    struct Contract;

    #[contract]
    impl ContractInterface for Contract {
        fn validate_state(
            parameters: Parameters<'static>,
            state: State<'static>,
            _related: RelatedContracts<'static>,
        ) -> Result<ValidateResult, ContractError> {
            let bytes = state.as_ref();
            if bytes.is_empty() {
                return Ok(ValidateResult::Valid);
            }
            let params: CellParametersV1 = deser(parameters.as_ref(), "parameters")?;
            let cell: SignedCellV1 = deser(bytes, "state")?;
            match cell.check(&params) {
                Ok(()) => Ok(ValidateResult::Valid),
                Err(_) => Ok(ValidateResult::Invalid),
            }
        }

        fn update_state(
            parameters: Parameters<'static>,
            state: State<'static>,
            data: Vec<UpdateData<'static>>,
        ) -> Result<UpdateModification<'static>, ContractError> {
            let params: CellParametersV1 = deser(parameters.as_ref(), "parameters")?;
            let mut held = checked_cell(state.as_ref(), &params, "state")?;

            for update in data {
                match update {
                    UpdateData::State(s) => {
                        if let Some(cell) = checked_cell(s.as_ref(), &params, "incoming state")? {
                            merge(&mut held, cell);
                        }
                    }
                    UpdateData::Delta(d) => {
                        if let Some(cell) = checked_cell(d.as_ref(), &params, "delta")? {
                            merge(&mut held, cell);
                        }
                    }
                    UpdateData::StateAndDelta { state, delta } => {
                        if let Some(cell) = checked_cell(state.as_ref(), &params, "incoming state")?
                        {
                            merge(&mut held, cell);
                        }
                        if let Some(cell) = checked_cell(delta.as_ref(), &params, "delta")? {
                            merge(&mut held, cell);
                        }
                    }
                    // Unknown variants (#[non_exhaustive]) are rejected, not
                    // panicked on — a panic in contract WASM kills the runtime.
                    _ => return Err(ContractError::InvalidUpdate),
                }
            }

            let out = match &held {
                Some(cell) => ser(cell)?,
                None => vec![],
            };
            Ok(UpdateModification::valid(out.into()))
        }

        fn summarize_state(
            _parameters: Parameters<'static>,
            state: State<'static>,
        ) -> Result<StateSummary<'static>, ContractError> {
            let bytes = state.as_ref();
            if bytes.is_empty() {
                return Ok(StateSummary::from(vec![]));
            }
            let cell: SignedCellV1 = deser(bytes, "state")?;
            Ok(StateSummary::from(ser(&cell.order_key())?))
        }

        fn get_state_delta(
            _parameters: Parameters<'static>,
            state: State<'static>,
            summary: StateSummary<'static>,
        ) -> Result<StateDelta<'static>, ContractError> {
            if state.as_ref().is_empty() {
                return Ok(StateDelta::from(vec![]));
            }
            let cell: SignedCellV1 = deser(state.as_ref(), "state")?;
            // Zero-byte summary = "peer has nothing" (summarize of empty
            // state emits it); parsing it as CBOR would abort the sync.
            let theirs: Option<CellSummaryV1> = if summary.as_ref().is_empty() {
                None
            } else {
                Some(deser(summary.as_ref(), "summary")?)
            };
            let newer = theirs.is_none_or(|held| cell.order_key() > held);
            if newer {
                Ok(StateDelta::from(ser(&cell)?))
            } else {
                Ok(StateDelta::from(vec![]))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn owner() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn params(sk: &SigningKey, purpose: &str) -> CellParametersV1 {
        CellParametersV1 {
            owner: sk.verifying_key(),
            purpose: purpose.into(),
        }
    }

    #[test]
    fn signed_cell_verifies() {
        let sk = owner();
        let p = params(&sk, "control");
        let cell = SignedCellV1::new(&sk, "control", 1, b"payload".to_vec());
        cell.check(&p).expect("valid");
    }

    #[test]
    fn wrong_owner_rejected() {
        let sk = owner();
        let p = params(&owner(), "control");
        let cell = SignedCellV1::new(&sk, "control", 1, b"payload".to_vec());
        assert!(cell.check(&p).is_err());
    }

    #[test]
    fn cross_purpose_replay_rejected() {
        let sk = owner();
        let cell = SignedCellV1::new(&sk, "control", 1, b"payload".to_vec());
        assert!(cell.check(&params(&sk, "anchor")).is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let sk = owner();
        let p = params(&sk, "control");
        let mut cell = SignedCellV1::new(&sk, "control", 1, b"payload".to_vec());
        cell.body = b"other".to_vec();
        assert!(cell.check(&p).is_err());
    }

    #[test]
    fn oversized_body_rejected() {
        let sk = owner();
        let p = params(&sk, "control");
        let cell = SignedCellV1::new(&sk, "control", 1, vec![0; MAX_BODY_BYTES + 1]);
        assert!(cell.check(&p).is_err());
    }

    #[test]
    fn arbitrary_bytes_accepted_when_signed() {
        // The body is opaque: garbage is fine as long as the owner signed it.
        let sk = owner();
        let p = params(&sk, "control");
        let cell = SignedCellV1::new(&sk, "control", 1, vec![0xFF, 0x00, 0xC3]);
        cell.check(&p).expect("opaque body accepted");
    }

    #[test]
    fn higher_seq_wins_stale_noop() {
        let sk = owner();
        let mut held = None;
        merge(
            &mut held,
            SignedCellV1::new(&sk, "control", 5, b"five".to_vec()),
        );
        merge(
            &mut held,
            SignedCellV1::new(&sk, "control", 3, b"three".to_vec()),
        );
        assert_eq!(held.as_ref().unwrap().body, b"five");
        merge(
            &mut held,
            SignedCellV1::new(&sk, "control", 7, b"seven".to_vec()),
        );
        assert_eq!(held.as_ref().unwrap().body, b"seven");
    }

    #[test]
    fn equal_seq_tiebreak_deterministic() {
        let sk = owner();
        let a = SignedCellV1::new(&sk, "control", 5, b"aaa".to_vec());
        let b = SignedCellV1::new(&sk, "control", 5, b"bbb".to_vec());
        // Both merge orders converge on the same winner.
        let mut h1 = Some(a.clone());
        merge(&mut h1, b.clone());
        let mut h2 = Some(b);
        merge(&mut h2, a);
        assert_eq!(h1, h2);
    }

    #[test]
    fn signing_payload_injective_on_purpose_boundary() {
        // "ab" + "c" must not collide with "a" + "bc".
        assert_ne!(
            signing_payload("ab", 1, b"x"),
            signing_payload("a", 1, b"x")
        );
    }
}
