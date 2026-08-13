//! Per-author reply inbox, v3 (issues #45/#46/#47; v2 was issue #23):
//! anonymous-parity slot policy, instance-bound domain-tagged pointers,
//! proof-of-possession attestations.
//!
//! V3 state types live HERE, not in freebird-core: that crate is byte-frozen
//! (any edit rotates every deployed contract's derived address — the
//! 2026-08-10 avatar incident), and the v1 types it holds keep decoding the
//! legacy inboxes during the dual-read migration window. The UI depends on
//! this crate with default-features = false, same pattern as the directory.

pub mod state;

#[cfg(feature = "freenet-main-contract")]
mod contract {
    use ciborium::{de::from_reader, ser::into_writer};
    use freenet_scaffold::ComposableState;
    use freenet_stdlib::prelude::*;

    use freebird_core::feed::MAX_FUTURE_MS;
    use crate::state::{InboxParametersV3, InboxStateV3, InboxStateV3Delta, InboxStateV3Summary};

    fn now_ms() -> u64 {
        freenet_stdlib::time::now().timestamp_millis().max(0) as u64
    }

    fn deser<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ContractError> {
        from_reader::<T, &[u8]>(bytes).map_err(|e| ContractError::Deser(format!("{what}: {e}")))
    }

    fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
        let mut out = vec![];
        into_writer(value, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(out)
    }

    /// Drop far-future pointers from an incoming delta before the merge — a
    /// poisoned timestamp must never get the chance to outlive honest ones.
    fn scrub_delta(delta: &mut InboxStateV3Delta, now: u64) {
        if let Some(pointers) = &mut delta.pointers {
            pointers.retain(|p| p.ptr.time <= now.saturating_add(MAX_FUTURE_MS));
        }
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
            let inbox: InboxStateV3 = deser(bytes, "state")?;
            let parameters: InboxParametersV3 = deser(parameters.as_ref(), "parameters")?;

            let mut scrubbed = inbox.clone();
            scrubbed.scrub_future(now_ms());
            if scrubbed != inbox {
                return Ok(ValidateResult::Invalid);
            }

            match inbox.verify(&inbox, &parameters) {
                Ok(()) => Ok(ValidateResult::Valid),
                Err(_) => Ok(ValidateResult::Invalid),
            }
        }

        fn update_state(
            parameters: Parameters<'static>,
            state: State<'static>,
            data: Vec<UpdateData<'static>>,
        ) -> Result<UpdateModification<'static>, ContractError> {
            let parameters: InboxParametersV3 = deser(parameters.as_ref(), "parameters")?;
            let mut inbox: InboxStateV3 = if state.as_ref().is_empty() {
                InboxStateV3::default()
            } else {
                deser(state.as_ref(), "state")?
            };
            let now = now_ms();
            inbox.scrub_future(now);

            for update in data {
                match update {
                    UpdateData::State(new_state) => {
                        let mut incoming: InboxStateV3 = deser(new_state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        inbox
                            .merge(&inbox.clone(), &parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::Delta(d) => {
                        if d.as_ref().is_empty() {
                            continue;
                        }
                        let mut delta: InboxStateV3Delta = deser(d.as_ref(), "delta")?;
                        scrub_delta(&mut delta, now);
                        inbox
                            .apply_delta(&inbox.clone(), &parameters, &Some(delta))
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                    UpdateData::StateAndDelta { state, delta } => {
                        let mut incoming: InboxStateV3 = deser(state.as_ref(), "incoming state")?;
                        incoming.scrub_future(now);
                        inbox
                            .merge(&inbox.clone(), &parameters, &incoming)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                        if !delta.as_ref().is_empty() {
                            let mut delta: InboxStateV3Delta = deser(delta.as_ref(), "delta")?;
                            scrub_delta(&mut delta, now);
                            inbox
                                .apply_delta(&inbox.clone(), &parameters, &Some(delta))
                                .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                        }
                    }
                    // Unknown variants (#[non_exhaustive]) are rejected, not
                    // panicked on — a panic in contract WASM kills the runtime.
                    _ => return Err(ContractError::InvalidUpdate),
                }
            }

            Ok(UpdateModification::valid(ser(&inbox)?.into()))
        }

        fn summarize_state(
            parameters: Parameters<'static>,
            state: State<'static>,
        ) -> Result<StateSummary<'static>, ContractError> {
            let bytes = state.as_ref();
            if bytes.is_empty() {
                return Ok(StateSummary::from(vec![]));
            }
            let parameters: InboxParametersV3 = deser(parameters.as_ref(), "parameters")?;
            let inbox: InboxStateV3 = deser(bytes, "state")?;
            let summary = inbox.summarize(&inbox, &parameters);
            Ok(StateSummary::from(ser(&summary)?))
        }

        fn get_state_delta(
            parameters: Parameters<'static>,
            state: State<'static>,
            summary: StateSummary<'static>,
        ) -> Result<StateDelta<'static>, ContractError> {
            if state.as_ref().is_empty() {
                return Ok(StateDelta::from(vec![]));
            }
            let parameters: InboxParametersV3 = deser(parameters.as_ref(), "parameters")?;
            let inbox: InboxStateV3 = deser(state.as_ref(), "state")?;
            // Zero-byte summary = "peer has nothing" (summarize of empty
            // state emits it); parsing it as CBOR would abort the sync.
            let summary: InboxStateV3Summary = if summary.as_ref().is_empty() {
                let empty = InboxStateV3::default();
                empty.summarize(&empty, &parameters)
            } else {
                deser(summary.as_ref(), "summary")?
            };
            match inbox.delta(&inbox, &parameters, &summary) {
                Some(d) => Ok(StateDelta::from(ser(&d)?)),
                None => Ok(StateDelta::from(vec![])),
            }
        }
    }
}
