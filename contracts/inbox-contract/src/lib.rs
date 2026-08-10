//! Thin contract shell over `freebird_core::inbox::InboxStateV1`.
//! Same structure and clock-scrub rationale as the feed contract.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use freebird_core::feed::MAX_FUTURE_MS;
use freebird_core::inbox::{InboxParametersV1, InboxStateV1, InboxStateV1Delta, InboxStateV1Summary};

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

fn scrub_delta(delta: &mut InboxStateV1Delta, now: u64) {
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
        let inbox: InboxStateV1 = deser(bytes, "state")?;
        let parameters: InboxParametersV1 = deser(parameters.as_ref(), "parameters")?;

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
        let parameters: InboxParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let mut inbox: InboxStateV1 = if state.as_ref().is_empty() {
            InboxStateV1::default()
        } else {
            deser(state.as_ref(), "state")?
        };
        let now = now_ms();
        inbox.scrub_future(now);

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let mut incoming: InboxStateV1 = deser(new_state.as_ref(), "incoming state")?;
                    incoming.scrub_future(now);
                    inbox
                        .merge(&inbox.clone(), &parameters, &incoming)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let mut delta: InboxStateV1Delta = deser(d.as_ref(), "delta")?;
                    scrub_delta(&mut delta, now);
                    inbox
                        .apply_delta(&inbox.clone(), &parameters, &Some(delta))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
                UpdateData::StateAndDelta { state, delta } => {
                    let mut incoming: InboxStateV1 = deser(state.as_ref(), "incoming state")?;
                    incoming.scrub_future(now);
                    inbox
                        .merge(&inbox.clone(), &parameters, &incoming)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    if !delta.as_ref().is_empty() {
                        let mut delta: InboxStateV1Delta = deser(delta.as_ref(), "delta")?;
                        scrub_delta(&mut delta, now);
                        inbox
                            .apply_delta(&inbox.clone(), &parameters, &Some(delta))
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                }
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
        let parameters: InboxParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let inbox: InboxStateV1 = deser(bytes, "state")?;
        let summary = inbox.summarize(&inbox, &parameters);
        Ok(StateSummary::from(ser(&summary)?))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let parameters: InboxParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let inbox: InboxStateV1 = deser(state.as_ref(), "state")?;
        let summary: InboxStateV1Summary = deser(summary.as_ref(), "summary")?;
        match inbox.delta(&inbox, &parameters, &summary) {
            Some(d) => Ok(StateDelta::from(ser(&d)?)),
            None => Ok(StateDelta::from(vec![])),
        }
    }
}
