//! Thin contract shell over `freebird_core::feed::FeedStateV1`.
//!
//! All CRDT logic lives in freebird-core; this file only deserializes,
//! delegates, and applies the clock-dependent future-timestamp scrub — which
//! must stay OUT of the pure merge (order-dependence breaks convergence) and
//! runs here where the host clock exists.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use freebird_core::feed::{FeedParametersV1, FeedStateV1, FeedStateV1Delta, FeedStateV1Summary, MAX_FUTURE_MS};

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

/// Drop far-future posts from an incoming delta before it meets the merge —
/// a poisoned entry must never get the chance to evict an honest one.
fn scrub_delta(delta: &mut FeedStateV1Delta, now: u64) {
    if let Some(posts) = &mut delta.posts {
        posts.retain(|p| p.post.time <= now.saturating_add(MAX_FUTURE_MS));
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
        let feed: FeedStateV1 = deser(bytes, "state")?;
        let parameters: FeedParametersV1 = deser(parameters.as_ref(), "parameters")?;

        // Refuse far-future state outright so poison is never cached and
        // gossiped onward (doorbell hardening rule 3).
        let mut scrubbed = feed.clone();
        scrubbed.scrub_future(now_ms());
        if scrubbed != feed {
            return Ok(ValidateResult::Invalid);
        }

        match feed.verify(&feed, &parameters) {
            Ok(()) => Ok(ValidateResult::Valid),
            Err(_) => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let parameters: FeedParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let mut feed: FeedStateV1 = deser(state.as_ref(), "state")?;
        let now = now_ms();

        // Self-heal: scrub stored poison a pre-fix node may have accepted.
        feed.scrub_future(now);

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let mut incoming: FeedStateV1 = deser(new_state.as_ref(), "incoming state")?;
                    incoming.scrub_future(now);
                    feed.merge(&feed.clone(), &parameters, &incoming)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let mut delta: FeedStateV1Delta = deser(d.as_ref(), "delta")?;
                    scrub_delta(&mut delta, now);
                    feed.apply_delta(&feed.clone(), &parameters, &Some(delta))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                }
                UpdateData::StateAndDelta { state, delta } => {
                    let mut incoming: FeedStateV1 = deser(state.as_ref(), "incoming state")?;
                    incoming.scrub_future(now);
                    feed.merge(&feed.clone(), &parameters, &incoming)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    if !delta.as_ref().is_empty() {
                        let mut delta: FeedStateV1Delta = deser(delta.as_ref(), "delta")?;
                        scrub_delta(&mut delta, now);
                        feed.apply_delta(&feed.clone(), &parameters, &Some(delta))
                            .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
                    }
                }
                // Related-contract updates are not used by Freebird. Unknown
                // variants (the enum is #[non_exhaustive]) are rejected, not
                // panicked on — a panic in contract WASM kills the runtime.
                _ => return Err(ContractError::InvalidUpdate),
            }
        }

        Ok(UpdateModification::valid(ser(&feed)?.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let parameters: FeedParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let feed: FeedStateV1 = deser(bytes, "state")?;
        let summary = feed.summarize(&feed, &parameters);
        Ok(StateSummary::from(ser(&summary)?))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let parameters: FeedParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let feed: FeedStateV1 = deser(state.as_ref(), "state")?;
        let summary: FeedStateV1Summary = deser(summary.as_ref(), "summary")?;
        match feed.delta(&feed, &parameters, &summary) {
            Some(d) => Ok(StateDelta::from(ser(&d)?)),
            None => Ok(StateDelta::from(vec![])),
        }
    }
}
