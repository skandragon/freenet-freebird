//! Thin contract shell over `freebird_core::avatar`: a single-slot LWW
//! register holding one signed image blob. All checks live in freebird-core;
//! this file deserializes, compares `(time, hash)` order keys, and applies
//! the clock-dependent far-future clamp (host clock lives here, not in the
//! pure merge).

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use freebird_core::avatar::{check_avatar, order_key, AuthorizedAvatar, AvatarParametersV1};
use freebird_core::feed::MAX_FUTURE_MS;

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

/// Full validity for an incoming avatar: core checks plus the far-future
/// reject — a poisoned timestamp must not win LWW forever.
fn check(a: &AuthorizedAvatar, params: &AvatarParametersV1, now: u64) -> Result<(), String> {
    if a.avatar.time > now.saturating_add(MAX_FUTURE_MS) {
        return Err("avatar timestamp too far in the future".into());
    }
    check_avatar(a, &params.author)
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
        let avatar: AuthorizedAvatar = deser(bytes, "state")?;
        let parameters: AvatarParametersV1 = deser(parameters.as_ref(), "parameters")?;
        match check(&avatar, &parameters, now_ms()) {
            Ok(()) => Ok(ValidateResult::Valid),
            Err(_) => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let parameters: AvatarParametersV1 = deser(parameters.as_ref(), "parameters")?;
        let now = now_ms();
        let mut current: Option<AuthorizedAvatar> = if state.as_ref().is_empty() {
            None
        } else {
            Some(deser(state.as_ref(), "state")?)
        };

        // State and delta are the same thing here: one full signed avatar.
        let mut merge = |bytes: &[u8]| -> Result<(), ContractError> {
            if bytes.is_empty() {
                return Ok(());
            }
            let incoming: AuthorizedAvatar = deser(bytes, "incoming avatar")?;
            check(&incoming, &parameters, now)
                .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
            let newer = match &current {
                None => true,
                Some(held) => order_key(&incoming) > order_key(held),
            };
            if newer {
                current = Some(incoming);
            }
            Ok(())
        };

        for update in data {
            match update {
                UpdateData::State(s) => merge(s.as_ref())?,
                UpdateData::Delta(d) => merge(d.as_ref())?,
                UpdateData::StateAndDelta { state, delta } => {
                    merge(state.as_ref())?;
                    merge(delta.as_ref())?;
                }
                // Unknown variants (#[non_exhaustive]) are rejected, not
                // panicked on — a panic in contract WASM kills the runtime.
                _ => return Err(ContractError::InvalidUpdate),
            }
        }

        let avatar = current.ok_or(ContractError::InvalidUpdate)?;
        Ok(UpdateModification::valid(ser(&avatar)?.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let _ = parameters;
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let avatar: AuthorizedAvatar = deser(bytes, "state")?;
        Ok(StateSummary::from(ser(&order_key(&avatar))?))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _ = parameters;
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let avatar: AuthorizedAvatar = deser(state.as_ref(), "state")?;
        // Empty summary = peer has nothing; any real avatar is newer.
        let newer = if summary.as_ref().is_empty() {
            true
        } else {
            let theirs: (u64, [u8; 32]) = deser(summary.as_ref(), "summary")?;
            order_key(&avatar) > theirs
        };
        if newer {
            Ok(StateDelta::from(state.as_ref().to_vec()))
        } else {
            Ok(StateDelta::from(vec![]))
        }
    }
}
