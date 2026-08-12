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

/// The whole update, with the clock injected so tests can exercise the
/// clock-dependent paths (`update_state` passes the host clock).
fn update_at(
    parameters: &AvatarParametersV1,
    state: &[u8],
    data: Vec<UpdateData<'_>>,
    now: u64,
) -> Result<Vec<u8>, ContractError> {
    let mut current: Option<AuthorizedAvatar> = if state.is_empty() {
        None
    } else {
        Some(deser(state, "state")?)
    };

    // Self-heal: scrub stored poison a pre-fix node may have accepted — a
    // far-future timestamp must not win LWW forever and brick the slot.
    if current
        .as_ref()
        .is_some_and(|held| held.avatar.time > now.saturating_add(MAX_FUTURE_MS))
    {
        current = None;
    }

    // State and delta are the same thing here: one full signed avatar.
    let mut merge = |bytes: &[u8]| -> Result<(), ContractError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let incoming: AuthorizedAvatar = deser(bytes, "incoming avatar")?;
        check(&incoming, parameters, now)
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
    ser(&avatar)
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
        let bytes = update_at(&parameters, state.as_ref(), data, now_ms())?;
        Ok(UpdateModification::valid(bytes.into()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freebird_core::avatar::AvatarV1;
    use rand::rngs::OsRng;

    fn avatar(sk: &SigningKey, time: u64) -> AuthorizedAvatar {
        AuthorizedAvatar::new(
            AvatarV1 {
                content_type: "image/jpeg".into(),
                data: vec![0xFF, 0xD8, 0xFF, 0x00],
                time,
            },
            sk,
        )
    }

    /// Self-heal: a stored far-future avatar (accepted by a pre-fix node) is
    /// scrubbed on the next update, so an honest older avatar wins the slot.
    #[test]
    fn stored_far_future_avatar_is_scrubbed() {
        let sk = SigningKey::generate(&mut OsRng);
        let params = AvatarParametersV1 {
            author: sk.verifying_key(),
        };
        let now = 1_000_000;
        let poison = avatar(&sk, u64::MAX);
        let honest = avatar(&sk, now);
        let stored = ser(&poison).unwrap();
        let update = vec![UpdateData::State(ser(&honest).unwrap().into())];
        let out = update_at(&params, &stored, update, now).expect("update succeeds");
        let held: AuthorizedAvatar = deser(&out, "out").unwrap();
        assert_eq!(held, honest, "poisoned slot must heal to the honest avatar");
    }

    /// Sanity: a valid stored avatar still wins LWW over an older incoming one.
    #[test]
    fn stored_newer_avatar_still_wins() {
        let sk = SigningKey::generate(&mut OsRng);
        let params = AvatarParametersV1 {
            author: sk.verifying_key(),
        };
        let now = 1_000_000;
        let held = avatar(&sk, now);
        let older = avatar(&sk, now - 1);
        let stored = ser(&held).unwrap();
        let update = vec![UpdateData::State(ser(&older).unwrap().into())];
        let out = update_at(&params, &stored, update, now).expect("update succeeds");
        let kept: AuthorizedAvatar = deser(&out, "out").unwrap();
        assert_eq!(kept, held);
    }
}
