#![allow(unexpected_cfgs)]
//! Freebird KV delegate: per-origin encrypted key-value storage on the
//! user's node. Pattern-copied from River's chat-delegate, minus everything
//! Freebird doesn't need (CAS, subscriptions, signing — posts are signed in
//! the UI with the posting key this delegate merely stores).
//!
//! Origin isolation: every secret key is prefixed with the runtime-attested
//! caller contract id, so another webapp on the same node cannot read
//! Freebird's keys (and vice versa).

use freebird_core::delegate_api::{FreebirdDelegateRequest, FreebirdDelegateResponse};
use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateContext, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

const ORIGIN_SEPARATOR: &str = ":";

/// The one seam in this delegate: the native `DelegateCtx` is a stub (every
/// call is a no-op), so handlers run against this trait and tests use the
/// in-memory impl below.
trait Kv {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool;
    fn remove(&mut self, key: &[u8]) -> bool;
    fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>>;
}

impl Kv for DelegateCtx {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_secret(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.set_secret(key, value)
    }
    fn remove(&mut self, key: &[u8]) -> bool {
        self.remove_secret(key)
    }
    fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.list_secrets(prefix)
    }
}

fn origin_prefix(origin: &[u8]) -> String {
    format!("{}{}", bs58::encode(origin).into_string(), ORIGIN_SEPARATOR)
}

fn handle_request(
    kv: &mut impl Kv,
    origin: &[u8],
    request: FreebirdDelegateRequest,
) -> FreebirdDelegateResponse {
    let prefix = origin_prefix(origin);
    match request {
        FreebirdDelegateRequest::Store { key, value } => {
            let full = format!("{prefix}{key}");
            // set() returns false on failure in wasm and always in the
            // native stub; handlers must not treat native-stub failure as
            // an error path in tests, so tests use the in-memory Kv.
            if kv.set(full.as_bytes(), &value) {
                FreebirdDelegateResponse::Stored { key }
            } else {
                FreebirdDelegateResponse::Error {
                    message: format!("failed to store {key}"),
                }
            }
        }
        FreebirdDelegateRequest::Get { key } => {
            let full = format!("{prefix}{key}");
            FreebirdDelegateResponse::Value {
                value: kv.get(full.as_bytes()),
                key,
            }
        }
        FreebirdDelegateRequest::Delete { key } => {
            let full = format!("{prefix}{key}");
            kv.remove(full.as_bytes());
            FreebirdDelegateResponse::Deleted { key }
        }
        FreebirdDelegateRequest::List => {
            let keys = kv
                .list(prefix.as_bytes())
                .into_iter()
                .filter_map(|k| {
                    String::from_utf8(k)
                        .ok()
                        .and_then(|s| s.strip_prefix(&prefix).map(str::to_string))
                })
                .collect();
            FreebirdDelegateResponse::KeyList { keys }
        }
    }
}

fn app_response(response: &FreebirdDelegateResponse) -> Result<OutboundDelegateMsg, DelegateError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(response, &mut bytes)
        .map_err(|e| DelegateError::Deser(format!("serialize response: {e}")))?;
    Ok(OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(bytes)
            .with_context(DelegateContext::default())
            .processed(true),
    ))
}

pub struct FreebirdDelegate;

#[delegate]
impl DelegateInterface for FreebirdDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        let InboundDelegateMsg::ApplicationMessage(app_msg) = message else {
            return Err(DelegateError::Other(
                "freebird-delegate only handles application messages".into(),
            ));
        };
        if app_msg.processed {
            return Err(DelegateError::Other(
                "cannot process an already processed message".into(),
            ));
        }
        // Only runtime-attested webapp callers; inter-delegate calls are not
        // part of Freebird's design and are rejected.
        let origin_bytes = match origin {
            Some(MessageOrigin::WebApp(contract_id)) => contract_id.as_bytes().to_vec(),
            Some(_) => {
                return Err(DelegateError::Other(
                    "freebird-delegate does not accept inter-delegate calls".into(),
                ))
            }
            None => return Err(DelegateError::Other("missing message origin".into())),
        };

        let payload: &[u8] = app_msg.payload.as_ref();
        let request: FreebirdDelegateRequest = ciborium::de::from_reader(payload)
            .map_err(|e| DelegateError::Deser(format!("deserialize request: {e}")))?;

        let response = handle_request(ctx, &origin_bytes, request);
        Ok(vec![app_response(&response)?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemKv(BTreeMap<Vec<u8>, Vec<u8>>);

    impl Kv for MemKv {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key).cloned()
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.insert(key.to_vec(), value.to_vec());
            true
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            self.0.remove(key).is_some()
        }
        fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.0
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
    }

    const ORIGIN_A: &[u8] = b"origin-a";
    const ORIGIN_B: &[u8] = b"origin-b";

    #[test]
    fn store_get_roundtrip() {
        let mut kv = MemKv::default();
        let stored = handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Store {
                key: "posting_key".into(),
                value: vec![1, 2, 3],
            },
        );
        assert_eq!(
            stored,
            FreebirdDelegateResponse::Stored {
                key: "posting_key".into()
            }
        );
        let got = handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Get {
                key: "posting_key".into(),
            },
        );
        assert_eq!(
            got,
            FreebirdDelegateResponse::Value {
                key: "posting_key".into(),
                value: Some(vec![1, 2, 3])
            }
        );
    }

    #[test]
    fn origin_isolation() {
        let mut kv = MemKv::default();
        handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Store {
                key: "posting_key".into(),
                value: vec![9],
            },
        );
        let got = handle_request(
            &mut kv,
            ORIGIN_B,
            FreebirdDelegateRequest::Get {
                key: "posting_key".into(),
            },
        );
        assert_eq!(
            got,
            FreebirdDelegateResponse::Value {
                key: "posting_key".into(),
                value: None
            }
        );
    }

    #[test]
    fn list_scoped_to_origin() {
        let mut kv = MemKv::default();
        for (origin, key) in [
            (ORIGIN_A, "draft"),
            (ORIGIN_A, "posting_key"),
            (ORIGIN_B, "other"),
        ] {
            handle_request(
                &mut kv,
                origin,
                FreebirdDelegateRequest::Store {
                    key: key.into(),
                    value: vec![0],
                },
            );
        }
        let list = handle_request(&mut kv, ORIGIN_A, FreebirdDelegateRequest::List);
        assert_eq!(
            list,
            FreebirdDelegateResponse::KeyList {
                keys: vec!["draft".into(), "posting_key".into()]
            }
        );
    }

    #[test]
    fn delete_removes() {
        let mut kv = MemKv::default();
        handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Store {
                key: "draft".into(),
                value: vec![1],
            },
        );
        handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Delete {
                key: "draft".into(),
            },
        );
        let got = handle_request(
            &mut kv,
            ORIGIN_A,
            FreebirdDelegateRequest::Get {
                key: "draft".into(),
            },
        );
        assert_eq!(
            got,
            FreebirdDelegateResponse::Value {
                key: "draft".into(),
                value: None
            }
        );
    }
}
