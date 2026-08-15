//! Legacy-generation fixtures: state the DEPLOYED contract itself produced.
//!
//! `legacy.rs` mirrors the wire types of the build named in
//! `scripts/live-build.txt`, and every test there signs with the mirror and
//! verifies with the mirror — self-consistent by construction. The
//! wire-format KATs pin the mirror's SHAPE; nothing pinned its BEHAVIOR
//! against what the deployed contract actually accepts, merges and evicts.
//!
//! These fixtures close that gap. `generate_legacy_fixtures` drives a local
//! node running the ACTUAL vendored `*_v1.wasm`: it PUTs a seed state, sends
//! deltas built from the mirror types, and captures whatever the old contract
//! merged. So the committed bytes are bytes the old contract validated and
//! wrote — not bytes we serialized and handed back to ourselves. If the
//! mirror encoded a field the old contract does not understand, the update is
//! rejected at generation time; if the old contract merges differently from
//! `LegacyDirectoryState::merge`, the decode test's expectations do not hold.
//!
//! The corpus is synthetic and deterministic: authors are seed bytes, times
//! are literals, so there is no live user data in the tree and the fixture is
//! reproducible rather than a snapshot nobody dares regenerate.
//!
//! Attested listings are deliberately absent. `AttestationV1::verify` takes a
//! `master_override` that contracts pass as `None`, so the deployed wasm
//! anchors on ghostkey_lib's compiled-in Freenet master; a chain minted by
//! `freebird-core`'s `test-fixtures` feature verifies only under an override
//! the real bytes never take. The attested paths stay covered by the unit
//! tests that can pass an override.
//!
//! Regenerate with `make fixtures`, which needs a local node — never the
//! live one, since the legacy directory is a single global address and these
//! records would land in everyone's Discover. CI runs only the decode test.

use ed25519_dalek::SigningKey;

use crate::legacy::{LegacyAuthorizedListing, LegacyDirectoryState, LegacyListing};

const DIRECTORY_FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/directory_legacy.cbor");

/// Synthetic authors: the seed IS the key, so nothing has to be stored
/// alongside the fixture and anyone can rebuild the corpus from this file.
fn author(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The deltas sent to the old contract, in order. Author 11 appears twice so
/// the capture exercises the per-author LWW replacement rather than three
/// independent inserts. Times are fixed and in the past — `scrub_future`
/// drops anything ahead of the node's clock.
const UPDATES: &[(u8, u64)] = &[
    (11, 1_755_000_000_000),
    (12, 1_755_000_001_000),
    (13, 1_755_000_002_000),
    (11, 1_755_000_003_000),
];

/// What the old contract must have ended up holding: one row per author,
/// with author 11 at its LATER time.
const EXPECTED: &[(u8, u64)] = &[
    (11, 1_755_000_003_000),
    (12, 1_755_000_001_000),
    (13, 1_755_000_002_000),
];

/// A listing signed the way the live generation signs one: bare CBOR of the
/// `listing` field, no domain tag (that arrived with #47), no attestation.
fn listing(sk: &SigningKey, last_active: u64) -> LegacyAuthorizedListing {
    let listing = LegacyListing {
        author: sk.verifying_key().to_bytes(),
        last_active,
    };
    let bytes = freebird_core::to_cbor(&listing).expect("listing serializes");
    LegacyAuthorizedListing {
        signature: ed25519_dalek::Signer::sign(sk, &bytes),
        listing,
        attestation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the captured bytes through the dual-read path, with no node.
    ///
    /// This is the test that runs in CI. It fails if the mirror stops being
    /// able to read what the deployed contract wrote — a renamed field, a
    /// changed signing payload, a retyped map key.
    #[test]
    fn legacy_directory_fixture_decodes() {
        let bytes = std::fs::read(DIRECTORY_FIXTURE).unwrap_or_else(|e| {
            panic!("read {DIRECTORY_FIXTURE}: {e} — regenerate with `make fixtures`")
        });
        let state: LegacyDirectoryState = freebird_core::from_cbor(&bytes)
            .expect("legacy directory state decodes under the mirrored types");

        let mut got: Vec<(u8, u64)> = Vec::new();
        for (seed, _) in EXPECTED {
            let vk = author(*seed).verifying_key().to_bytes();
            let l = state
                .listings
                .get(&vk)
                .unwrap_or_else(|| panic!("author {seed} missing from the captured directory"));
            l.check(&crate::keys::master_key())
                .expect("captured listing passes the mirror's own check");
            got.push((*seed, l.listing.last_active));
        }
        assert_eq!(got, EXPECTED, "captured directory contents");
        assert_eq!(
            state.listings.len(),
            EXPECTED.len(),
            "captured directory holds exactly the corpus"
        );
    }

    /// The mirror's merge must reach the same state the old contract reached
    /// from the same deltas. A divergence here is the dual-read window
    /// showing a different Discover than the network holds.
    #[test]
    fn mirror_merge_agrees_with_the_captured_state() {
        let bytes = std::fs::read(DIRECTORY_FIXTURE).unwrap_or_else(|e| {
            panic!("read {DIRECTORY_FIXTURE}: {e} — regenerate with `make fixtures`")
        });
        let captured: LegacyDirectoryState =
            freebird_core::from_cbor(&bytes).expect("captured state decodes");

        let mut ours = LegacyDirectoryState::default();
        for (seed, t) in UPDATES {
            ours.merge(&crate::keys::master_key(), vec![listing(&author(*seed), *t)]);
        }
        assert_eq!(
            ours, captured,
            "mirror merge diverged from what the deployed contract produced"
        );
    }
}

/// Generator — talks to a local node, so it is `#[ignore]`d and never runs in
/// CI. `make fixtures` runs it.
#[cfg(test)]
mod generate {
    use super::*;
    use freenet_stdlib::client_api::{
        ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi,
    };
    use freenet_stdlib::prelude::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// The isolated node from the local-dev skill, NOT the 7509 tunnel.
    const DEFAULT_NODE: &str = "ws://127.0.0.1:7511/v1/contract/command?encodingProtocol=native";

    // These two mirror `tools/freebird-ctl`'s helpers. Duplicated rather than
    // shared: freebird-ctl is a binary crate, and a crate existing only to
    // hold twenty lines of websocket plumbing costs more than the copy.
    async fn connect(url: &str) -> Result<WebApi, String> {
        let (stream, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| format!("connect {url}: {e} (is the local test node up?)"))?;
        Ok(WebApi::start(stream))
    }

    async fn wait_for<T>(
        api: &mut WebApi,
        what: &str,
        mut f: impl FnMut(HostResponse) -> Option<T>,
    ) -> Result<T, String> {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match api.recv().await {
                    Ok(r) => {
                        if let Some(v) = f(r) {
                            return Ok(v);
                        }
                    }
                    Err(e) => return Err(format!("node error: {e}")),
                }
            }
        })
        .await
        .map_err(|_| format!("timed out waiting for {what}"))?
    }

    fn directory_v1_container() -> ContractContainer {
        let params =
            freebird_core::to_cbor(&crate::keys::directory_params_v1()).expect("params serialize");
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            Arc::new(ContractCode::from(
                crate::keys::DIRECTORY_V1_CONTRACT_WASM.to_vec(),
            )),
            Parameters::from(params),
        )))
    }

    async fn capture_directory(url: &str) -> Result<Vec<u8>, String> {
        let mut api = connect(url).await?;

        // Seed with an empty state so the contract exists, then let every
        // listing arrive as a delta — the path the live UI writes through.
        let seed = freebird_core::to_cbor(&LegacyDirectoryState::default())?;
        api.send(ClientRequest::ContractOp(ContractRequest::Put {
            contract: directory_v1_container(),
            state: WrappedState::new(seed),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|e| e.to_string())?;
        wait_for(&mut api, "PutResponse", |r| match r {
            HostResponse::ContractResponse(ContractResponse::PutResponse { key }) => Some(key),
            _ => None,
        })
        .await?;

        for (seed, t) in UPDATES {
            let delta: crate::legacy::LegacyDirectoryDelta = vec![listing(&author(*seed), *t)];
            api.send(ClientRequest::ContractOp(ContractRequest::Update {
                key: crate::keys::directory_key_v1(),
                data: UpdateData::Delta(StateDelta::from(freebird_core::to_cbor(&delta)?)),
            }))
            .await
            .map_err(|e| e.to_string())?;
            wait_for(&mut api, "UpdateResponse", |r| match r {
                HostResponse::ContractResponse(ContractResponse::UpdateResponse { key, .. }) => {
                    Some(key)
                }
                _ => None,
            })
            .await?;
        }

        api.send(ClientRequest::ContractOp(ContractRequest::Get {
            key: *crate::keys::directory_key_v1().id(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }))
        .await
        .map_err(|e| e.to_string())?;
        let state = wait_for(&mut api, "GetResponse", |r| match r {
            HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }) => {
                Some(state)
            }
            _ => None,
        })
        .await?;

        if state.as_ref().is_empty() {
            return Err("node returned an empty directory state".into());
        }
        Ok(state.as_ref().to_vec())
    }

    #[test]
    #[ignore = "needs a local Freenet node; run via `make fixtures`"]
    fn generate_legacy_fixtures() {
        let url =
            std::env::var("FREEBIRD_FIXTURE_NODE").unwrap_or_else(|_| DEFAULT_NODE.to_string());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let bytes = rt.block_on(capture_directory(&url)).expect("capture");

        let path = std::path::Path::new(DIRECTORY_FIXTURE);
        std::fs::create_dir_all(path.parent().expect("fixtures dir")).expect("mkdir");
        std::fs::write(path, &bytes).expect("write fixture");
        println!("wrote {} ({} bytes)", DIRECTORY_FIXTURE, bytes.len());
    }
}
