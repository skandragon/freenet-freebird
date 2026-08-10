//! Publisher CLI for the Freebird control cell.
//!
//! `keygen`          — mint the publisher keypair (~/.freebird/publisher.key)
//! `publish-control` — sign and Put the control record (build + flags)
//! `show`            — fetch and print the current control record
//!
//! Talks to a Freenet node on localhost (same ssh tunnel as fdev, see
//! scripts/publish-ui.sh). `make publish` chains publish-control after the
//! site update so the advertised build always matches the deployed bundle.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cell_contract::SignedCellV1;
use ed25519_dalek::SigningKey;
use freebird_control::{ControlV1, CONTROL_PURPOSE};
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi};
use freenet_stdlib::prelude::*;

/// The exact bytes the UI embeds — the address must match the UI's.
const CELL_CONTRACT_WASM: &[u8] = include_bytes!("../../../ui/contracts/cell_contract.wasm");

const DEFAULT_NODE: &str = "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native";

fn key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME set");
    PathBuf::from(home).join(".freebird").join("publisher.key")
}

fn control_container() -> ContractContainer {
    let params = cell_contract::to_cbor(&freebird_control::control_params()).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(CELL_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

fn control_key() -> ContractKey {
    let params = cell_contract::to_cbor(&freebird_control::control_params()).expect("params");
    ContractKey::from_params_and_code(
        Parameters::from(params),
        &ContractCode::from(CELL_CONTRACT_WASM.to_vec()),
    )
}

fn load_signing_key() -> Result<SigningKey, String> {
    let path = key_path();
    let hex = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {e} (run `freebird-ctl keygen` first)", path.display()))?;
    let seed: [u8; 32] = data_encoding::HEXLOWER
        .decode(hex.trim().as_bytes())
        .map_err(|e| format!("{} is not hex: {e}", path.display()))?
        .try_into()
        .map_err(|_| format!("{} is not a 32-byte seed", path.display()))?;
    let sk = SigningKey::from_bytes(&seed);
    if sk.verifying_key() != freebird_control::publisher_key() {
        return Err(format!(
            "{} does not match the compiled-in publisher key ({})",
            path.display(),
            freebird_control::PUBLISHER_VK_HEX
        ));
    }
    Ok(sk)
}

fn keygen() -> Result<(), String> {
    use rand::rngs::OsRng;
    let path = key_path();
    if path.exists() {
        return Err(format!(
            "{} already exists — refusing to overwrite the publisher key",
            path.display()
        ));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let sk = SigningKey::generate(&mut OsRng);
    let hex = data_encoding::HEXLOWER.encode(&sk.to_bytes());
    std::fs::write(&path, hex).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    println!("publisher key written to {} — BACK IT UP", path.display());
    println!(
        "public key (paste into freebird-control PUBLISHER_VK_HEX): {}",
        data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes())
    );
    Ok(())
}

async fn connect(node: &str) -> Result<WebApi, String> {
    let (stream, _) = tokio_tungstenite::connect_async(node)
        .await
        .map_err(|e| format!("connect {node}: {e} (is the ssh tunnel up?)"))?;
    Ok(WebApi::start(stream))
}

/// Drive recv until `f` yields, or time out. Request errors surface as Err.
async fn wait_for<T>(
    api: &mut WebApi,
    what: &str,
    mut f: impl FnMut(HostResponse) -> Option<T>,
) -> Result<T, String> {
    let deadline = Duration::from_secs(60);
    tokio::time::timeout(deadline, async {
        loop {
            match api.recv().await {
                Ok(response) => {
                    if let Some(v) = f(response) {
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

fn parse_flag(kv: &str) -> Result<(String, ciborium::Value), String> {
    let (k, v) = kv
        .split_once('=')
        .ok_or_else(|| format!("--flag wants key=value, got {kv:?}"))?;
    let value = match v {
        "true" => ciborium::Value::Bool(true),
        "false" => ciborium::Value::Bool(false),
        _ => match v.parse::<i64>() {
            Ok(n) => ciborium::Value::Integer(n.into()),
            Err(_) => ciborium::Value::Text(v.into()),
        },
    };
    Ok((k.to_string(), value))
}

async fn publish_control(
    node: &str,
    build: u64,
    label: String,
    flags: BTreeMap<String, ciborium::Value>,
) -> Result<(), String> {
    let sk = load_signing_key()?;
    let mut control = ControlV1::new(build, label);
    control.flags = flags;
    let cell = SignedCellV1::new(&sk, CONTROL_PURPOSE, now_ms(), control.encode());
    let state = cell_contract::to_cbor(&cell)?;

    let mut api = connect(node).await?;
    api.send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: control_container(),
        state: WrappedState::new(state),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|e| e.to_string())?;

    let key = wait_for(&mut api, "PutResponse", |r| match r {
        HostResponse::ContractResponse(ContractResponse::PutResponse { key }) => Some(key),
        _ => None,
    })
    .await?;
    println!(
        "control published: build {} ({}) seq {} → {key}",
        control.build, control.build_label, cell.seq
    );
    Ok(())
}

async fn show(node: &str) -> Result<(), String> {
    let mut api = connect(node).await?;
    let id = *control_key().id();
    api.send(ClientRequest::ContractOp(ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|e| e.to_string())?;

    let state = wait_for(&mut api, "GetResponse", |r| match r {
        HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }) => Some(state),
        _ => None,
    })
    .await?;

    if state.as_ref().is_empty() {
        println!("control cell {id}: empty (never published)");
        return Ok(());
    }
    let cell: SignedCellV1 = cell_contract::from_cbor(state.as_ref())?;
    cell.check(&freebird_control::control_params())?;
    match ControlV1::decode(&cell.body) {
        Some(c) => println!(
            "control cell {id}: build {} ({}) seq {} flags {:?}",
            c.build, c.build_label, cell.seq, c.flags
        ),
        None => println!("control cell {id}: seq {} with undecodable body", cell.seq),
    }
    Ok(())
}

fn usage() -> String {
    "usage:\n  freebird-ctl keygen\n  freebird-ctl publish-control --build N [--label S] [--flag k=v]... [--node URL]\n  freebird-ctl show [--node URL]"
        .into()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().ok_or_else(usage)?.clone();

    let mut node = DEFAULT_NODE.to_string();
    let mut build: Option<u64> = None;
    let mut label = String::new();
    let mut flags = BTreeMap::new();
    let mut it = args[1..].iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| -> Result<String, String> {
            it.next().cloned().ok_or(format!("{name} wants a value"))
        };
        match arg.as_str() {
            "--node" => node = value("--node")?,
            "--build" => {
                build = Some(
                    value("--build")?
                        .parse()
                        .map_err(|e| format!("--build: {e}"))?,
                )
            }
            "--label" => label = value("--label")?,
            "--flag" => {
                let (k, v) = parse_flag(&value("--flag")?)?;
                flags.insert(k, v);
            }
            other => return Err(format!("unknown argument {other:?}\n{}", usage())),
        }
    }

    match cmd.as_str() {
        "keygen" => keygen(),
        "publish-control" => {
            let build = build.ok_or("--build is required")?;
            if build == 0 {
                return Err("--build 0 means 'no git at compile time'; refusing to publish it".into());
            }
            runtime(publish_control(&node, build, label, flags))
        }
        "show" => runtime(show(&node)),
        _ => Err(usage()),
    }
}

fn runtime<F: std::future::Future<Output = Result<(), String>>>(f: F) -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(f)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("freebird-ctl: {e}");
        std::process::exit(1);
    }
}
