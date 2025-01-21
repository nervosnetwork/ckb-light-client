mod utils;

use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

use ckb_light_client_lib::{
    error::Error,
    protocols::{
        FilterProtocol, LightClientProtocol, Peers, PendingTxs, RelayProtocol, SyncProtocol,
        BAD_MESSAGE_ALLOWED_EACH_HOUR, CHECK_POINT_INTERVAL,
    },
    service::{
        Cell, CellType, CellsCapacity, FetchStatus, LocalNode, LocalNodeProtocol, Order,
        Pagination, PeerSyncState, RemoteNode, ScriptStatus, ScriptType, SearchKey,
        SetScriptsCommand, Status, TransactionWithStatus, Tx, TxStatus, TxWithCell, TxWithCells,
    },
    storage::{
        self, extract_raw_data, CursorDirection, Key, KeyPrefix, Storage, StorageWithChainData,
        LAST_STATE_KEY,
    },
    types::RunEnv,
    verify::verify_tx,
};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

use ckb_chain_spec::{consensus::Consensus, ChainSpec};
use ckb_jsonrpc_types::{JsonBytes, Transaction};
use ckb_network::{
    extract_peer_id, CKBProtocol, CKBProtocolHandler, Flags, NetworkController, NetworkService,
    NetworkState, SupportProtocols,
};
use ckb_resource::Resource;
use ckb_stop_handler::broadcast_exit_signals;
use ckb_systemtime::{unix_time_as_millis, Instant};
use ckb_types::{core, packed, prelude::*, H256};

use std::sync::OnceLock;

static MAINNET_CONFIG: &str = include_str!("../../../config/mainnet.toml");

static TESTNET_CONFIG: &str = include_str!("../../../config/testnet.toml");

static STORAGE_WITH_DATA: OnceLock<StorageWithChainData> = OnceLock::new();

static NET_CONTROL: OnceLock<NetworkController> = OnceLock::new();

static CONSENSUS: OnceLock<Arc<Consensus>> = OnceLock::new();

static SERIALIZER: Serializer = Serializer::new()
    .serialize_large_number_types_as_bigints(true)
    .serialize_maps_as_objects(true);

/// 0b0 init
/// 0b1 start
/// 0b10 stop
static START_FLAG: AtomicU8 = AtomicU8::new(0);

fn status(flag: u8) -> bool {
    START_FLAG.load(Ordering::SeqCst) & flag == flag
}

fn change_status(flag: u8) {
    START_FLAG.store(flag, Ordering::SeqCst);
}
#[allow(clippy::enum_variant_names)]
#[derive(Deserialize)]
#[serde(tag = "type")]
enum NetworkSetting {
    MainNet { config: Option<String> },
    TestNet { config: Option<String> },
    DevNet { spec: String, config: String },
}

#[wasm_bindgen]
pub async fn light_client(
    network_setting: JsValue,
    log_level: String,
    network_secret_key: JsValue,
) -> Result<(), JsValue> {
    if !status(0b0) {
        return Err(JsValue::from_str("Can't start twice"));
    }
    utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::new(
        log::Level::from_str(&log_level).expect("Bad log level"),
    ));
    let network_flag: NetworkSetting = serde_wasm_bindgen::from_value(network_setting)?;

    let mut config = match &network_flag {
        NetworkSetting::TestNet { config } => config
            .as_ref()
            .map_or(TESTNET_CONFIG, |v| v)
            .parse::<RunEnv>()
            .unwrap(),
        NetworkSetting::MainNet { config } => config
            .as_ref()
            .map_or(MAINNET_CONFIG, |v| v)
            .parse::<RunEnv>()
            .unwrap(),
        NetworkSetting::DevNet { config, .. } => config.parse::<RunEnv>().unwrap(),
    };

    let storage = Storage::new(&config.store.path);
    let chain_spec = ChainSpec::load_from(&match network_flag {
        NetworkSetting::MainNet { .. } => Resource::bundled("specs/mainnet.toml".to_string()),
        NetworkSetting::TestNet { .. } => Resource::bundled("specs/testnet.toml".to_string()),
        NetworkSetting::DevNet { spec, .. } => Resource::raw(spec),
    })
    .expect("load spec should be OK");

    let consensus = chain_spec
        .build_consensus()
        .expect("build consensus should be ok");
    let genesis = consensus.genesis_block().data();

    storage.init_genesis_block(genesis);

    let pending_txs = Arc::new(tokio::sync::RwLock::new(PendingTxs::default()));
    let max_outbound_peers = config.network.max_outbound_peers;
    let network_secret_key =
        serde_wasm_bindgen::from_value(network_secret_key).expect("Invalid network secret key");
    config.network.secret_key = network_secret_key;
    let network_state = NetworkState::from_config(config.network)
        .await
        .map(|network_state| {
            Arc::new(network_state.required_flags(
                Flags::DISCOVERY
                    | Flags::SYNC
                    | Flags::RELAY
                    | Flags::LIGHT_CLIENT
                    | Flags::BLOCK_FILTER,
            ))
        })
        .map_err(|err| {
            let errmsg = format!("failed to initialize network state since {}", err);
            Error::runtime(errmsg)
        })
        .unwrap();
    let required_protocol_ids = vec![
        SupportProtocols::Sync.protocol_id(),
        SupportProtocols::LightClient.protocol_id(),
        SupportProtocols::Filter.protocol_id(),
    ];
    let peers = Arc::new(Peers::new(
        max_outbound_peers,
        CHECK_POINT_INTERVAL,
        storage.get_last_check_point(),
        BAD_MESSAGE_ALLOWED_EACH_HOUR,
    ));

    let sync_protocol = SyncProtocol::new(storage.clone(), Arc::clone(&peers));
    let relay_protocol_v2 = RelayProtocol::new(
        pending_txs.clone(),
        Arc::clone(&peers),
        consensus.clone(),
        storage.clone(),
        false,
    );
    let relay_protocol_v3 = RelayProtocol::new(
        pending_txs.clone(),
        Arc::clone(&peers),
        consensus.clone(),
        storage.clone(),
        true,
    );
    let light_client: Box<dyn CKBProtocolHandler> = Box::new(LightClientProtocol::new(
        storage.clone(),
        Arc::clone(&peers),
        consensus.clone(),
    ));

    let filter_protocol = FilterProtocol::new(storage.clone(), Arc::clone(&peers));

    let protocols = vec![
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::Sync,
            Box::new(sync_protocol),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::RelayV2,
            Box::new(relay_protocol_v2),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::RelayV3,
            Box::new(relay_protocol_v3),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::LightClient,
            light_client,
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::Filter,
            Box::new(filter_protocol),
            Arc::clone(&network_state),
        ),
    ];

    let handle = ckb_async_runtime::Handle {};
    let network_controller = NetworkService::new(
        Arc::clone(&network_state),
        protocols,
        required_protocol_ids,
        (
            consensus.identify_name(),
            "0.1.0".to_owned(),
            Flags::DISCOVERY,
        ),
    )
    .start(&handle)
    .map_err(|err| {
        let errmsg = format!("failed to start network since {}", err);
        Error::runtime(errmsg)
    })
    .unwrap();

    let storage_with_data = StorageWithChainData::new(storage, peers, pending_txs);

    STORAGE_WITH_DATA.get_or_init(|| storage_with_data);
    NET_CONTROL.get_or_init(|| network_controller);
    CONSENSUS.get_or_init(|| Arc::new(consensus));
    change_status(0b1);
    Ok(())
}

#[wasm_bindgen]
pub fn stop() {
    broadcast_exit_signals();
    STORAGE_WITH_DATA.get().unwrap().storage().shutdown();
    change_status(0b10);
}

use ckb_types::prelude::IntoHeaderView;

#[wasm_bindgen]
pub fn get_tip_header() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(Into::<ckb_jsonrpc_types::HeaderView>::into(
        STORAGE_WITH_DATA
            .get()
            .unwrap()
            .storage()
            .get_tip_header()
            .into_view(),
    )
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_genesis_block() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(Into::<ckb_jsonrpc_types::BlockView>::into(
        STORAGE_WITH_DATA
            .get()
            .unwrap()
            .storage()
            .get_genesis_block()
            .into_view(),
    )
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_header(hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let block_hash = H256::from_str(&hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let swc = STORAGE_WITH_DATA.get().unwrap();
    let header_view: Option<ckb_jsonrpc_types::HeaderView> =
        swc.storage().get_header(&block_hash.pack()).map(Into::into);

    Ok(header_view.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn fetch_header(hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let block_hash = H256::from_str(&hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let swc = STORAGE_WITH_DATA.get().unwrap();

    if let Some(value) = swc.storage().get_header(&block_hash.pack()) {
        return Ok(
            FetchStatus::<ckb_jsonrpc_types::HeaderView>::Fetched { data: value.into() }
                .serialize(&SERIALIZER)?,
        );
    }

    let now = unix_time_as_millis();
    if let Some((added_ts, first_sent, missing)) = swc.get_header_fetch_info(&block_hash) {
        if missing {
            // re-fetch the header
            swc.add_fetch_header(block_hash, now);
            return Ok(
                FetchStatus::<ckb_jsonrpc_types::HeaderView>::NotFound.serialize(&SERIALIZER)?
            );
        } else if first_sent > 0 {
            return Ok(FetchStatus::<ckb_jsonrpc_types::HeaderView>::Fetching {
                first_sent: first_sent.into(),
            }
            .serialize(&SERIALIZER)?);
        } else {
            return Ok(FetchStatus::<ckb_jsonrpc_types::HeaderView>::Added {
                timestamp: added_ts.into(),
            }
            .serialize(&SERIALIZER)?);
        }
    } else {
        swc.add_fetch_header(block_hash, now);
    }
    Ok(FetchStatus::<ckb_jsonrpc_types::HeaderView>::Added {
        timestamp: now.into(),
    }
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn estimate_cycles(tx: JsValue) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let tx: Transaction = serde_wasm_bindgen::from_value(tx)?;
    let tx: packed::Transaction = tx.into();
    let tx = tx.into_view();

    let swc = STORAGE_WITH_DATA.get().unwrap();
    let consensus = CONSENSUS.get().unwrap();

    let cycles = verify_tx(
        tx.clone(),
        swc,
        Arc::clone(consensus),
        &swc.storage().get_last_state().1.into_view(),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid transaction: {:?}", e)))?;
    Ok(ckb_jsonrpc_types::EstimateCycles {
        cycles: cycles.into(),
    }
    .serialize(&SERIALIZER)?)
}

const MAX_ADDRS: usize = 50;

#[wasm_bindgen]
pub fn local_node_info() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let network_controller = NET_CONTROL.get().unwrap();
    Ok(LocalNode {
        version: network_controller.version().to_owned(),
        node_id: network_controller.node_id(),
        active: network_controller.is_active(),
        addresses: network_controller
            .public_urls(MAX_ADDRS)
            .into_iter()
            .map(|(address, score)| ckb_jsonrpc_types::NodeAddress {
                address,
                score: u64::from(score).into(),
            })
            .collect(),
        protocols: network_controller
            .protocols()
            .into_iter()
            .map(|(protocol_id, name, support_versions)| LocalNodeProtocol {
                id: (protocol_id.value() as u64).into(),
                name,
                support_versions,
            })
            .collect::<Vec<_>>(),
        connections: (network_controller.connected_peers().len() as u64).into(),
    }
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_peers() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let network_controller = NET_CONTROL.get().unwrap();
    let swc = STORAGE_WITH_DATA.get().unwrap();
    let peers: Vec<RemoteNode> = network_controller
        .connected_peers()
        .iter()
        .map(|(peer_index, peer)| {
            let mut addresses = vec![&peer.connected_addr];
            addresses.extend(peer.listened_addrs.iter());

            let node_addresses = addresses
                .iter()
                .map(|addr| {
                    let score = network_controller
                        .addr_info(addr)
                        .map(|addr_info| addr_info.score)
                        .unwrap_or(1);
                    let non_negative_score = if score > 0 { score as u64 } else { 0 };
                    ckb_jsonrpc_types::NodeAddress {
                        address: addr.to_string(),
                        score: non_negative_score.into(),
                    }
                })
                .collect();

            RemoteNode {
                version: peer
                    .identify_info
                    .as_ref()
                    .map(|info| info.client_version.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                node_id: extract_peer_id(&peer.connected_addr)
                    .map(|peer_id| peer_id.to_base58())
                    .unwrap_or_default(),
                addresses: node_addresses,
                connected_duration: (Instant::now()
                    .saturating_duration_since(peer.connected_time)
                    .as_millis() as u64)
                    .into(),
                sync_state: swc
                    .peers()
                    .get_state(peer_index)
                    .map(|state| PeerSyncState {
                        requested_best_known_header: state
                            .get_prove_request()
                            .map(|request| request.get_last_header().header().to_owned().into()),
                        proved_best_known_header: state
                            .get_prove_state()
                            .map(|request| request.get_last_header().header().to_owned().into()),
                    }),
                protocols: peer
                    .protocols
                    .iter()
                    .map(
                        |(protocol_id, protocol_version)| ckb_jsonrpc_types::RemoteNodeProtocol {
                            id: (protocol_id.value() as u64).into(),
                            version: protocol_version.clone(),
                        },
                    )
                    .collect(),
            }
        })
        .collect();
    Ok(peers.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn set_scripts(
    scripts: Vec<JsValue>,
    command: Option<SetScriptsCommand>,
) -> Result<(), JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let mut matched_blocks = STORAGE_WITH_DATA
        .get()
        .unwrap()
        .matched_blocks()
        .blocking_write();

    let scripts: Vec<ScriptStatus> = scripts
        .into_iter()
        .map(serde_wasm_bindgen::from_value::<ScriptStatus>)
        .collect::<Result<Vec<_>, _>>()?;
    debug!("Update scripts, {:?}, {:?}", scripts, command);
    STORAGE_WITH_DATA
        .get()
        .unwrap()
        .storage()
        .update_filter_scripts(
            scripts.into_iter().map(Into::into).collect(),
            command.map(Into::into).unwrap_or_default(),
        );
    matched_blocks.clear();
    Ok(())
}

#[wasm_bindgen]
pub fn get_scripts() -> Result<Vec<JsValue>, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let scripts = STORAGE_WITH_DATA
        .get()
        .unwrap()
        .storage()
        .get_filter_scripts();

    Ok(scripts
        .into_iter()
        .map(Into::into)
        .map(|v: ScriptStatus| v.serialize(&SERIALIZER))
        .collect::<Result<Vec<_>, _>>()?)
}

#[wasm_bindgen]
pub fn get_cells(
    search_key: JsValue,
    order: Order,
    limit: u32,
    after_cursor: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    debug!(
        "Calling get_cells with {:?}, {:?}, {:?}, {:?}",
        search_key, order, limit, after_cursor
    );
    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;

    let (prefix, from_key, direction, skip) = build_query_options(
        &search_key,
        KeyPrefix::CellLockScript,
        KeyPrefix::CellTypeScript,
        order,
        after_cursor.map(JsonBytes::from_vec),
    )?;

    let limit = limit as usize;
    if limit == 0 {
        return Err(JsValue::from_str("limit should be greater than 0"));
    }
    let with_data = search_key.with_data.unwrap_or(true);
    let filter_script_type = match search_key.script_type {
        ScriptType::Lock => ScriptType::Type,
        ScriptType::Type => ScriptType::Lock,
    };

    let (
        filter_prefix,
        filter_script_len_range,
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ) = build_filter_options(search_key)?;

    let storage = STORAGE_WITH_DATA.get().unwrap().storage();

    let kvs: Vec<_> = storage.collect_iterator(
        from_key,
        direction,
        Box::new(move |key| key.starts_with(&prefix)),
        limit,
        skip,
    );

    let mut cells = Vec::new();
    let mut last_key = Vec::new();
    for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
        debug!("get cells iterator at {:?} {:?}", key, value);
        let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
        let output_index = u32::from_be_bytes(
            key[key.len() - 4..]
                .try_into()
                .expect("stored output_index"),
        );
        let tx_index = u32::from_be_bytes(
            key[key.len() - 8..key.len() - 4]
                .try_into()
                .expect("stored tx_index"),
        );
        let block_number = u64::from_be_bytes(
            key[key.len() - 16..key.len() - 8]
                .try_into()
                .expect("stored block_number"),
        );

        let tx = packed::Transaction::from_slice(
            &storage
                .get(Key::TxHash(&tx_hash).into_vec())
                .unwrap()
                .expect("stored tx")[12..],
        )
        .expect("from stored tx slice should be OK");
        let output = tx
            .raw()
            .outputs()
            .get(output_index as usize)
            .expect("get output by index should be OK");
        let output_data = tx
            .raw()
            .outputs_data()
            .get(output_index as usize)
            .expect("get output data by index should be OK");

        if let Some(prefix) = filter_prefix.as_ref() {
            match filter_script_type {
                ScriptType::Lock => {
                    if !extract_raw_data(&output.lock())
                        .as_slice()
                        .starts_with(prefix)
                    {
                        debug!("skipped at {}", line!());
                        continue;
                    }
                }
                ScriptType::Type => {
                    if output.type_().is_none()
                        || !extract_raw_data(&output.type_().to_opt().unwrap())
                            .as_slice()
                            .starts_with(prefix)
                    {
                        debug!("skipped at {}", line!());
                        continue;
                    }
                }
            }
        }

        if let Some([r0, r1]) = filter_script_len_range {
            match filter_script_type {
                ScriptType::Lock => {
                    let script_len = extract_raw_data(&output.lock()).len();
                    if script_len < r0 || script_len > r1 {
                        debug!("skipped at {}", line!());
                        continue;
                    }
                }
                ScriptType::Type => {
                    let script_len = output
                        .type_()
                        .to_opt()
                        .map(|script| extract_raw_data(&script).len())
                        .unwrap_or_default();
                    if script_len < r0 || script_len > r1 {
                        debug!("skipped at {}", line!());
                        continue;
                    }
                }
            }
        }

        if let Some([r0, r1]) = filter_output_data_len_range {
            if output_data.len() < r0 || output_data.len() >= r1 {
                debug!("skipped at {}", line!());
                continue;
            }
        }

        if let Some([r0, r1]) = filter_output_capacity_range {
            let capacity: core::Capacity = output.capacity().unpack();
            if capacity < r0 || capacity >= r1 {
                debug!("skipped at {}", line!());
                continue;
            }
        }

        if let Some([r0, r1]) = filter_block_range {
            if block_number < r0 || block_number >= r1 {
                debug!("skipped at {}", line!());
                continue;
            }
        }

        last_key = key.to_vec();
        let cell_to_push = Cell {
            output: output.into(),
            output_data: if with_data {
                Some(output_data.into())
            } else {
                None
            },
            out_point: packed::OutPoint::new(tx_hash, output_index).into(),
            block_number: block_number.into(),
            tx_index: tx_index.into(),
        };
        debug!("pushed cell {:#?}", cell_to_push);
        cells.push(cell_to_push);
    }
    debug!("get_cells last_key={:?}", last_key);
    Ok((Pagination {
        objects: cells,
        last_cursor: JsonBytes::from_vec(last_key),
    })
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_transactions(
    search_key: JsValue,
    order: Order,
    limit: u32,
    after_cursor: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;
    let (prefix, from_key, direction, skip) = build_query_options(
        &search_key,
        KeyPrefix::TxLockScript,
        KeyPrefix::TxTypeScript,
        order,
        after_cursor.map(JsonBytes::from_vec),
    )?;
    let limit = limit as usize;
    if limit == 0 {
        return Err(JsValue::from_str("limit should be greater than 0"));
    }

    let (filter_script, filter_block_range) = if let Some(filter) = search_key.filter.as_ref() {
        if filter.output_data_len_range.is_some() {
            return Err(JsValue::from_str(
                "doesn't support search_key.filter.output_data_len_range parameter",
            ));
        }
        if filter.output_capacity_range.is_some() {
            return Err(JsValue::from_str(
                "doesn't support search_key.filter.output_capacity_range parameter",
            ));
        }
        let filter_script: Option<packed::Script> =
            filter.script.as_ref().map(|script| script.clone().into());
        let filter_block_range: Option<[core::BlockNumber; 2]> =
            filter.block_range.map(|r| [r[0].into(), r[1].into()]);
        (filter_script, filter_block_range)
    } else {
        (None, None)
    };

    let filter_script_type = match search_key.script_type {
        ScriptType::Lock => ScriptType::Type,
        ScriptType::Type => ScriptType::Lock,
    };

    let storage = STORAGE_WITH_DATA.get().unwrap().storage();

    if search_key.group_by_transaction.unwrap_or_default() {
        let prefix_cloned = prefix.clone();
        let mut kvs: Vec<_> = storage.collect_iterator(
            from_key,
            direction,
            Box::new(move |key| key.starts_with(&prefix_cloned)),
            100,
            skip,
        );
        let mut tx_with_cells: Vec<TxWithCells> = Vec::new();
        let mut last_key = Vec::new();

        'outer: while !kvs.is_empty() {
            for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                if tx_with_cells.len() == limit
                    && tx_with_cells.last_mut().unwrap().transaction.hash != tx_hash.unpack()
                {
                    break 'outer;
                }
                last_key = key.to_vec();
                let tx = packed::Transaction::from_slice(
                    &storage
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx")[12..],
                )
                .expect("from stored tx slice should be OK");

                let block_number = u64::from_be_bytes(
                    key[key.len() - 17..key.len() - 9]
                        .try_into()
                        .expect("stored block_number"),
                );
                let tx_index = u32::from_be_bytes(
                    key[key.len() - 9..key.len() - 5]
                        .try_into()
                        .expect("stored tx_index"),
                );
                let io_index = u32::from_be_bytes(
                    key[key.len() - 5..key.len() - 1]
                        .try_into()
                        .expect("stored io_index"),
                );
                let io_type = if *key.last().expect("stored io_type") == 0 {
                    CellType::Input
                } else {
                    CellType::Output
                };

                if let Some(filter_script) = filter_script.as_ref() {
                    let filter_script_matched = match filter_script_type {
                        ScriptType::Lock => storage
                            .get(
                                Key::TxLockScript(
                                    filter_script,
                                    block_number,
                                    tx_index,
                                    io_index,
                                    match io_type {
                                        CellType::Input => storage::CellType::Input,
                                        CellType::Output => storage::CellType::Output,
                                    },
                                )
                                .into_vec(),
                            )
                            .expect("get TxLockScript should be OK")
                            .is_some(),
                        ScriptType::Type => storage
                            .get(
                                Key::TxTypeScript(
                                    filter_script,
                                    block_number,
                                    tx_index,
                                    io_index,
                                    match io_type {
                                        CellType::Input => storage::CellType::Input,
                                        CellType::Output => storage::CellType::Output,
                                    },
                                )
                                .into_vec(),
                            )
                            .expect("get TxTypeScript should be OK")
                            .is_some(),
                    };

                    if !filter_script_matched {
                        continue;
                    }
                }

                if let Some([r0, r1]) = filter_block_range {
                    if block_number < r0 || block_number >= r1 {
                        continue;
                    }
                }

                let last_tx_hash_is_same = tx_with_cells
                    .last_mut()
                    .map(|last| {
                        if last.transaction.hash == tx_hash.unpack() {
                            last.cells.push((io_type.clone(), io_index.into()));
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or_default();

                if !last_tx_hash_is_same {
                    tx_with_cells.push(TxWithCells {
                        transaction: tx.into_view().into(),
                        block_number: block_number.into(),
                        tx_index: tx_index.into(),
                        cells: vec![(io_type, io_index.into())],
                    });
                }
            }
            let prefix_cloned = prefix.clone();
            kvs = storage.collect_iterator(
                last_key.clone(),
                direction,
                Box::new(move |key| key.starts_with(&prefix_cloned)),
                100,
                1,
            );
        }
        Ok((Pagination {
            objects: tx_with_cells.into_iter().map(Tx::Grouped).collect(),
            last_cursor: JsonBytes::from_vec(last_key),
        })
        .serialize(&SERIALIZER)?)
    } else {
        let kvs: Vec<_> = storage.collect_iterator(
            from_key,
            direction,
            Box::new(move |key| key.starts_with(&prefix)),
            limit,
            skip,
        );
        let mut last_key = Vec::new();
        let mut txs = Vec::new();
        for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
            let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
            let tx = packed::Transaction::from_slice(
                &storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .expect("get tx should be OK")
                    .expect("stored tx")[12..],
            )
            .expect("from stored tx slice should be OK");

            let block_number = u64::from_be_bytes(
                key[key.len() - 17..key.len() - 9]
                    .try_into()
                    .expect("stored block_number"),
            );
            let tx_index = u32::from_be_bytes(
                key[key.len() - 9..key.len() - 5]
                    .try_into()
                    .expect("stored tx_index"),
            );
            let io_index = u32::from_be_bytes(
                key[key.len() - 5..key.len() - 1]
                    .try_into()
                    .expect("stored io_index"),
            );
            let io_type = if *key.last().expect("stored io_type") == 0 {
                CellType::Input
            } else {
                CellType::Output
            };

            if let Some(filter_script) = filter_script.as_ref() {
                match filter_script_type {
                    ScriptType::Lock => {
                        if storage
                            .get(
                                Key::TxLockScript(
                                    filter_script,
                                    block_number,
                                    tx_index,
                                    io_index,
                                    match io_type {
                                        CellType::Input => storage::CellType::Input,
                                        CellType::Output => storage::CellType::Output,
                                    },
                                )
                                .into_vec(),
                            )
                            .expect("get TxLockScript should be OK")
                            .is_none()
                        {
                            continue;
                        };
                    }
                    ScriptType::Type => {
                        if storage
                            .get(
                                Key::TxTypeScript(
                                    filter_script,
                                    block_number,
                                    tx_index,
                                    io_index,
                                    match io_type {
                                        CellType::Input => storage::CellType::Input,
                                        CellType::Output => storage::CellType::Output,
                                    },
                                )
                                .into_vec(),
                            )
                            .expect("get TxTypeScript should be OK")
                            .is_none()
                        {
                            continue;
                        };
                    }
                }
            }

            if let Some([r0, r1]) = filter_block_range {
                if block_number < r0 || block_number >= r1 {
                    continue;
                }
            }

            last_key = key.to_vec();
            txs.push(Tx::Ungrouped(TxWithCell {
                transaction: tx.into_view().into(),
                block_number: block_number.into(),
                tx_index: tx_index.into(),
                io_index: io_index.into(),
                io_type,
            }))
        }

        Ok((Pagination {
            objects: txs,
            last_cursor: JsonBytes::from_vec(last_key),
        })
        .serialize(&SERIALIZER)?)
    }
}

#[wasm_bindgen]
pub fn get_cells_capacity(search_key: JsValue) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;
    debug!("Call get_cells_capacity: {:?}", search_key);
    let (prefix, from_key, direction, skip) = build_query_options(
        &search_key,
        KeyPrefix::CellLockScript,
        KeyPrefix::CellTypeScript,
        Order::Asc,
        None,
    )?;
    let filter_script_type = match search_key.script_type {
        ScriptType::Lock => ScriptType::Type,
        ScriptType::Type => ScriptType::Lock,
    };
    let (
        filter_prefix,
        filter_script_len_range,
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ) = build_filter_options(search_key)?;

    let storage = STORAGE_WITH_DATA.get().unwrap().storage();
    let kvs: Vec<_> = storage.collect_iterator(
        from_key,
        direction,
        Box::new(move |key| key.starts_with(&prefix)),
        usize::MAX,
        skip,
    );

    let mut capacity = 0;
    for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
        let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
        let output_index = u32::from_be_bytes(
            key[key.len() - 4..]
                .try_into()
                .expect("stored output_index"),
        );
        let block_number = u64::from_be_bytes(
            key[key.len() - 16..key.len() - 8]
                .try_into()
                .expect("stored block_number"),
        );

        let tx = packed::Transaction::from_slice(
            &storage
                .get(Key::TxHash(&tx_hash).into_vec())
                .expect("get tx should be OK")
                .expect("stored tx")[12..],
        )
        .expect("from stored tx slice should be OK");
        let output = tx
            .raw()
            .outputs()
            .get(output_index as usize)
            .expect("get output by index should be OK");
        let output_data = tx
            .raw()
            .outputs_data()
            .get(output_index as usize)
            .expect("get output data by index should be OK");

        if let Some(prefix) = filter_prefix.as_ref() {
            match filter_script_type {
                ScriptType::Lock => {
                    if !extract_raw_data(&output.lock())
                        .as_slice()
                        .starts_with(prefix)
                    {
                        continue;
                    }
                }
                ScriptType::Type => {
                    if output.type_().is_none()
                        || !extract_raw_data(&output.type_().to_opt().unwrap())
                            .as_slice()
                            .starts_with(prefix)
                    {
                        continue;
                    }
                }
            }
        }

        if let Some([r0, r1]) = filter_script_len_range {
            match filter_script_type {
                ScriptType::Lock => {
                    let script_len = extract_raw_data(&output.lock()).len();
                    if script_len < r0 || script_len > r1 {
                        continue;
                    }
                }
                ScriptType::Type => {
                    let script_len = output
                        .type_()
                        .to_opt()
                        .map(|script| extract_raw_data(&script).len())
                        .unwrap_or_default();
                    if script_len < r0 || script_len > r1 {
                        continue;
                    }
                }
            }
        }

        if let Some([r0, r1]) = filter_output_data_len_range {
            if output_data.len() < r0 || output_data.len() >= r1 {
                continue;
            }
        }

        if let Some([r0, r1]) = filter_output_capacity_range {
            let capacity: core::Capacity = output.capacity().unpack();
            if capacity < r0 || capacity >= r1 {
                continue;
            }
        }

        if let Some([r0, r1]) = filter_block_range {
            if block_number < r0 || block_number >= r1 {
                continue;
            }
        }

        capacity += Unpack::<core::Capacity>::unpack(&output.capacity()).as_u64()
    }

    let key = Key::Meta(LAST_STATE_KEY).into_vec();
    let tip_header = storage
        .get(key)
        .expect("snapshot get last state should be ok")
        .map(|data| packed::HeaderReader::from_slice_should_be_ok(&data[32..]).to_entity())
        .expect("tip header should be inited");
    Ok((CellsCapacity {
        capacity: capacity.into(),
        block_hash: tip_header.calc_header_hash().unpack(),
        block_number: tip_header.raw().number().unpack(),
    })
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn send_transaction(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let tx: Transaction = serde_wasm_bindgen::from_value(tx)?;
    let tx: packed::Transaction = tx.into();
    let tx = tx.into_view();

    let swc = STORAGE_WITH_DATA.get().unwrap();
    let consensus = CONSENSUS.get().unwrap();

    let cycles = verify_tx(
        tx.clone(),
        swc,
        Arc::clone(consensus),
        &swc.storage().get_last_state().1.into_view(),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid transaction: {:?}", e)))?;
    swc.pending_txs().blocking_write().push(tx.clone(), cycles);

    Ok(Unpack::<H256>::unpack(&tx.hash()).0.to_vec())
}

#[wasm_bindgen]
pub fn get_transaction(tx_hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let tx_hash = H256::from_str(&tx_hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let swc = STORAGE_WITH_DATA.get().unwrap();

    if let Some((transaction, header)) = swc.storage().get_transaction_with_header(&tx_hash.pack())
    {
        return Ok((TransactionWithStatus {
            transaction: Some(transaction.into_view().into()),
            cycles: None,
            tx_status: TxStatus {
                block_hash: Some(header.into_view().hash().unpack()),
                status: Status::Committed,
            },
        })
        .serialize(&SERIALIZER)?);
    }

    if let Some((transaction, cycles, _)) = swc.pending_txs().blocking_read().get(&tx_hash.pack()) {
        return Ok((TransactionWithStatus {
            transaction: Some(transaction.into_view().into()),
            cycles: Some(cycles.into()),
            tx_status: TxStatus {
                block_hash: None,
                status: Status::Pending,
            },
        })
        .serialize(&SERIALIZER)?);
    }

    Ok((TransactionWithStatus {
        transaction: None,
        cycles: None,
        tx_status: TxStatus {
            block_hash: None,
            status: Status::Unknown,
        },
    })
    .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn fetch_transaction(tx_hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let tws = get_transaction(tx_hash)?;
    let tws: TransactionWithStatus = serde_wasm_bindgen::from_value(tws)?;
    if tws.transaction.is_some() {
        return Ok((FetchStatus::Fetched { data: tws }).serialize(&SERIALIZER)?);
    }
    let tx_hash = H256::from_str(&tx_hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let swc = STORAGE_WITH_DATA.get().unwrap();

    let now = unix_time_as_millis();
    if let Some((added_ts, first_sent, missing)) = swc.get_tx_fetch_info(&tx_hash) {
        if missing {
            // re-fetch the transaction
            swc.add_fetch_tx(tx_hash, now);
            return Ok((FetchStatus::<TransactionWithStatus>::NotFound).serialize(&SERIALIZER)?);
        } else if first_sent > 0 {
            return Ok((FetchStatus::<TransactionWithStatus>::Fetching {
                first_sent: first_sent.into(),
            })
            .serialize(&SERIALIZER)?);
        } else {
            return Ok((FetchStatus::<TransactionWithStatus>::Added {
                timestamp: added_ts.into(),
            })
            .serialize(&SERIALIZER)?);
        }
    } else {
        swc.add_fetch_tx(tx_hash, now);
    }
    Ok((FetchStatus::<TransactionWithStatus>::Added {
        timestamp: now.into(),
    })
    .serialize(&SERIALIZER)?)
}

const MAX_PREFIX_SEARCH_SIZE: usize = u16::MAX as usize;

// a helper fn to build query options from search paramters, returns prefix, from_key, direction and skip offset
pub fn build_query_options(
    search_key: &SearchKey,
    lock_prefix: KeyPrefix,
    type_prefix: KeyPrefix,
    order: Order,
    after_cursor: Option<JsonBytes>,
) -> Result<(Vec<u8>, Vec<u8>, CursorDirection, usize), JsValue> {
    let mut prefix = match search_key.script_type {
        ScriptType::Lock => vec![lock_prefix as u8],
        ScriptType::Type => vec![type_prefix as u8],
    };
    let script: packed::Script = search_key.script.clone().into();
    let args_len = script.args().len();
    if args_len > MAX_PREFIX_SEARCH_SIZE {
        return Err(JsValue::from_str(&format!(
            "search_key.script.args len should be less than {}",
            MAX_PREFIX_SEARCH_SIZE
        )));
    }
    prefix.extend_from_slice(extract_raw_data(&script).as_slice());

    let (from_key, direction, skip) = match order {
        Order::Asc => after_cursor.map_or_else(
            || (prefix.clone(), CursorDirection::NextUnique, 0),
            |json_bytes| (json_bytes.as_bytes().into(), CursorDirection::NextUnique, 1),
        ),
        Order::Desc => after_cursor.map_or_else(
            || {
                (
                    [
                        prefix.clone(),
                        vec![0xff; MAX_PREFIX_SEARCH_SIZE - args_len],
                    ]
                    .concat(),
                    CursorDirection::PrevUnique,
                    0,
                )
            },
            |json_bytes| (json_bytes.as_bytes().into(), CursorDirection::PrevUnique, 1),
        ),
    };

    Ok((prefix, from_key, direction, skip))
}

#[allow(clippy::type_complexity)]
pub fn build_filter_options(
    search_key: SearchKey,
) -> Result<
    (
        Option<Vec<u8>>,
        Option<[usize; 2]>,
        Option<[usize; 2]>,
        Option<[core::Capacity; 2]>,
        Option<[core::BlockNumber; 2]>,
    ),
    JsValue,
> {
    let filter = search_key.filter.unwrap_or_default();
    let filter_script_prefix = if let Some(script) = filter.script {
        let script: packed::Script = script.into();
        if script.args().len() > MAX_PREFIX_SEARCH_SIZE {
            return Err(JsValue::from_str(&format!(
                "search_key.filter.script.args len should be less than {}",
                MAX_PREFIX_SEARCH_SIZE
            )));
        }
        let mut prefix = Vec::new();
        prefix.extend_from_slice(extract_raw_data(&script).as_slice());
        Some(prefix)
    } else {
        None
    };

    let filter_script_len_range = filter.script_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });

    let filter_output_data_len_range = filter.output_data_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });
    let filter_output_capacity_range = filter.output_capacity_range.map(|[r0, r1]| {
        [
            core::Capacity::shannons(r0.into()),
            core::Capacity::shannons(r1.into()),
        ]
    });
    let filter_block_range = filter.block_range.map(|r| [r[0].into(), r[1].into()]);

    Ok((
        filter_script_prefix,
        filter_script_len_range,
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ))
}
