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
        FetchStatus, LocalNode, LocalNodeProtocol, Order, PeerSyncState, RemoteNode, ScriptStatus,
        SearchKey, SetScriptsCommand, Status, TransactionWithStatus, TxStatus,
    },
    service_impl::LightClientService,
    storage::{Storage, StorageWithChainData},
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
    extract_peer_id, network::TransportType, CKBProtocol, CKBProtocolHandler, Flags,
    NetworkController, NetworkService, NetworkState, SupportProtocols,
};
use ckb_resource::Resource;
use ckb_stop_handler::broadcast_exit_signals;
use ckb_systemtime::{unix_time_as_millis, Instant};
use ckb_types::{packed, prelude::*, H256};

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

#[derive(Deserialize, Debug)]
enum WasmTransportType {
    #[serde(rename = "ws")]
    Ws,
    #[serde(rename = "wss")]
    Wss,
}

#[wasm_bindgen]
pub async fn light_client(
    network_setting: JsValue,
    log_level: String,
    network_secret_key: JsValue,
    wasm_transport_type: JsValue,
    network_config_is_json: bool,
) -> Result<(), JsValue> {
    if !status(0b0) {
        return Err(JsValue::from_str("Can't start twice"));
    }
    utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::new(
        log::Level::from_str(&log_level).expect("Bad log level"),
    ));
    let network_flag: NetworkSetting = serde_wasm_bindgen::from_value(network_setting)?;

    let wasm_transport_type: WasmTransportType =
        serde_wasm_bindgen::from_value(wasm_transport_type)?;
    debug!(
        "Starting with wasm transport type = {:?}",
        wasm_transport_type
    );
    enum NetworkConfigType<'a> {
        Default(&'a str),
        UserDefined(&'a str),
    }
    let config_string = match &network_flag {
        NetworkSetting::TestNet { config } => config
            .as_ref()
            .map_or(NetworkConfigType::Default(TESTNET_CONFIG), |v| {
                NetworkConfigType::UserDefined(v.as_str())
            }),
        NetworkSetting::MainNet { config } => config
            .as_ref()
            .map_or(NetworkConfigType::Default(MAINNET_CONFIG), |v| {
                NetworkConfigType::UserDefined(v.as_str())
            }),
        NetworkSetting::DevNet { config, .. } => NetworkConfigType::UserDefined(config.as_str()),
    };
    let mut config = match config_string {
        NetworkConfigType::Default(s) => s.parse::<RunEnv>().unwrap(),
        NetworkConfigType::UserDefined(s) => {
            if network_config_is_json {
                serde_json::from_str(s)
                    .map_err(|e| format!("Unable to parse network setting from json: {}", e))?
            } else {
                s.parse::<RunEnv>()
                    .map_err(|e| format!("Unable to parse network setting from toml: {}", e))?
            }
        }
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

    // Cleanup any invalid matched blocks from previous runs (e.g., uncle blocks from chain reorgs)
    log::info!("Cleaning up invalid matched blocks...");
    storage.cleanup_invalid_matched_blocks();

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
    let relay_protocol =
        RelayProtocol::new(pending_txs.clone(), Arc::clone(&peers), storage.clone());
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
            SupportProtocols::RelayV3,
            Box::new(relay_protocol),
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
        match wasm_transport_type {
            WasmTransportType::Ws => TransportType::Ws,
            WasmTransportType::Wss => TransportType::Wss,
        },
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
    let after_cursor_json = after_cursor.map(JsonBytes::from_vec);
    
    let storage = STORAGE_WITH_DATA
        .get()
        .ok_or_else(|| JsValue::from_str("storage not initialized"))?
        .storage();
    
    let service = LightClientService::new(Arc::new(storage.clone()));
    let result = service
        .get_cells(search_key, order, limit.into(), after_cursor_json)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    
    Ok(result.serialize(&SERIALIZER)?)
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
    debug!(
        "Calling get_transactions with {:?}, {:?}, {:?}, {:?}",
        search_key, order, limit, after_cursor
    );
    
    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;
    let after_cursor_json = after_cursor.map(JsonBytes::from_vec);
    
    let storage = STORAGE_WITH_DATA
        .get()
        .ok_or_else(|| JsValue::from_str("storage not initialized"))?
        .storage();
    
    let service = LightClientService::new(Arc::new(storage.clone()));
    let result = service
        .get_transactions(search_key, order, limit.into(), after_cursor_json)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    
    Ok(result.serialize(&SERIALIZER)?)
}
#[wasm_bindgen]
pub fn get_cells_capacity(search_key: JsValue) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;
    debug!("Call get_cells_capacity: {:?}", search_key);
    
    let storage = STORAGE_WITH_DATA
        .get()
        .ok_or_else(|| JsValue::from_str("storage not initialized"))?
        .storage();
    
    let service = LightClientService::new(Arc::new(storage.clone()));
    let result = service
        .get_cells_capacity(search_key)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    
    Ok(result.serialize(&SERIALIZER)?)
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
