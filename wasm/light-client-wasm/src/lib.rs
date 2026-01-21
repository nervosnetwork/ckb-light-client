mod utils;

use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

use ckb_light_client_lib::storage::db::StorageGeneralOperations;
use ckb_light_client_lib::{
    error::Error,
    protocols::{
        FilterProtocol, LightClientProtocol, Peers, PendingTxs, RelayProtocol, SyncProtocol,
        BAD_MESSAGE_ALLOWED_EACH_HOUR, CHECK_POINT_INTERVAL,
    },
    service::{Order, ScriptStatus, SearchKey, SetScriptsCommand},
    storage::{Storage, StorageWithChainData},
    types::RunEnv,
};
use ckb_light_client_rpc::{
    BlockFilterRpcImpl, BlockFilterRpcMethods, ChainRpcImpl, ChainRpcMethods, NetRpcImpl,
    NetRpcMethods, TransactionRpcImpl, TransactionRpcMethods,
};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

use ckb_chain_spec::ChainSpec;
use ckb_jsonrpc_types::{JsonBytes, Transaction};
use ckb_network::{
    network::TransportType, CKBProtocol, CKBProtocolHandler, Flags, NetworkService, NetworkState,
    SupportProtocols,
};
use ckb_resource::Resource;
use ckb_stop_handler::broadcast_exit_signals;
use ckb_types::H256;

use ckb_light_client_lib::storage::db::StorageBatchRelatedOperations;
use std::sync::OnceLock;
static MAINNET_CONFIG: &str = include_str!("../../../config/mainnet.toml");

static TESTNET_CONFIG: &str = include_str!("../../../config/testnet.toml");

static STORAGE_WITH_DATA: OnceLock<StorageWithChainData<Storage>> = OnceLock::new();

static SERIALIZER: Serializer = Serializer::new()
    .serialize_large_number_types_as_bigints(true)
    .serialize_maps_as_objects(true);

static BLOCK_FILTER_RPC: OnceLock<BlockFilterRpcImpl<Storage>> = OnceLock::new();
static TRANSACTION_RPC: OnceLock<TransactionRpcImpl<Storage>> = OnceLock::new();
static CHAIN_RPC: OnceLock<ChainRpcImpl<Storage>> = OnceLock::new();
static NET_RPC: OnceLock<NetRpcImpl> = OnceLock::new();

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
    let consensus = Arc::new(consensus);

    STORAGE_WITH_DATA.get_or_init(|| storage_with_data.clone());
    // NET_CONTROL.get_or_init(|| network_controller);
    // CONSENSUS.get_or_init(|| consensus.clone());
    BLOCK_FILTER_RPC.get_or_init(|| BlockFilterRpcImpl {
        swc: storage_with_data.clone(),
    });
    TRANSACTION_RPC.get_or_init(|| TransactionRpcImpl {
        swc: storage_with_data.clone(),
        consensus: consensus.clone(),
    });
    CHAIN_RPC.get_or_init(|| ChainRpcImpl {
        swc: storage_with_data.clone(),
        consensus: consensus.clone(),
    });
    NET_RPC.get_or_init(|| NetRpcImpl {
        network_controller,
        peers: storage_with_data.peers().clone(),
    });
    change_status(0b1);
    Ok(())
}

#[wasm_bindgen]
pub fn stop() {
    broadcast_exit_signals();
    STORAGE_WITH_DATA.get().unwrap().storage().shutdown();
    change_status(0b10);
}

#[wasm_bindgen]
pub fn get_tip_header() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(CHAIN_RPC
        .get()
        .unwrap()
        .get_tip_header()
        .map_err(|e| JsValue::from_str(&format!("Unable to get tip header: {:?}", e)))?
        .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_genesis_block() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(CHAIN_RPC
        .get()
        .unwrap()
        .get_genesis_block()
        .map_err(|e| JsValue::from_str(&format!("Unable to get genesis block: {:?}", e)))?
        .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_header(hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let block_hash = H256::from_str(&hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let header_view = CHAIN_RPC
        .get()
        .unwrap()
        .get_header(block_hash)
        .map_err(|e| JsValue::from_str(&format!("Unable to get header: {}", e)))?;

    Ok(header_view.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn fetch_header(hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let block_hash = H256::from_str(&hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = CHAIN_RPC
        .get()
        .unwrap()
        .fetch_header(block_hash)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn estimate_cycles(tx: JsValue) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let tx: Transaction = serde_wasm_bindgen::from_value(tx)?;

    let result = CHAIN_RPC
        .get()
        .unwrap()
        .estimate_cycles(tx)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn local_node_info() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(NET_RPC
        .get()
        .unwrap()
        .local_node_info()
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn get_peers() -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    Ok(NET_RPC
        .get()
        .unwrap()
        .get_peers()
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn set_scripts(
    scripts: Vec<JsValue>,
    command: Option<SetScriptsCommand>,
) -> Result<(), JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let scripts: Vec<ScriptStatus> = scripts
        .into_iter()
        .map(serde_wasm_bindgen::from_value::<ScriptStatus>)
        .collect::<Result<Vec<_>, _>>()?;
    BLOCK_FILTER_RPC
        .get()
        .unwrap()
        .set_scripts(scripts, command)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(())
}

#[wasm_bindgen]
pub fn get_scripts() -> Result<Vec<JsValue>, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let result = BLOCK_FILTER_RPC
        .get()
        .unwrap()
        .get_scripts()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(result
        .into_iter()
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
    let result = BLOCK_FILTER_RPC
        .get()
        .unwrap()
        .get_cells(
            search_key,
            order,
            limit.into(),
            after_cursor.map(JsonBytes::from_vec),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
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

    let result = BLOCK_FILTER_RPC
        .get()
        .unwrap()
        .get_transactions(
            search_key,
            order,
            limit.into(),
            after_cursor.map(JsonBytes::from_vec),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}
#[wasm_bindgen]
pub fn get_cells_capacity(search_key: JsValue) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }

    let search_key: SearchKey = serde_wasm_bindgen::from_value(search_key)?;

    let result = BLOCK_FILTER_RPC
        .get()
        .unwrap()
        .get_cells_capacity(search_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn send_transaction(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let tx: Transaction = serde_wasm_bindgen::from_value(tx)?;

    let result = TRANSACTION_RPC
        .get()
        .unwrap()
        .send_transaction(tx)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(result.0.to_vec())
}

#[wasm_bindgen]
pub fn get_transaction(tx_hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let tx_hash = H256::from_str(&tx_hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = TRANSACTION_RPC
        .get()
        .unwrap()
        .get_transaction(tx_hash)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}

#[wasm_bindgen]
pub fn fetch_transaction(tx_hash: &str) -> Result<JsValue, JsValue> {
    if !status(0b1) {
        return Err(JsValue::from_str("light client not on start state"));
    }
    let tx_hash = H256::from_str(&tx_hash[2..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = TRANSACTION_RPC
        .get()
        .unwrap()
        .fetch_transaction(tx_hash)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(result.serialize(&SERIALIZER)?)
}
