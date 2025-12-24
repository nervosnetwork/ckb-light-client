//! Shared runtime bootstrap for native targets (CLI and JNI).
//!
//! This module contains the same startup path the binary uses, but returns
//! the handles required to shut the light client down gracefully from
//! embedded environments (Android JNI, tests, etc).

use crate::error::{Error, Result};
use crate::protocols::{
    FilterProtocol, LightClientProtocol, Peers, PendingTxs, RelayProtocol, SyncProtocol,
    BAD_MESSAGE_ALLOWED_EACH_HOUR, CHECK_POINT_INTERVAL,
};
use crate::storage::{Storage, StorageWithChainData};
use crate::types::RunEnv;
use crate::utils;
use ckb_async_runtime::{new_global_runtime, tokio, Handle, Runtime};
use ckb_chain_spec::{consensus::Consensus, ChainSpec};
use ckb_network::{
    network::TransportType, CKBProtocol, CKBProtocolHandler, Flags, NetworkService, NetworkState,
    SupportProtocols,
};
use ckb_resource::Resource;
use std::sync::{Arc, RwLock};

/// Holds the running light client pieces so callers can control shutdown.
pub struct StartedLightClient {
    runtime_handle: Handle,
    runtime_stop_rx: tokio::sync::mpsc::Receiver<()>,
    runtime: Runtime,
    network_controller: ckb_network::NetworkController,
    storage_with_data: StorageWithChainData,
    consensus: Arc<Consensus>,
    peers: Arc<Peers>,
    pending_txs: Arc<RwLock<PendingTxs>>,
}

impl StartedLightClient {
    /// Boot the light client using the provided run environment.
    pub fn start(run_env: RunEnv) -> Result<Self> {
        utils::fs::need_directory(&run_env.network.path)?;

        let storage = Storage::new(&run_env.store.path);
        let chain_spec = ChainSpec::load_from(&match run_env.chain.as_str() {
            "mainnet" => Resource::bundled("specs/mainnet.toml".to_string()),
            "testnet" => Resource::bundled("specs/testnet.toml".to_string()),
            path => Resource::file_system(path.into()),
        })
        .map_err(|err| Error::runtime(format!("failed to load spec since {}", err)))?;

        let consensus = chain_spec
            .build_consensus()
            .map_err(|err| Error::runtime(format!("failed to build consensus since {}", err)))?;

        storage.init_genesis_block(consensus.genesis_block().data());

        // Cleanup any invalid matched blocks from previous runs (e.g., uncle blocks from chain reorgs)
        log::info!("Cleaning up invalid matched blocks...");
        storage.cleanup_invalid_matched_blocks();

        let pending_txs = Arc::new(RwLock::new(PendingTxs::default()));
        let max_outbound_peers = run_env.network.max_outbound_peers;
        let network_state = NetworkState::from_config(run_env.network)
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
            })?;
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

        let (runtime_handle, runtime_stop_rx, runtime) = new_global_runtime(None);

        let network_controller = NetworkService::new(
            Arc::clone(&network_state),
            protocols,
            required_protocol_ids,
            (
                consensus.identify_name(),
                env!("CARGO_PKG_VERSION").to_owned(),
                Flags::DISCOVERY,
            ),
            // Usually native light-client only connects to peers through TCP
            TransportType::Tcp,
        )
        .start(&runtime_handle)
        .map_err(|err| {
            let errmsg = format!("failed to start network since {}", err);
            Error::runtime(errmsg)
        })?;

        let storage_with_data =
            StorageWithChainData::new(storage.clone(), Arc::clone(&peers), pending_txs.clone());

        Ok(Self {
            runtime_handle,
            runtime_stop_rx,
            runtime,
            network_controller,
            storage_with_data,
            consensus: Arc::new(consensus),
            peers,
            pending_txs,
        })
    }

    pub fn network_controller(&self) -> ckb_network::NetworkController {
        self.network_controller.clone()
    }

    pub fn storage(&self) -> Storage {
        self.storage_with_data.storage().clone()
    }

    pub fn storage_with_data(&self) -> StorageWithChainData {
        self.storage_with_data.clone()
    }

    pub fn peers(&self) -> Arc<Peers> {
        Arc::clone(&self.peers)
    }

    pub fn pending_txs(&self) -> Arc<RwLock<PendingTxs>> {
        Arc::clone(&self.pending_txs)
    }

    pub fn consensus(&self) -> Arc<Consensus> {
        Arc::clone(&self.consensus)
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn runtime_handle(&mut self) -> &mut Handle {
        &mut self.runtime_handle
    }

    pub fn stop_receiver(&mut self) -> &mut tokio::sync::mpsc::Receiver<()> {
        &mut self.runtime_stop_rx
    }
}
