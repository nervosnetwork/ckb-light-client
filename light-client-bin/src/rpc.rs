use std::{
    net::ToSocketAddrs,
    sync::{Arc, RwLock},
};

use jsonrpc_core::{Error, IoHandler, Result};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;

use ckb_light_client_lib::{
    protocols::{Peers, PendingTxs},
    service::{
        Cell, CellsCapacity, FetchStatus, LocalNode, LocalNodeProtocol, Order, Pagination,
        PeerSyncState, RemoteNode, ScriptStatus, SearchKey, SetScriptsCommand,
        TransactionWithStatus, Tx,
    },
    service_impl::{LightClientChainService, LightClientService},
    storage::{Storage, StorageWithChainData},
};

use ckb_chain_spec::consensus::Consensus;
use ckb_jsonrpc_types::{
    BlockView, EstimateCycles, HeaderView, JsonBytes, NodeAddress, RemoteNodeProtocol, Transaction,
    Uint32,
};
use ckb_network::{extract_peer_id, NetworkController};
use ckb_types::H256;

#[rpc(server)]
pub trait BlockFilterRpc {
    /// curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [{"script": {"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}, "block_number": "0x59F74D"}], "id": 1}'
    #[rpc(name = "set_scripts")]
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()>;

    #[rpc(name = "get_scripts")]
    fn get_scripts(&self) -> Result<Vec<ScriptStatus>>;

    #[rpc(name = "get_cells")]
    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>>;

    #[rpc(name = "get_transactions")]
    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>>;

    #[rpc(name = "get_cells_capacity")]
    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity>;
}

#[rpc(server)]
pub trait TransactionRpc {
    #[rpc(name = "send_transaction")]
    fn send_transaction(&self, tx: Transaction) -> Result<H256>;

    #[rpc(name = "get_transaction")]
    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus>;

    #[rpc(name = "fetch_transaction")]
    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>>;
}

#[rpc(server)]
pub trait ChainRpc {
    #[rpc(name = "get_tip_header")]
    fn get_tip_header(&self) -> Result<HeaderView>;

    #[rpc(name = "get_genesis_block")]
    fn get_genesis_block(&self) -> Result<BlockView>;

    #[rpc(name = "get_header")]
    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>>;

    #[rpc(name = "fetch_header")]
    fn fetch_header(&self, block_hash: H256) -> Result<FetchStatus<HeaderView>>;

    #[rpc(name = "estimate_cycles")]
    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles>;
}

#[rpc(server)]
pub trait NetRpc {
    #[rpc(name = "local_node_info")]
    fn local_node_info(&self) -> Result<LocalNode>;

    #[rpc(name = "get_peers")]
    fn get_peers(&self) -> Result<Vec<RemoteNode>>;
}

pub struct BlockFilterRpcImpl {
    pub(crate) swc: StorageWithChainData,
}

pub struct TransactionRpcImpl {
    pub(crate) swc: StorageWithChainData,
    pub(crate) consensus: Arc<Consensus>,
}

pub struct ChainRpcImpl {
    pub(crate) swc: StorageWithChainData,
    pub(crate) consensus: Arc<Consensus>,
}

pub struct NetRpcImpl {
    network_controller: NetworkController,
    peers: Arc<Peers>,
}

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let swc = self.swc.clone();
        std::thread::spawn(move || {
            let mut matched_blocks = swc.matched_blocks().blocking_write();
            let scripts = scripts.into_iter().map(Into::into).collect();
            swc.storage()
                .update_filter_scripts(scripts, command.map(Into::into).unwrap_or_default());
            matched_blocks.clear();
            tx.send(()).unwrap();
        });
        rx.recv().unwrap();
        Ok(())
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        let scripts = self.swc.storage().get_filter_scripts();
        Ok(scripts.into_iter().map(Into::into).collect())
    }

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        // Use unified service layer
        let service = LightClientService::new(Arc::new(self.swc.storage().clone()));
        service
            .get_cells(search_key, order, limit, after_cursor)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>> {
        // Use unified service layer
        let service = LightClientService::new(Arc::new(self.swc.storage().clone()));
        service
            .get_transactions(search_key, order, limit, after_cursor)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        // Use unified service layer
        let service = LightClientService::new(Arc::new(self.swc.storage().clone()));
        service
            .get_cells_capacity(search_key)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }
}

const MAX_ADDRS: usize = 50;

impl NetRpc for NetRpcImpl {
    fn local_node_info(&self) -> Result<LocalNode> {
        Ok(LocalNode {
            version: self.network_controller.version().to_owned(),
            node_id: self.network_controller.node_id(),
            active: self.network_controller.is_active(),
            addresses: self
                .network_controller
                .public_urls(MAX_ADDRS)
                .into_iter()
                .map(|(address, score)| NodeAddress {
                    address,
                    score: u64::from(score).into(),
                })
                .collect(),
            protocols: self
                .network_controller
                .protocols()
                .into_iter()
                .map(|(protocol_id, name, support_versions)| LocalNodeProtocol {
                    id: (protocol_id.value() as u64).into(),
                    name,
                    support_versions,
                })
                .collect::<Vec<_>>(),
            connections: (self.network_controller.connected_peers().len() as u64).into(),
        })
    }

    fn get_peers(&self) -> Result<Vec<RemoteNode>> {
        let peers: Vec<RemoteNode> = self
            .network_controller
            .connected_peers()
            .iter()
            .map(|(peer_index, peer)| {
                let mut addresses = vec![&peer.connected_addr];
                addresses.extend(peer.listened_addrs.iter());

                let node_addresses = addresses
                    .iter()
                    .map(|addr| {
                        let score = self
                            .network_controller
                            .addr_info(addr)
                            .map(|addr_info| addr_info.score)
                            .unwrap_or(1);
                        let non_negative_score = if score > 0 { score as u64 } else { 0 };
                        NodeAddress {
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
                    connected_duration: (std::time::Instant::now()
                        .saturating_duration_since(peer.connected_time)
                        .as_millis() as u64)
                        .into(),
                    sync_state: self.peers.get_state(peer_index).map(|state| PeerSyncState {
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
                        .map(|(protocol_id, protocol_version)| RemoteNodeProtocol {
                            id: (protocol_id.value() as u64).into(),
                            version: protocol_version.clone(),
                        })
                        .collect(),
                }
            })
            .collect();
        Ok(peers)
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn send_transaction(&self, tx: Transaction) -> Result<H256> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        service
            .send_transaction(tx)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }

    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.get_transaction(&tx_hash))
    }

    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.fetch_transaction(&tx_hash))
    }
}

impl ChainRpc for ChainRpcImpl {
    fn get_tip_header(&self) -> Result<HeaderView> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.get_tip_header())
    }

    fn get_genesis_block(&self) -> Result<BlockView> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.get_genesis_block())
    }

    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.get_header(&block_hash))
    }

    fn fetch_header(&self, block_hash: H256) -> Result<FetchStatus<HeaderView>> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.fetch_header(&block_hash))
    }

    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        let cycles = service
            .estimate_cycles(tx)
            .map_err(|e| Error::invalid_params(format!("{}", e)))?;
        Ok(EstimateCycles { cycles })
    }
}

pub struct Service {
    listen_address: String,
}

impl Service {
    pub fn new(listen_address: &str) -> Self {
        Self {
            listen_address: listen_address.to_string(),
        }
    }

    pub fn start(
        &self,
        network_controller: NetworkController,
        storage: Storage,
        peers: Arc<Peers>,
        pending_txs: Arc<RwLock<PendingTxs>>,
        consensus: Consensus,
    ) -> Server {
        let mut io_handler = IoHandler::new();
        let swc = StorageWithChainData::new(storage, Arc::clone(&peers), Arc::clone(&pending_txs));
        let consensus = Arc::new(consensus);
        let block_filter_rpc_impl = BlockFilterRpcImpl { swc: swc.clone() };
        let chain_rpc_impl = ChainRpcImpl {
            swc: swc.clone(),
            consensus: Arc::clone(&consensus),
        };
        let transaction_rpc_impl = TransactionRpcImpl { swc, consensus };
        let net_rpc_impl = NetRpcImpl {
            network_controller,
            peers,
        };
        io_handler.extend_with(block_filter_rpc_impl.to_delegate());
        io_handler.extend_with(chain_rpc_impl.to_delegate());
        io_handler.extend_with(transaction_rpc_impl.to_delegate());
        io_handler.extend_with(net_rpc_impl.to_delegate());

        ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .health_api(("/ping", "ping"))
            .start_http(
                &self
                    .listen_address
                    .to_socket_addrs()
                    .expect("config listen_address parsed")
                    .next()
                    .expect("config listen_address parsed"),
            )
            .expect("Start Jsonrpc HTTP service")
    }
}
