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
        Cell, CellsCapacity, FetchStatus, LightClientChainService, LightClientNetworkService,
        LightClientService, LocalNode, Order, Pagination, RemoteNode, ScriptStatus, SearchKey,
        SetScriptsCommand, TransactionWithStatus, Tx,
    },
    storage::{Storage, StorageWithChainData},
};

use ckb_chain_spec::consensus::Consensus;
use ckb_jsonrpc_types::{BlockView, EstimateCycles, HeaderView, JsonBytes, Transaction, Uint32};
use ckb_network::NetworkController;
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
    pub(crate) consensus: Arc<Consensus>,
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
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        service.set_scripts(scripts, command);
        Ok(())
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        // Use unified service layer
        let service = LightClientChainService::new(self.swc.clone(), Arc::clone(&self.consensus));
        Ok(service.get_scripts())
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
        // Use unified service layer
        let service = LightClientNetworkService::new(
            self.network_controller.clone(),
            Arc::clone(&self.peers),
        );
        Ok(service.local_node_info(MAX_ADDRS))
    }

    fn get_peers(&self) -> Result<Vec<RemoteNode>> {
        // Use unified service layer
        let service = LightClientNetworkService::new(
            self.network_controller.clone(),
            Arc::clone(&self.peers),
        );
        Ok(service.get_peers())
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
        let block_filter_rpc_impl = BlockFilterRpcImpl {
            swc: swc.clone(),
            consensus: Arc::clone(&consensus),
        };
        let chain_rpc_impl = ChainRpcImpl {
            swc: swc.clone(),
            consensus: Arc::clone(&consensus),
        };
        let transaction_rpc_impl = TransactionRpcImpl {
            swc,
            consensus: Arc::clone(&consensus),
        };
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
