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
    cell_service: LightClientService<Storage>,
    chain_service: LightClientChainService,
}

pub struct TransactionRpcImpl {
    service: LightClientChainService,
}

pub struct ChainRpcImpl {
    service: LightClientChainService,
}

pub struct NetRpcImpl {
    service: LightClientNetworkService,
}

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        self.chain_service.set_scripts(scripts, command);
        Ok(())
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        Ok(self.chain_service.get_scripts())
    }

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        self.cell_service
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
        self.cell_service
            .get_transactions(search_key, order, limit, after_cursor)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        self.cell_service
            .get_cells_capacity(search_key)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }
}

const MAX_ADDRS: usize = 50;

impl NetRpc for NetRpcImpl {
    fn local_node_info(&self) -> Result<LocalNode> {
        Ok(self.service.local_node_info(MAX_ADDRS))
    }

    fn get_peers(&self) -> Result<Vec<RemoteNode>> {
        Ok(self.service.get_peers())
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn send_transaction(&self, tx: Transaction) -> Result<H256> {
        self.service
            .send_transaction(tx)
            .map_err(|e| Error::invalid_params(format!("{}", e)))
    }

    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus> {
        Ok(self.service.get_transaction(&tx_hash))
    }

    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>> {
        Ok(self.service.fetch_transaction(&tx_hash))
    }
}

impl ChainRpc for ChainRpcImpl {
    fn get_tip_header(&self) -> Result<HeaderView> {
        Ok(self.service.get_tip_header())
    }

    fn get_genesis_block(&self) -> Result<BlockView> {
        Ok(self.service.get_genesis_block())
    }

    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>> {
        Ok(self.service.get_header(&block_hash))
    }

    fn fetch_header(&self, block_hash: H256) -> Result<FetchStatus<HeaderView>> {
        Ok(self.service.fetch_header(&block_hash))
    }

    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles> {
        let cycles = self
            .service
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
        let swc = StorageWithChainData::new(
            storage.clone(),
            Arc::clone(&peers),
            Arc::clone(&pending_txs),
        );
        let consensus = Arc::new(consensus);

        let chain_service = LightClientChainService::new(swc.clone(), Arc::clone(&consensus));
        let cell_service = LightClientService::new(Arc::new(storage));

        let block_filter_rpc_impl = BlockFilterRpcImpl {
            cell_service,
            chain_service: chain_service.clone(),
        };
        let chain_rpc_impl = ChainRpcImpl {
            service: chain_service.clone(),
        };
        let transaction_rpc_impl = TransactionRpcImpl {
            service: chain_service,
        };
        let net_rpc_impl = NetRpcImpl {
            service: LightClientNetworkService::new(network_controller, peers),
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
