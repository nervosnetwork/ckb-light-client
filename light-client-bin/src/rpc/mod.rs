use ckb_light_client_lib::{
    protocols::PendingTxs,
    storage::{
        db::{
            StorageGeneralOperations, StorageGetPinnedRelatedOperations, StorageHighLevelOperations,
        },
        Storage,
    },
    types::RwLock,
};
use ckb_light_client_rpc::{
    BlockFilterRpcImpl, BlockFilterRpcMethods, ChainRpcImpl, ChainRpcMethods, NetRpcImpl,
    NetRpcMethods, TransactionRpcImpl, TransactionRpcMethods,
};
use jsonrpc_core::{Error, IoHandler, Result};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, Server, ServerBuilder};
use std::{net::ToSocketAddrs, sync::Arc};

use ckb_chain_spec::consensus::Consensus;
use ckb_jsonrpc_types::{BlockView, EstimateCycles, HeaderView, JsonBytes, Transaction, Uint32};
use ckb_light_client_lib::{
    protocols::Peers,
    service::{
        Cell, CellsCapacity, FetchStatus, LocalNode, Order, Pagination, RemoteNode, ScriptStatus,
        SearchKey, SetScriptsCommand, TransactionWithStatus, Tx,
    },
    storage::StorageWithChainData,
};
use ckb_network::NetworkController;
use ckb_traits::CellDataProvider;
use ckb_types::H256;
use jsonrpc_derive::rpc;

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
    fn fetch_header(
        &self,
        block_hash: H256,
    ) -> Result<ckb_light_client_lib::service::FetchStatus<HeaderView>>;

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

impl<S: StorageHighLevelOperations + Send + Sync + Clone + 'static> BlockFilterRpc
    for BlockFilterRpcImpl<S>
{
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        BlockFilterRpcMethods::set_scripts(self, scripts, command)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        BlockFilterRpcMethods::get_scripts(self).map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        BlockFilterRpcMethods::get_cells(self, search_key, order, limit, after)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>> {
        BlockFilterRpcMethods::get_transactions(self, search_key, order, limit, after)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        BlockFilterRpcMethods::get_cells_capacity(self, search_key)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }
}

impl<
        S: StorageHighLevelOperations
            + StorageGetPinnedRelatedOperations
            + CellDataProvider
            + Send
            + Sync
            + Clone
            + 'static,
    > TransactionRpc for TransactionRpcImpl<S>
{
    fn send_transaction(&self, tx: Transaction) -> Result<H256> {
        TransactionRpcMethods::send_transaction(self, tx)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus> {
        TransactionRpcMethods::get_transaction(self, tx_hash)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>> {
        TransactionRpcMethods::fetch_transaction(self, tx_hash)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }
}

impl<
        S: StorageHighLevelOperations
            + StorageGeneralOperations
            + StorageGetPinnedRelatedOperations
            + CellDataProvider
            + Send
            + Sync
            + Clone
            + 'static,
    > ChainRpc for ChainRpcImpl<S>
{
    fn get_tip_header(&self) -> Result<HeaderView> {
        ChainRpcMethods::get_tip_header(self).map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_genesis_block(&self) -> Result<BlockView> {
        ChainRpcMethods::get_genesis_block(self).map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>> {
        ChainRpcMethods::get_header(self, block_hash)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn fetch_header(
        &self,
        block_hash: H256,
    ) -> Result<ckb_light_client_lib::service::FetchStatus<HeaderView>> {
        ChainRpcMethods::fetch_header(self, block_hash)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles> {
        ChainRpcMethods::estimate_cycles(self, tx).map_err(|e| Error::invalid_params(e.to_string()))
    }
}

impl NetRpc for NetRpcImpl {
    fn local_node_info(&self) -> Result<LocalNode> {
        NetRpcMethods::local_node_info(self).map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn get_peers(&self) -> Result<Vec<RemoteNode>> {
        NetRpcMethods::get_peers(self).map_err(|e| Error::invalid_params(e.to_string()))
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
