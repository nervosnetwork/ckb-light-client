use ckb_jsonrpc_types::{
    BlockNumber, Capacity, CellOutput, Cycle, HeaderView, JsonBytes, NodeAddress, OutPoint,
    RemoteNodeProtocol, Script, TransactionView, Uint32, Uint64,
};
use ckb_types::H256;
use serde::{Deserialize, Serialize};

use crate::storage;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SetScriptsCommand {
    // Replace all scripts with new scripts, non-exist scripts will be deleted
    All,
    // Update partial scripts with new scripts, non-exist scripts will be ignored
    Partial,
    // Delete scripts, non-exist scripts will be ignored
    Delete,
}

impl From<SetScriptsCommand> for storage::SetScriptsCommand {
    fn from(cmd: SetScriptsCommand) -> Self {
        match cmd {
            SetScriptsCommand::All => Self::All,
            SetScriptsCommand::Partial => Self::Partial,
            SetScriptsCommand::Delete => Self::Delete,
        }
    }
}

#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
#[serde(tag = "status")]
#[serde(rename_all = "snake_case")]
pub enum FetchStatus<T> {
    Added { timestamp: Uint64 },
    Fetching { first_sent: Uint64 },
    Fetched { data: T },
    NotFound,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ScriptStatus {
    pub script: Script,
    pub script_type: ScriptType,
    pub block_number: BlockNumber,
}

impl From<storage::ScriptType> for ScriptType {
    fn from(st: storage::ScriptType) -> Self {
        match st {
            storage::ScriptType::Lock => Self::Lock,
            storage::ScriptType::Type => Self::Type,
        }
    }
}

impl From<ScriptType> for storage::ScriptType {
    fn from(st: ScriptType) -> Self {
        match st {
            ScriptType::Lock => Self::Lock,
            ScriptType::Type => Self::Type,
        }
    }
}

impl From<ScriptStatus> for storage::ScriptStatus {
    fn from(ss: ScriptStatus) -> Self {
        Self {
            script: ss.script.into(),
            script_type: ss.script_type.into(),
            block_number: ss.block_number.into(),
        }
    }
}

impl From<storage::ScriptStatus> for ScriptStatus {
    fn from(ss: storage::ScriptStatus) -> Self {
        Self {
            script: ss.script.into(),
            script_type: ss.script_type.into(),
            block_number: ss.block_number.into(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct LocalNode {
    /// light client node version.
    ///
    /// Example: "version": "0.2.0"
    pub version: String,
    /// The unique node ID derived from the p2p private key.
    ///
    /// The private key is generated randomly on the first boot.
    pub node_id: String,
    /// Whether this node is active.
    ///
    /// An inactive node ignores incoming p2p messages and drops outgoing messages.
    pub active: bool,
    /// P2P addresses of this node.
    ///
    /// A node can have multiple addresses.
    pub addresses: Vec<NodeAddress>,
    /// Supported protocols.
    pub protocols: Vec<LocalNodeProtocol>,
    /// Count of currently connected peers.
    pub connections: Uint64,
}

/// The information of a P2P protocol that is supported by the local node.
#[derive(Deserialize, Serialize)]
pub struct LocalNodeProtocol {
    /// Unique protocol ID.
    pub id: Uint64,
    /// Readable protocol name.
    pub name: String,
    /// Supported versions.
    ///
    /// See [Semantic Version](https://semver.org/) about how to specify a version.
    pub support_versions: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct RemoteNode {
    /// The remote node version.
    pub version: String,
    /// The remote node ID which is derived from its P2P private key.
    pub node_id: String,
    /// The remote node addresses.
    pub addresses: Vec<NodeAddress>,
    /// Elapsed time in milliseconds since the remote node is connected.
    pub connected_duration: Uint64,
    /// Null means chain sync has not started with this remote node yet.
    pub sync_state: Option<PeerSyncState>,
    /// Active protocols.
    ///
    /// CKB uses Tentacle multiplexed network framework. Multiple protocols are running
    /// simultaneously in the connection.
    pub protocols: Vec<RemoteNodeProtocol>,
    // TODO: maybe add this field later.
    // /// Elapsed time in milliseconds since receiving the ping response from this remote node.
    // ///
    // /// Null means no ping responses have been received yet.
    // pub last_ping_duration: Option<Uint64>,
}
#[derive(Deserialize, Serialize)]
pub struct PeerSyncState {
    /// Requested best known header of remote peer.
    ///
    /// This is the best known header yet to be proved.
    pub requested_best_known_header: Option<HeaderView>,
    /// Proved best known header of remote peer.
    pub proved_best_known_header: Option<HeaderView>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchKey {
    pub script: Script,
    pub script_type: ScriptType,
    pub filter: Option<SearchKeyFilter>,
    pub with_data: Option<bool>,
    pub group_by_transaction: Option<bool>,
}

impl Default for SearchKey {
    fn default() -> Self {
        Self {
            script: Script::default(),
            script_type: ScriptType::Lock,
            filter: None,
            with_data: None,
            group_by_transaction: None,
        }
    }
}

#[derive(Deserialize, Default, Serialize, Debug)]
pub struct SearchKeyFilter {
    pub script: Option<Script>,
    pub script_len_range: Option<[Uint64; 2]>,
    pub output_data_len_range: Option<[Uint64; 2]>,
    pub output_capacity_range: Option<[Uint64; 2]>,
    pub block_range: Option<[BlockNumber; 2]>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    Lock,
    Type,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    Desc,
    Asc,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cell {
    pub output: CellOutput,
    pub output_data: Option<JsonBytes>,
    pub out_point: OutPoint,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
}

#[derive(Serialize, Deserialize)]
pub struct CellsCapacity {
    pub capacity: Capacity,
    pub block_hash: H256,
    pub block_number: BlockNumber,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Tx {
    Ungrouped(TxWithCell),
    Grouped(TxWithCells),
}

impl Tx {
    pub fn tx_hash(&self) -> H256 {
        match self {
            Tx::Ungrouped(tx) => tx.transaction.hash.clone(),
            Tx::Grouped(tx) => tx.transaction.hash.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxWithCell {
    pub transaction: TransactionView,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
    pub io_index: Uint32,
    pub io_type: CellType,
}

#[derive(Serialize, Deserialize)]
pub struct TxWithCells {
    pub transaction: TransactionView,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
    pub cells: Vec<(CellType, Uint32)>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CellType {
    Input,
    Output,
}

#[derive(Serialize, Deserialize)]
pub struct Pagination<T> {
    pub objects: Vec<T>,
    pub last_cursor: JsonBytes,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TransactionWithStatus {
    pub transaction: Option<TransactionView>,
    pub cycles: Option<Cycle>,
    pub tx_status: TxStatus,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TxStatus {
    pub status: Status,
    pub block_hash: Option<H256>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Committed,
    Unknown,
}
