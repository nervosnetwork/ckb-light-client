use std::{collections::HashMap, sync::Arc};

use ckb_traits::{
    CellDataProvider, ExtensionProvider, HeaderFields, HeaderFieldsProvider, HeaderProvider,
};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        BlockNumber, BlockView, HeaderView,
    },
    packed::{self, Byte32, CellOutput, Header, OutPoint, Script, Transaction},
    prelude::*,
    utilities::FilterDataProvider,
    H256,
};

mod db;

#[cfg(target_arch = "wasm32")]
pub use db::{Batch, CursorDirection, Storage};

#[cfg(not(target_arch = "wasm32"))]
pub use db::{Batch, Storage};

use crate::{
    protocols::{Peers, PendingTxs},
    types::RwLock,
};

pub const LAST_STATE_KEY: &str = "LAST_STATE";
const GENESIS_BLOCK_KEY: &str = "GENESIS_BLOCK";
const FILTER_SCRIPTS_KEY: &str = "FILTER_SCRIPTS";
const MATCHED_FILTER_BLOCKS_KEY: &str = "MATCHED_BLOCKS";
const MIN_FILTERED_BLOCK_NUMBER: &str = "MIN_FILTERED_NUMBER";
const LAST_N_HEADERS_KEY: &str = "LAST_N_HEADERS";
const MAX_CHECK_POINT_INDEX: &str = "MAX_CHECK_POINT_INDEX";

pub struct HeaderWithExtension {
    pub header: Header,
    pub extension: Option<packed::Bytes>,
}

impl HeaderWithExtension {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = self.header.as_slice().to_vec();
        if let Some(extension) = self.extension.as_ref() {
            vec.extend_from_slice(extension.as_slice());
        }
        vec
    }
}

pub struct ScriptStatus {
    pub script: Script,
    pub script_type: ScriptType,
    pub block_number: BlockNumber,
}

pub enum SetScriptsCommand {
    All,
    Partial,
    Delete,
}

impl Default for SetScriptsCommand {
    fn default() -> Self {
        Self::All
    }
}

#[derive(PartialEq, Eq, Hash)]
pub enum ScriptType {
    Lock,
    Type,
}

struct WrappedBlockView<'a> {
    inner: &'a BlockView,
    index: HashMap<Byte32, usize>,
}

impl<'a> WrappedBlockView<'a> {
    fn new(inner: &'a BlockView) -> Self {
        let index = inner
            .transactions()
            .into_iter()
            .enumerate()
            .map(|(index, tx)| (tx.hash(), index))
            .collect();
        Self { inner, index }
    }
}

impl FilterDataProvider for WrappedBlockView<'_> {
    fn cell(&self, out_point: &OutPoint) -> Option<CellOutput> {
        self.index.get(&out_point.tx_hash()).and_then(|tx_index| {
            self.inner
                .transactions()
                .get(*tx_index)
                .and_then(|tx| tx.outputs().get(out_point.index().unpack()))
        })
    }
}

#[derive(Clone)]
pub struct StorageWithChainData {
    pub(crate) storage: Storage,
    pub(crate) peers: Arc<Peers>,
    pending_txs: Arc<RwLock<PendingTxs>>,
}

impl StorageWithChainData {
    pub fn new(storage: Storage, peers: Arc<Peers>, pending_txs: Arc<RwLock<PendingTxs>>) -> Self {
        Self {
            storage,
            peers,
            pending_txs,
        }
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn peers(&self) -> &Arc<Peers> {
        &self.peers
    }

    pub fn pending_txs(&self) -> &RwLock<PendingTxs> {
        &self.pending_txs
    }

    pub fn matched_blocks(&self) -> &RwLock<HashMap<H256, (bool, Option<packed::Block>)>> {
        self.peers.matched_blocks()
    }
    /// return (added_ts, first_sent, missing)
    pub fn get_header_fetch_info(&self, block_hash: &H256) -> Option<(u64, u64, bool)> {
        self.peers.get_header_fetch_info(&block_hash.pack())
    }
    /// return (added_ts, first_sent, missing)
    pub fn get_tx_fetch_info(&self, tx_hash: &H256) -> Option<(u64, u64, bool)> {
        self.peers.get_tx_fetch_info(&tx_hash.pack())
    }
    pub fn add_fetch_header(&self, header_hash: H256, timestamp: u64) {
        self.peers.add_fetch_header(header_hash.pack(), timestamp);
    }
    pub fn add_fetch_tx(&self, tx_hash: H256, timestamp: u64) {
        self.peers.add_fetch_tx(tx_hash.pack(), timestamp);
    }
}
#[cfg(target_arch = "wasm32")]
impl CellProvider for StorageWithChainData {
    fn cell(&self, out_point: &OutPoint, eager_load: bool) -> CellStatus {
        match self.storage.cell(out_point, eager_load) {
            CellStatus::Live(cell_meta) => CellStatus::Live(cell_meta),
            _ => {
                // Safe to call blocking_read() here, CellProvider::cell will only be called from sync APIs
                if let Some((tx, _, _)) = self.pending_txs.blocking_read().get(&out_point.tx_hash())
                {
                    if let Some(cell_output) = tx.raw().outputs().get(out_point.index().unpack()) {
                        let output_data = tx
                            .raw()
                            .outputs_data()
                            .get(out_point.index().unpack())
                            .expect("output_data's index should be same as output")
                            .raw_data();
                        let output_data_data_hash = CellOutput::calc_data_hash(&output_data);
                        return CellStatus::Live(CellMeta {
                            out_point: out_point.clone(),
                            cell_output,
                            transaction_info: None,
                            data_bytes: output_data.len() as u64,
                            mem_cell_data: Some(output_data),
                            mem_cell_data_hash: Some(output_data_data_hash),
                        });
                    }
                }
                CellStatus::Unknown
            }
        }
    }
}
#[cfg(target_arch = "wasm32")]
impl CellDataProvider for StorageWithChainData {
    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<Bytes> {
        unreachable!()
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        unreachable!()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl CellDataProvider for StorageWithChainData {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        self.storage.get_cell_data(out_point)
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.storage.get_cell_data_hash(out_point)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl CellProvider for StorageWithChainData {
    fn cell(&self, out_point: &OutPoint, eager_load: bool) -> CellStatus {
        match self.storage.cell(out_point, eager_load) {
            CellStatus::Live(cell_meta) => CellStatus::Live(cell_meta),
            _ => {
                if let Some((tx, _, _)) = self
                    .pending_txs
                    .read()
                    .expect("poisoned")
                    .get(&out_point.tx_hash())
                {
                    if let Some(cell_output) = tx.raw().outputs().get(out_point.index().unpack()) {
                        let output_data = tx
                            .raw()
                            .outputs_data()
                            .get(out_point.index().unpack())
                            .expect("output_data's index should be same as output")
                            .raw_data();
                        let output_data_data_hash = CellOutput::calc_data_hash(&output_data);
                        return CellStatus::Live(CellMeta {
                            out_point: out_point.clone(),
                            cell_output,
                            transaction_info: None,
                            data_bytes: output_data.len() as u64,
                            mem_cell_data: Some(output_data),
                            mem_cell_data_hash: Some(output_data_data_hash),
                        });
                    }
                }
                CellStatus::Unknown
            }
        }
    }
}

impl HeaderProvider for StorageWithChainData {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        self.storage
            .get_header(hash)
            .or_else(|| self.peers.find_header_in_proved_state(hash))
    }
}

impl ExtensionProvider for StorageWithChainData {
    fn get_block_extension(&self, hash: &Byte32) -> Option<packed::Bytes> {
        self.storage
            .get(Key::BlockHash(hash).into_vec())
            .map(|v| {
                v.map(|v| {
                    if v.len() > Header::TOTAL_SIZE {
                        Some(
                            packed::Bytes::from_slice(&v[Header::TOTAL_SIZE..])
                                .expect("stored block extension"),
                        )
                    } else {
                        None
                    }
                })
            })
            .expect("db get should be ok")
            .flatten()
    }
}

impl HeaderFieldsProvider for StorageWithChainData {
    fn get_header_fields(&self, hash: &Byte32) -> Option<HeaderFields> {
        self.get_header(hash).map(|header| HeaderFields {
            hash: header.hash(),
            number: header.number(),
            epoch: header.epoch(),
            timestamp: header.timestamp(),
            parent_hash: header.parent_hash(),
        })
    }
}

pub type TxIndex = u32;
pub type CpIndex = u32;
pub type OutputIndex = u32;
pub type CellIndex = u32;
pub enum CellType {
    Input,
    Output,
}

///
/// +--------------+--------------------+--------------------------+
/// | KeyPrefix::  | Key::              | Value::                  |
/// +--------------+--------------------+--------------------------+
/// | 0            | TxHash             | Transaction              |
/// | 32           | CellLockScript     | TxHash                   |
/// | 64           | CellTypeScript     | TxHash                   |
/// | 96           | TxLockScript       | TxHash                   |
/// | 128          | TxTypeScript       | TxHash                   |
/// | 160          | BlockHash          | HeaderWithExtension      |
/// | 192          | BlockNumber        | BlockHash                |
/// | 208          | CheckPointIndex    | BlockFilterHash          |
/// | 224          | Meta               | Meta                     |
/// +--------------+--------------------+--------------------------+
///
pub enum Key<'a> {
    TxHash(&'a Byte32),
    CellLockScript(&'a Script, BlockNumber, TxIndex, OutputIndex),
    CellTypeScript(&'a Script, BlockNumber, TxIndex, OutputIndex),
    TxLockScript(&'a Script, BlockNumber, TxIndex, CellIndex, CellType),
    TxTypeScript(&'a Script, BlockNumber, TxIndex, CellIndex, CellType),
    BlockHash(&'a Byte32),
    BlockNumber(BlockNumber),
    // The index number for check points.
    CheckPointIndex(CpIndex),
    Meta(&'a str),
}

pub enum Value<'a> {
    Transaction(BlockNumber, TxIndex, &'a Transaction),
    TxHash(&'a Byte32),
    HeaderWithExtension(&'a HeaderWithExtension),
    BlockHash(&'a Byte32),
    BlockFilterHash(&'a Byte32),
    Meta(Vec<u8>),
}

#[repr(u8)]
pub enum KeyPrefix {
    TxHash = 0,
    CellLockScript = 32,
    CellTypeScript = 64,
    TxLockScript = 96,
    TxTypeScript = 128,
    BlockHash = 160,
    BlockNumber = 192,
    CheckPointIndex = 208,
    Meta = 224,
}

impl Key<'_> {
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl<'a> From<Key<'a>> for Vec<u8> {
    fn from(key: Key<'a>) -> Vec<u8> {
        let mut encoded = Vec::new();

        match key {
            Key::TxHash(tx_hash) => {
                encoded.push(KeyPrefix::TxHash as u8);
                encoded.extend_from_slice(tx_hash.as_slice());
            }
            Key::CellLockScript(script, block_number, tx_index, output_index) => {
                encoded.push(KeyPrefix::CellLockScript as u8);
                append_key(&mut encoded, script, block_number, tx_index, output_index);
            }
            Key::CellTypeScript(script, block_number, tx_index, output_index) => {
                encoded.push(KeyPrefix::CellTypeScript as u8);
                append_key(&mut encoded, script, block_number, tx_index, output_index);
            }
            Key::TxLockScript(script, block_number, tx_index, io_index, io_type) => {
                encoded.push(KeyPrefix::TxLockScript as u8);
                append_key(&mut encoded, script, block_number, tx_index, io_index);
                match io_type {
                    CellType::Input => encoded.push(0),
                    CellType::Output => encoded.push(1),
                }
            }
            Key::TxTypeScript(script, block_number, tx_index, io_index, io_type) => {
                encoded.push(KeyPrefix::TxTypeScript as u8);
                append_key(&mut encoded, script, block_number, tx_index, io_index);
                match io_type {
                    CellType::Input => encoded.push(0),
                    CellType::Output => encoded.push(1),
                }
            }
            Key::BlockHash(block_hash) => {
                encoded.push(KeyPrefix::BlockHash as u8);
                encoded.extend_from_slice(block_hash.as_slice());
            }
            Key::BlockNumber(block_number) => {
                encoded.push(KeyPrefix::BlockNumber as u8);
                encoded.extend_from_slice(&block_number.to_be_bytes());
            }
            Key::CheckPointIndex(index) => {
                encoded.push(KeyPrefix::CheckPointIndex as u8);
                encoded.extend_from_slice(&index.to_be_bytes());
            }
            Key::Meta(meta_key) => {
                encoded.push(KeyPrefix::Meta as u8);
                encoded.extend_from_slice(meta_key.as_bytes());
            }
        }
        encoded
    }
}

impl<'a> From<Value<'a>> for Vec<u8> {
    fn from(value: Value<'a>) -> Vec<u8> {
        match value {
            Value::Transaction(block_number, tx_index, transaction) => {
                let mut encoded = Vec::new();
                encoded.extend_from_slice(&block_number.to_be_bytes());
                encoded.extend_from_slice(&tx_index.to_be_bytes());
                encoded.extend_from_slice(transaction.as_slice());
                encoded
            }
            Value::TxHash(tx_hash) => tx_hash.as_slice().into(),
            Value::HeaderWithExtension(hwe) => hwe.to_vec(),
            Value::BlockHash(block_hash) => block_hash.as_slice().into(),
            Value::BlockFilterHash(block_filter_hash) => block_filter_hash.as_slice().into(),
            Value::Meta(meta_value) => meta_value,
        }
    }
}

fn append_key(
    encoded: &mut Vec<u8>,
    script: &Script,
    block_number: u64,
    tx_index: u32,
    io_index: u32,
) {
    encoded.extend_from_slice(&extract_raw_data(script));
    encoded.extend_from_slice(&block_number.to_be_bytes());
    encoded.extend_from_slice(&tx_index.to_be_bytes());
    encoded.extend_from_slice(&io_index.to_be_bytes());
}

fn parse_matched_blocks(data: &[u8]) -> (u64, Vec<(Byte32, bool)>) {
    let mut u64_bytes = [0u8; 8];
    u64_bytes.copy_from_slice(&data[0..8]);
    let blocks_count = u64::from_le_bytes(u64_bytes);
    assert!((data.len() - 8) % 33 == 0);
    let matched_len = (data.len() - 8) / 33;
    let matched_blocks = (0..matched_len)
        .map(|i| {
            let offset = 8 + i * 33;
            let part = &data[offset..offset + 32];
            let hash = packed::Byte32Reader::from_slice_should_be_ok(part).to_entity();
            let proved = data[offset + 32] == 1;
            (hash, proved)
        })
        .collect::<Vec<_>>();
    (blocks_count, matched_blocks)
}

// a helper fn extracts script fields raw data
pub fn extract_raw_data(script: &Script) -> Vec<u8> {
    [
        script.code_hash().as_slice(),
        script.hash_type().as_slice(),
        &script.args().raw_data(),
    ]
    .concat()
}
