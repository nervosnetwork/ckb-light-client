use std::{collections::HashMap, path::Path, sync::Arc};

use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        BlockNumber, HeaderView, TransactionInfo, TransactionView,
    },
    packed::{self, Block, Byte32, CellOutput, Header, OutPoint, Script, Transaction},
    prelude::*,
    H256, U256,
};

use dashmap::DashMap;
use rocksdb::{prelude::*, Direction, IteratorMode, WriteBatch, DB};

use crate::error::Result;
use crate::protocols::Peers;

const LAST_STATE_KEY: &str = "LAST_STATE";
const GENESIS_BLOCK_KEY: &str = "GENESIS_BLOCK";
const FILTER_SCRIPTS_KEY: &str = "FILTER_SCRIPTS";

#[derive(Clone)]
pub struct Storage {
    pub(crate) db: Arc<DB>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let db = Arc::new(DB::open_default(path).expect("Failed to open rocksdb"));
        Self { db }
    }

    fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key.as_ref())
            .map(|v| v.map(|vi| vi.to_vec()))
            .map_err(Into::into)
    }

    // fn exists<K: AsRef<[u8]>>(&self, key: K) -> Result<bool> {
    //     self.db
    //         .get(key.as_ref())
    //         .map(|v| v.is_some())
    //         .map_err(Into::into)
    // }

    fn batch(&self) -> Batch {
        Batch {
            db: Arc::clone(&self.db),
            wb: WriteBatch::default(),
        }
    }

    pub fn init_genesis_block(&self, block: Block) {
        let genesis_hash = block.calc_header_hash();
        let genesis_block_key = Key::Meta(GENESIS_BLOCK_KEY).into_vec();
        if let Some(stored_genesis_hash) = self
            .get(genesis_block_key.as_slice())
            .expect("get genesis block")
            .map(|v| v[0..32].to_vec())
        {
            if genesis_hash.as_slice() != stored_genesis_hash.as_slice() {
                panic!(
                    "genesis hash mismatch: stored={:#?}, new={}",
                    stored_genesis_hash, genesis_hash
                );
            }
        } else {
            let mut batch = self.batch();
            let block_hash = block.calc_header_hash();
            batch
                .put_kv(Key::Meta(LAST_STATE_KEY), block.header().as_slice())
                .expect("batch put should be ok");
            batch
                .put_kv(Key::BlockHash(&block_hash), block.header().as_slice())
                .expect("batch put should be ok");
            batch
                .put_kv(Key::BlockNumber(0), block_hash.as_slice())
                .expect("batch put should be ok");
            let mut genesis_hash_and_txs_hash = genesis_hash.as_slice().to_vec();
            block
                .transactions()
                .into_iter()
                .enumerate()
                .for_each(|(tx_index, tx)| {
                    let tx_hash = tx.calc_tx_hash();
                    genesis_hash_and_txs_hash.extend_from_slice(tx_hash.as_slice());
                    let key = Key::TxHash(&tx_hash).into_vec();
                    let value = Value::Transaction(0, tx_index as TxIndex, &tx);
                    batch.put_kv(key, value).expect("batch put should be ok");
                });
            batch
                .put_kv(genesis_block_key, genesis_hash_and_txs_hash.as_slice())
                .expect("batch put should be ok");
            batch.commit().expect("batch commit should be ok");
            self.update_last_state(&U256::zero(), &block.header());
        }
    }

    fn get_genesis_block(&self) -> Block {
        let genesis_hash_and_txs_hash = self
            .get(Key::Meta(GENESIS_BLOCK_KEY).into_vec())
            .expect("get genesis block")
            .expect("inited storage");
        let genesis_hash = Byte32::from_slice(&genesis_hash_and_txs_hash[0..32])
            .expect("stored genesis block hash");
        let genesis_header = Header::from_slice(
            &self
                .get(Key::BlockHash(&genesis_hash).into_vec())
                .expect("db get should be ok")
                .expect("stored block hash / header mapping"),
        )
        .expect("stored header should be OK");

        let transactions: Vec<Transaction> = genesis_hash_and_txs_hash[32..]
            .chunks_exact(32)
            .map(|tx_hash| {
                Transaction::from_slice(
                    &self
                        .get(
                            Key::TxHash(
                                &Byte32::from_slice(tx_hash).expect("stored genesis block tx hash"),
                            )
                            .into_vec(),
                        )
                        .expect("db get should be ok")
                        .expect("stored genesis block tx")[12..],
                )
                .expect("stored Transaction")
            })
            .collect();

        Block::new_builder()
            .header(genesis_header)
            .transactions(transactions.pack())
            .build()
    }

    pub fn get_filter_scripts(&self) -> HashMap<Script, BlockNumber> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .map(|(key, value)| {
                let script = Script::from_slice(&key[key_prefix.len()..]).expect("stored Script");
                let block_number = BlockNumber::from_be_bytes(
                    value.as_ref().try_into().expect("stored BlockNumber"),
                );
                (script, block_number)
            })
            .collect()
    }

    /// Update all filter scripts' status to the specified block number and delete the outdated ones.
    pub fn update_filter_scripts(&self, scripts: HashMap<Script, BlockNumber>) {
        let should_filter_genesis_block =
            scripts.iter().any(|(_, block_number)| *block_number == 0);
        let mut batch = self.batch();

        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .for_each(|(key, _value)| {
                batch.delete(key).expect("batch delete should be ok");
            });

        for (script, block_number) in scripts {
            let key = [key_prefix.as_ref(), script.as_slice()].concat();
            batch
                .put(key, block_number.to_be_bytes())
                .expect("batch put should be ok");
        }
        batch.commit().expect("batch commit should be ok");

        if should_filter_genesis_block {
            let block = self.get_genesis_block();
            self.filter_block(block);
        }
    }

    // get scripts hash that should be filtered below the given block number
    pub fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .filter_map(|(key, value)| {
                let stored_block_number = BlockNumber::from_be_bytes(
                    value.as_ref().try_into().expect("stored BlockNumber"),
                );
                if stored_block_number < block_number {
                    let script =
                        Script::from_slice(&key[key_prefix.len()..]).expect("stored Script");
                    Some(script.calc_script_hash())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn update_last_state(&self, total_difficulty: &U256, tip_header: &Header) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let mut value = total_difficulty.to_le_bytes().to_vec();
        value.extend(tip_header.as_slice());
        self.db
            .put(key, &value)
            .expect("db put last state should be ok");
    }

    pub fn get_last_state(&self) -> (U256, Header) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        self.db
            .get_pinned(&key)
            .expect("db get last state should be ok")
            .map(|data| {
                let mut total_difficulty_bytes = [0u8; 32];
                total_difficulty_bytes.copy_from_slice(&data[0..32]);
                let total_difficulty = U256::from_le_bytes(&total_difficulty_bytes);
                let header = packed::HeaderReader::from_slice_should_be_ok(&data[32..]).to_entity();
                (total_difficulty, header)
            })
            .expect("tip header should be inited")
    }

    pub fn get_tip_header(&self) -> Header {
        self.get_last_state().1
    }

    pub fn update_block_number(&self, block_number: BlockNumber) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        let mut batch = self.batch();
        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .for_each(|(key, value)| {
                let stored_block_number = BlockNumber::from_be_bytes(
                    value.as_ref().try_into().expect("stored BlockNumber"),
                );
                if stored_block_number < block_number {
                    batch
                        .put(key, block_number.to_be_bytes())
                        .expect("batch put should be ok")
                }
            });
        batch.commit().expect("batch commit should be ok");
    }

    pub fn filter_block(&self, block: Block) {
        let scripts = self.get_filter_scripts();
        let block_number: BlockNumber = block.header().raw().number().unpack();
        let mut filter_matched = false;
        let mut batch = self.batch();
        block
            .transactions()
            .into_iter()
            .enumerate()
            .for_each(|(tx_index, tx)| {
                tx.raw()
                    .inputs()
                    .into_iter()
                    .enumerate()
                    .for_each(|(input_index, input)| {
                        if let Some((
                            generated_by_block_number,
                            generated_by_tx_index,
                            previous_tx,
                        )) = self.get_transaction(&input.previous_output().tx_hash())
                        {
                            let previous_output_index = input.previous_output().index().unpack();
                            if let Some(previous_output) =
                                previous_tx.raw().outputs().get(previous_output_index)
                            {
                                let script = previous_output.lock();
                                if scripts.contains_key(&script) {
                                    filter_matched = true;
                                    // delete utxo
                                    let key = Key::CellLockScript(
                                        &script,
                                        generated_by_block_number,
                                        generated_by_tx_index,
                                        previous_output_index as OutputIndex,
                                    )
                                    .into_vec();
                                    batch.delete(key).expect("batch delete should be ok");
                                    // insert tx history
                                    let key = Key::TxLockScript(
                                        &script,
                                        block_number,
                                        tx_index as TxIndex,
                                        input_index as CellIndex,
                                        CellType::Input,
                                    )
                                    .into_vec();
                                    let tx_hash = tx.calc_tx_hash();
                                    batch
                                        .put(key, tx_hash.as_slice())
                                        .expect("batch put should be ok");
                                    // insert tx
                                    let key = Key::TxHash(&tx_hash).into_vec();
                                    let value =
                                        Value::Transaction(block_number, tx_index as TxIndex, &tx);
                                    batch.put_kv(key, value).expect("batch put should be ok");
                                }
                            }
                        }
                    });

                tx.raw()
                    .outputs()
                    .into_iter()
                    .enumerate()
                    .for_each(|(output_index, output)| {
                        let script = output.lock();
                        if scripts.contains_key(&script) {
                            filter_matched = true;
                            let tx_hash = tx.calc_tx_hash();
                            // insert utxo
                            let key = Key::CellLockScript(
                                &script,
                                block_number,
                                tx_index as TxIndex,
                                output_index as OutputIndex,
                            )
                            .into_vec();
                            batch
                                .put(key, tx_hash.as_slice())
                                .expect("batch put should be ok");
                            // insert tx history
                            let key = Key::TxLockScript(
                                &script,
                                block_number,
                                tx_index as TxIndex,
                                output_index as CellIndex,
                                CellType::Output,
                            )
                            .into_vec();
                            batch
                                .put(key, tx_hash.as_slice())
                                .expect("batch put should be ok");
                            // insert tx
                            let key = Key::TxHash(&tx_hash).into_vec();
                            let value = Value::Transaction(block_number, tx_index as TxIndex, &tx);
                            batch.put_kv(key, value).expect("batch put should be ok");
                        }
                    });
            });
        if filter_matched {
            let block_hash = block.calc_header_hash();
            batch
                .put(
                    Key::BlockHash(&block_hash).into_vec(),
                    block.header().as_slice(),
                )
                .expect("batch put should be ok");
            batch
                .put(
                    Key::BlockNumber(block.header().raw().number().unpack()).into_vec(),
                    block_hash.as_slice(),
                )
                .expect("batch put should be ok");
        }
        batch.commit().expect("batch commit should be ok");
    }

    /// Rollback filtered block data to specified block number
    pub fn rollback_to_block(&self, to_number: BlockNumber) {
        let scripts = self.get_filter_scripts();
        let mut batch = self.batch();

        for (script, filtered_block_number) in scripts {
            if filtered_block_number >= to_number {
                let mut key_prefix = vec![KeyPrefix::TxLockScript as u8];
                key_prefix.extend_from_slice(&extract_raw_data(&script));
                let mut start_key = key_prefix.clone();
                start_key.extend_from_slice(BlockNumber::MAX.to_be_bytes().as_ref());
                let mode = IteratorMode::From(start_key.as_ref(), Direction::Reverse);
                let key_prefix_len = key_prefix.len();

                self.db
                    .iterator(mode)
                    .take_while(|(key, _value)| {
                        key.starts_with(&key_prefix)
                            && BlockNumber::from_be_bytes(
                                key[key_prefix_len..key_prefix_len + 8]
                                    .try_into()
                                    .expect("stored BlockNumber"),
                            ) >= to_number
                    })
                    .for_each(|(key, value)| {
                        let block_number = BlockNumber::from_be_bytes(
                            key[key_prefix_len..key_prefix_len + 8]
                                .try_into()
                                .expect("stored BlockNumber"),
                        );
                        let tx_index = TxIndex::from_be_bytes(
                            key[key_prefix_len + 8..key_prefix_len + 12]
                                .try_into()
                                .expect("stored TxIndex"),
                        );
                        let cell_index = CellIndex::from_be_bytes(
                            key[key_prefix_len + 12..key_prefix_len + 16]
                                .try_into()
                                .expect("stored CellIndex"),
                        );
                        let tx_hash =
                            packed::Byte32Reader::from_slice_should_be_ok(&value).to_entity();
                        if key[key_prefix_len + 16] == 0 {
                            let (_, _, tx) = self
                                .get_transaction(&tx_hash)
                                .expect("stored transaction history");
                            let input = tx.raw().inputs().get(cell_index as usize).unwrap();
                            if let Some((
                                generated_by_block_number,
                                generated_by_tx_index,
                                _previous_tx,
                            )) = self.get_transaction(&input.previous_output().tx_hash())
                            {
                                let key = Key::CellLockScript(
                                    &script,
                                    generated_by_block_number,
                                    generated_by_tx_index,
                                    input.previous_output().index().unpack(),
                                );
                                batch
                                    .put_kv(key, input.previous_output().tx_hash().as_slice())
                                    .expect("batch put should be ok");
                            };
                            // delete tx history
                            let key = Key::TxLockScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Input,
                            )
                            .into_vec();
                            batch.delete(key).expect("batch delete should be ok");
                        } else {
                            // delete utxo
                            let key =
                                Key::CellLockScript(&script, block_number, tx_index, cell_index)
                                    .into_vec();
                            batch.delete(key).expect("batch delete should be ok");

                            // delete tx history
                            let key = Key::TxLockScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Output,
                            )
                            .into_vec();
                            batch.delete(key).expect("batch delete should be ok");
                        };
                    });

                // update script filter block number
                {
                    let mut key = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
                    key.extend_from_slice(script.as_slice());
                    let value = to_number.to_be_bytes().to_vec();
                    batch.put(key, value).expect("batch put should be ok");
                }
            }
        }

        batch.commit().expect("batch commit should be ok");
    }

    fn get_transaction(&self, tx_hash: &Byte32) -> Option<(BlockNumber, TxIndex, Transaction)> {
        self.get(Key::TxHash(tx_hash).into_vec())
            .map(|v| {
                v.map(|v| {
                    (
                        BlockNumber::from_be_bytes(v[0..8].try_into().expect("stored BlockNumber")),
                        TxIndex::from_be_bytes(v[8..12].try_into().expect("stored TxIndex")),
                        Transaction::from_slice(&v[12..]).expect("stored Transaction"),
                    )
                })
            })
            .expect("db get should be ok")
    }

    pub fn get_transaction_with_header(&self, tx_hash: &Byte32) -> Option<(Transaction, Header)> {
        self.get_transaction(tx_hash)
            .map(|(block_number, _tx_index, tx)| {
                let block_hash = Byte32::from_slice(
                    &self
                        .get(Key::BlockNumber(block_number).into_vec())
                        .expect("db get should be ok")
                        .expect("stored block number / hash mapping"),
                )
                .expect("stored block hash should be OK");

                let header = Header::from_slice(
                    &self
                        .get(Key::BlockHash(&block_hash).into_vec())
                        .expect("db get should be ok")
                        .expect("stored block hash / header mapping"),
                )
                .expect("stored header should be OK");
                (tx, header)
            })
    }
}

impl CellProvider for Storage {
    // assume all cells are live and load data eagerly
    fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        if let Some((block_number, tx_index, tx)) = self.get_transaction(&out_point.tx_hash()) {
            let block_hash = Byte32::from_slice(
                &self
                    .get(Key::BlockNumber(block_number).into_vec())
                    .expect("db get should be ok")
                    .expect("stored block number / hash mapping"),
            )
            .expect("stored block hash should be OK");

            let header = Header::from_slice(
                &self
                    .get(Key::BlockHash(&block_hash).into_vec())
                    .expect("db get should be ok")
                    .expect("stored block hash / header mapping"),
            )
            .expect("stored header should be OK")
            .into_view();

            let output_index = out_point.index().unpack();
            let tx = tx.into_view();
            if let Some(cell_output) = tx.outputs().get(output_index) {
                let output_data = tx
                    .outputs_data()
                    .get(output_index)
                    .expect("output_data's index should be same as output")
                    .raw_data();
                let output_data_data_hash = CellOutput::calc_data_hash(&output_data);
                let cell_meta = CellMeta {
                    out_point: out_point.clone(),
                    cell_output,
                    transaction_info: Some(TransactionInfo {
                        block_hash,
                        block_epoch: header.epoch(),
                        block_number,
                        index: tx_index as usize,
                    }),
                    data_bytes: output_data.len() as u64,
                    mem_cell_data: Some(output_data),
                    mem_cell_data_hash: Some(output_data_data_hash),
                };
                return CellStatus::Live(cell_meta);
            }
        }
        CellStatus::Unknown
    }
}

impl CellDataProvider for Storage {
    // we load all cells data eagerly in Storage's CellProivder impl
    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<Bytes> {
        unreachable!()
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        unreachable!()
    }
}

impl HeaderProvider for Storage {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        self.get(Key::BlockHash(hash).into_vec())
            .map(|v| v.map(|v| Header::from_slice(&v).expect("stored Header").into_view()))
            .expect("db get should be ok")
    }
}

#[derive(Clone)]
pub struct StorageWithChainData {
    storage: Storage,
    peers: Arc<Peers>,
}

impl StorageWithChainData {
    pub fn new(storage: Storage, peers: Arc<Peers>) -> Self {
        Self { storage, peers }
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub(crate) fn fetching_headers(&self) -> &DashMap<H256, Option<(u64, bool)>> {
        self.peers.fetching_headers()
    }
    pub(crate) fn fetched_txs(&self) -> &DashMap<H256, (TransactionView, HeaderView)> {
        self.peers.fetched_txs()
    }
    pub(crate) fn fetching_txs(&self) -> &DashMap<H256, Option<(u64, bool)>> {
        self.peers.fetching_txs()
    }
}

impl HeaderProvider for StorageWithChainData {
    fn get_header(&self, hash: &packed::Byte32) -> Option<HeaderView> {
        self.storage
            .get_header(hash)
            .or_else(|| {
                self.peers
                    .last_headers()
                    .read()
                    .expect("poisoned")
                    .iter()
                    .find(|header| header.hash().eq(hash))
                    .cloned()
            })
            .or_else(|| {
                self.peers
                    .fetched_headers()
                    .get(&hash.unpack())
                    .map(|pair| pair.value().clone())
            })
    }
}

impl CellDataProvider for StorageWithChainData {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        self.storage.get_cell_data(out_point)
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.storage.get_cell_data_hash(out_point)
    }
}

impl CellProvider for StorageWithChainData {
    fn cell(&self, out_point: &OutPoint, eager_load: bool) -> CellStatus {
        self.storage.cell(out_point, eager_load)
    }
}

pub struct Batch {
    db: Arc<DB>,
    wb: WriteBatch,
}

impl Batch {
    fn put_kv<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) -> Result<()> {
        self.put(&Into::<Vec<u8>>::into(key), &Into::<Vec<u8>>::into(value))
    }

    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<()> {
        self.wb.put(key, value)?;
        Ok(())
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<()> {
        self.wb.delete(key.as_ref())?;
        Ok(())
    }

    fn commit(self) -> Result<()> {
        self.db.write(&self.wb)?;
        Ok(())
    }
}

pub type TxIndex = u32;
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
/// | 160          | BlockHash          | Header                   |
/// | 192          | BlockNumber        | BlockHash                |
/// | 224          | Meta               | Meta                |
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
    Meta(&'a str),
}

pub enum Value<'a> {
    Transaction(BlockNumber, TxIndex, &'a Transaction),
    TxHash(&'a Byte32),
    Header(&'a Header),
    BlockHash(&'a Byte32),
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
    Meta = 224,
}

impl<'a> Key<'a> {
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
            Value::Header(header) => header.as_slice().into(),
            Value::BlockHash(block_hash) => block_hash.as_slice().into(),
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

// a helper fn extracts script fields raw data
pub fn extract_raw_data(script: &Script) -> Vec<u8> {
    [
        script.code_hash().as_slice(),
        script.hash_type().as_slice(),
        &script.args().raw_data(),
    ]
    .concat()
}
