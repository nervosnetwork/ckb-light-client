use std::sync::RwLock;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use ckb_traits::{
    CellDataProvider, ExtensionProvider, HeaderFields, HeaderFieldsProvider, HeaderProvider,
};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        BlockNumber, BlockView, HeaderView, TransactionInfo,
    },
    packed::{self, Block, Byte32, CellOutput, Header, OutPoint, Script, Transaction},
    prelude::*,
    utilities::{build_filter_data, calc_filter_hash, FilterDataProvider},
    H256, U256,
};

use rocksdb::{prelude::*, Direction, IteratorMode, WriteBatch, DB};

use crate::error::Result;
use crate::protocols::Peers;

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

impl<'a> FilterDataProvider for WrappedBlockView<'a> {
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
            self.update_last_state(&U256::zero(), &block.header(), &[]);
            let genesis_block_filter_hash: Byte32 = {
                let block_view = block.into_view();
                let provider = WrappedBlockView::new(&block_view);
                let parent_block_filter_hash = Byte32::zero();
                let (genesis_block_filter_vec, missing_out_points) =
                    build_filter_data(provider, &block_view.transactions());
                if !missing_out_points.is_empty() {
                    panic!("Genesis block shouldn't missing any out points.");
                }
                let genesis_block_filter_data = genesis_block_filter_vec.pack();
                calc_filter_hash(&parent_block_filter_hash, &genesis_block_filter_data).pack()
            };
            self.update_max_check_point_index(0);
            self.update_check_points(0, &[genesis_block_filter_hash]);
            self.update_min_filtered_block_number(0);
        }
    }

    pub fn get_genesis_block(&self) -> Block {
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

    pub fn is_filter_scripts_empty(&self) -> bool {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);
        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .next()
            .is_none()
    }

    pub fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .map(|(key, value)| {
                let script = Script::from_slice(&key[key_prefix.len()..key.len() - 1])
                    .expect("stored Script");
                let script_type = match key[key.len() - 1] {
                    0 => ScriptType::Lock,
                    1 => ScriptType::Type,
                    _ => panic!("invalid script type"),
                };
                let block_number = BlockNumber::from_be_bytes(
                    value.as_ref().try_into().expect("stored BlockNumber"),
                );
                ScriptStatus {
                    script,
                    script_type,
                    block_number,
                }
            })
            .collect()
    }

    pub fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        let mut should_filter_genesis_block = false;
        let mut min_block_number = None;
        let mut batch = self.batch();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        match command {
            SetScriptsCommand::All => {
                should_filter_genesis_block = scripts.iter().any(|ss| ss.block_number == 0);
                let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

                self.db
                    .iterator(mode)
                    .take_while(|(key, _value)| key.starts_with(&key_prefix))
                    .for_each(|(key, _value)| {
                        batch.delete(key).expect("batch delete should be ok");
                    });

                for ss in scripts {
                    if min_block_number
                        .as_ref()
                        .map(|n| *n > ss.block_number)
                        .unwrap_or(true)
                    {
                        min_block_number = Some(ss.block_number);
                    }
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch
                        .put(key, ss.block_number.to_be_bytes())
                        .expect("batch put should be ok");
                }
            }
            SetScriptsCommand::Partial => {
                if scripts.is_empty() {
                    return;
                }
                let min_script_block_number = scripts.iter().map(|ss| ss.block_number).min();
                should_filter_genesis_block = min_script_block_number == Some(0);
                // min_block_number should be the min of all scripts' block_number when storage's filter_scripts is empty
                min_block_number = if self.is_filter_scripts_empty() {
                    min_script_block_number
                } else {
                    min_script_block_number.map(|n| n.min(self.get_min_filtered_block_number()))
                };

                for ss in scripts {
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch
                        .put(key, ss.block_number.to_be_bytes())
                        .expect("batch put should be ok");
                }
            }
            SetScriptsCommand::Delete => {
                if scripts.is_empty() {
                    return;
                }
                for ss in scripts {
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch.delete(key).expect("batch delete should be ok");
                }
            }
        }

        batch.commit().expect("batch commit should be ok");

        if let Some(min_number) = min_block_number {
            self.update_min_filtered_block_number(min_number);
        }
        self.clear_matched_blocks();

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
                    let script = Script::from_slice(&key[key_prefix.len()..key.len() - 1])
                        .expect("stored Script");
                    Some(script.calc_script_hash())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn update_last_state(
        &self,
        total_difficulty: &U256,
        tip_header: &Header,
        last_n_headers: &[HeaderView],
    ) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let mut value = total_difficulty.to_le_bytes().to_vec();
        value.extend(tip_header.as_slice());
        self.db
            .put(key, &value)
            .expect("db put last state should be ok");
        self.update_last_n_headers(last_n_headers);
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

    pub fn update_last_n_headers(&self, headers: &[HeaderView]) {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        let mut value: Vec<u8> = Vec::with_capacity(headers.len() * 40);
        for header in headers {
            value.extend(header.number().to_le_bytes());
            value.extend(header.hash().as_slice());
        }
        self.db
            .put(key, &value)
            .expect("db put last n headers should be ok");
    }
    pub fn get_last_n_headers(&self) -> Vec<(u64, Byte32)> {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        self.db
            .get_pinned(&key)
            .expect("db get last n headers should be ok")
            .map(|data| {
                assert!(data.len() % 40 == 0);
                let mut headers = Vec::with_capacity(data.len() / 40);
                for part in data.chunks(40) {
                    let number = u64::from_le_bytes(part[0..8].try_into().unwrap());
                    let hash = Byte32::from_slice(&part[8..]).expect("byte32 block hash");
                    headers.push((number, hash));
                }
                headers
            })
            .expect("last n headers should be inited")
    }

    /// 0 all blocks downloaded and inserted into storage call this function.
    pub fn remove_matched_blocks(&self, start_number: u64) {
        let mut key = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        key.extend(start_number.to_be_bytes());
        self.db.delete(&key).expect("delete matched blocks");
    }

    fn clear_matched_blocks(&self) {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);
        let mut batch = self.batch();
        for (key, _) in self
            .db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
        {
            batch.delete(key).expect("batch delete should be ok");
        }
        batch.commit().expect("batch commit should be ok");
    }

    /// the matched blocks must not empty
    pub fn add_matched_blocks(
        &self,
        start_number: u64,
        blocks_count: u64,
        // (block-hash, proved)
        matched_blocks: Vec<(Byte32, bool)>,
    ) {
        assert!(!matched_blocks.is_empty());
        let mut key = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        key.extend(start_number.to_be_bytes());

        let mut value = blocks_count.to_le_bytes().to_vec();
        for (block_hash, proved) in matched_blocks {
            value.extend(block_hash.as_slice());
            value.push(u8::from(proved));
        }
        self.db
            .put(key, &value)
            .expect("db put matched blocks should be ok");
    }

    #[allow(clippy::type_complexity)]
    fn get_matched_blocks(&self, direction: Direction) -> Option<(u64, u64, Vec<(Byte32, bool)>)> {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let iter_from = match direction {
            Direction::Forward => key_prefix.clone(),
            Direction::Reverse => {
                let mut key = key_prefix.clone();
                key.extend(u64::max_value().to_be_bytes());
                key
            }
        };
        let mode = IteratorMode::From(iter_from.as_ref(), direction);
        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .map(|(key, value)| {
                let mut u64_bytes = [0u8; 8];
                u64_bytes.copy_from_slice(&key[key_prefix.len()..]);
                let start_number = u64::from_be_bytes(u64_bytes);
                let (blocks_count, blocks) = parse_matched_blocks(&value);
                (start_number, blocks_count, blocks)
            })
            .next()
    }
    #[allow(clippy::type_complexity)]
    pub fn get_earliest_matched_blocks(&self) -> Option<(u64, u64, Vec<(Byte32, bool)>)> {
        self.get_matched_blocks(Direction::Forward)
    }
    #[allow(clippy::type_complexity)]
    pub fn get_latest_matched_blocks(&self) -> Option<(u64, u64, Vec<(Byte32, bool)>)> {
        self.get_matched_blocks(Direction::Reverse)
    }

    pub fn add_fetched_header(&self, hwe: &HeaderWithExtension) {
        let mut batch = self.batch();
        let block_hash = hwe.header.calc_header_hash();
        batch
            .put(Key::BlockHash(&block_hash).into_vec(), hwe.to_vec())
            .expect("batch put should be ok");
        batch
            .put(
                Key::BlockNumber(hwe.header.raw().number().unpack()).into_vec(),
                block_hash.as_slice(),
            )
            .expect("batch put should be ok");
        batch.commit().expect("batch commit should be ok");
    }

    pub fn add_fetched_tx(&self, tx: &Transaction, hwe: &HeaderWithExtension) {
        let mut batch = self.batch();
        let block_hash = hwe.header.calc_header_hash();
        let block_number: u64 = hwe.header.raw().number().unpack();
        batch
            .put(Key::BlockHash(&block_hash).into_vec(), hwe.to_vec())
            .expect("batch put should be ok");
        batch
            .put(
                Key::BlockNumber(block_number).into_vec(),
                block_hash.as_slice(),
            )
            .expect("batch put should be ok");
        let tx_hash = tx.calc_tx_hash();
        let tx_index = u32::max_value();
        let key = Key::TxHash(&tx_hash).into_vec();
        let value = Value::Transaction(block_number, tx_index as TxIndex, tx);
        batch.put_kv(key, value).expect("batch put should be ok");
        batch.commit().expect("batch commit should be ok");
    }

    pub fn get_tip_header(&self) -> Header {
        self.get_last_state().1
    }

    pub fn get_min_filtered_block_number(&self) -> BlockNumber {
        let key = Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec();
        self.db
            .get_pinned(&key)
            .expect("db get min filtered block number should be ok")
            .map(|data| u64::from_le_bytes(data.as_ref().try_into().unwrap()))
            .unwrap_or_default()
    }

    pub fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        let key = Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec();
        let value = block_number.to_le_bytes();
        self.db
            .put(key, value)
            .expect("db put min filtered block number should be ok");
    }

    pub fn get_last_check_point(&self) -> (CpIndex, Byte32) {
        let index = self.get_max_check_point_index();
        let hash = self
            .get_check_points(index, 1)
            .get(0)
            .cloned()
            .expect("db get last check point should be ok");
        (index, hash)
    }

    pub fn get_max_check_point_index(&self) -> CpIndex {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        self.db
            .get_pinned(&key)
            .expect("db get max check point index should be ok")
            .map(|data| CpIndex::from_be_bytes(data.as_ref().try_into().unwrap()))
            .expect("db get max check point index should be ok")
    }

    pub fn update_max_check_point_index(&self, index: CpIndex) {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        let value = index.to_be_bytes();
        self.db
            .put(key, value)
            .expect("db put max check point index should be ok");
    }

    pub fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        let start_key = Key::CheckPointIndex(start_index).into_vec();
        let key_prefix = [KeyPrefix::CheckPointIndex as u8];
        let mode = IteratorMode::From(start_key.as_ref(), Direction::Forward);
        self.db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .take(limit)
            .map(|(_key, value)| Byte32::from_slice(&value).expect("stored block filter hash"))
            .collect()
    }

    pub fn update_check_points(&self, start_index: CpIndex, check_points: &[Byte32]) {
        let mut index = start_index;
        let mut batch = self.batch();
        for cp in check_points {
            let key = Key::CheckPointIndex(index).into_vec();
            let value = Value::BlockFilterHash(cp);
            batch.put_kv(key, value).expect("batch put should be ok");
            index += 1;
        }
        batch.commit().expect("batch commit should be ok");
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
        let scripts: HashSet<(Script, ScriptType)> = self
            .get_filter_scripts()
            .into_iter()
            .map(|ss| (ss.script, ss.script_type))
            .collect();
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
                                if scripts.contains(&(script.clone(), ScriptType::Lock)) {
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
                                if let Some(script) = previous_output.type_().to_opt() {
                                    if scripts.contains(&(script.clone(), ScriptType::Type)) {
                                        filter_matched = true;
                                        // delete utxo
                                        let key = Key::CellTypeScript(
                                            &script,
                                            generated_by_block_number,
                                            generated_by_tx_index,
                                            previous_output_index as OutputIndex,
                                        )
                                        .into_vec();
                                        batch.delete(key).expect("batch delete should be ok");
                                        // insert tx history
                                        let key = Key::TxTypeScript(
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
                                        let value = Value::Transaction(
                                            block_number,
                                            tx_index as TxIndex,
                                            &tx,
                                        );
                                        batch.put_kv(key, value).expect("batch put should be ok");
                                    }
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
                        if scripts.contains(&(script.clone(), ScriptType::Lock)) {
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
                        if let Some(script) = output.type_().to_opt() {
                            if scripts.contains(&(script.clone(), ScriptType::Type)) {
                                filter_matched = true;
                                let tx_hash = tx.calc_tx_hash();
                                // insert utxo
                                let key = Key::CellTypeScript(
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
                                let key = Key::TxTypeScript(
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
                                let value =
                                    Value::Transaction(block_number, tx_index as TxIndex, &tx);
                                batch.put_kv(key, value).expect("batch put should be ok");
                            }
                        }
                    });
            });
        if filter_matched {
            let block_hash = block.calc_header_hash();
            let hwe = HeaderWithExtension {
                header: block.header(),
                extension: block.extension(),
            };
            batch
                .put(Key::BlockHash(&block_hash).into_vec(), hwe.to_vec())
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
    ///
    /// N.B. The specified block will be removed.
    pub fn rollback_to_block(&self, to_number: BlockNumber) {
        let scripts = self.get_filter_scripts();
        let mut batch = self.batch();

        for ss in scripts {
            if ss.block_number >= to_number {
                let script = ss.script;
                let mut key_prefix = vec![match ss.script_type {
                    ScriptType::Lock => KeyPrefix::TxLockScript as u8,
                    ScriptType::Type => KeyPrefix::TxTypeScript as u8,
                }];
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
                        log::debug!("rollback {}", block_number);
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
                                let key = match ss.script_type {
                                    ScriptType::Lock => Key::CellLockScript(
                                        &script,
                                        generated_by_block_number,
                                        generated_by_tx_index,
                                        input.previous_output().index().unpack(),
                                    ),
                                    ScriptType::Type => Key::CellTypeScript(
                                        &script,
                                        generated_by_block_number,
                                        generated_by_tx_index,
                                        input.previous_output().index().unpack(),
                                    ),
                                };
                                batch
                                    .put_kv(key, input.previous_output().tx_hash().as_slice())
                                    .expect("batch put should be ok");
                            };
                            // delete tx history
                            let key = match ss.script_type {
                                ScriptType::Lock => Key::TxLockScript(
                                    &script,
                                    block_number,
                                    tx_index,
                                    cell_index,
                                    CellType::Input,
                                ),
                                ScriptType::Type => Key::TxTypeScript(
                                    &script,
                                    block_number,
                                    tx_index,
                                    cell_index,
                                    CellType::Input,
                                ),
                            }
                            .into_vec();
                            batch.delete(key).expect("batch delete should be ok");
                        } else {
                            // delete utxo
                            let key = match ss.script_type {
                                ScriptType::Lock => {
                                    Key::CellLockScript(&script, block_number, tx_index, cell_index)
                                }
                                ScriptType::Type => {
                                    Key::CellTypeScript(&script, block_number, tx_index, cell_index)
                                }
                            }
                            .into_vec();
                            batch.delete(key).expect("batch delete should be ok");

                            // delete tx history
                            let key = match ss.script_type {
                                ScriptType::Lock => Key::TxLockScript(
                                    &script,
                                    block_number,
                                    tx_index,
                                    cell_index,
                                    CellType::Output,
                                ),
                                ScriptType::Type => Key::TxTypeScript(
                                    &script,
                                    block_number,
                                    tx_index,
                                    cell_index,
                                    CellType::Output,
                                ),
                            }
                            .into_vec();
                            batch.delete(key).expect("batch delete should be ok");
                        };
                    });

                // update script filter block number
                {
                    let mut key = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
                    key.extend_from_slice(script.as_slice());
                    key.extend_from_slice(match ss.script_type {
                        ScriptType::Lock => &[0],
                        ScriptType::Type => &[1],
                    });
                    let value = to_number.to_be_bytes().to_vec();
                    batch.put(key, value).expect("batch put should be ok");
                }
            }
        }

        // we should also sync block filters again
        if self.get_min_filtered_block_number() >= to_number {
            batch
                .put(
                    Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec(),
                    to_number.saturating_sub(1).to_le_bytes(),
                )
                .expect("batch put should be ok");
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
                        .expect("stored block hash / header mapping")[..Header::TOTAL_SIZE],
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
                    .expect("stored block hash / header mapping")[..Header::TOTAL_SIZE],
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
            .map(|v| {
                v.map(|v| {
                    Header::from_slice(&v[..Header::TOTAL_SIZE])
                        .expect("stored Header")
                        .into_view()
                })
            })
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

    pub(crate) fn matched_blocks(&self) -> &RwLock<HashMap<H256, (bool, Option<packed::Block>)>> {
        self.peers.matched_blocks()
    }
    /// return (added_ts, first_sent, missing)
    pub(crate) fn get_header_fetch_info(&self, block_hash: &H256) -> Option<(u64, u64, bool)> {
        self.peers.get_header_fetch_info(&block_hash.pack())
    }
    /// return (added_ts, first_sent, missing)
    pub(crate) fn get_tx_fetch_info(&self, tx_hash: &H256) -> Option<(u64, u64, bool)> {
        self.peers.get_tx_fetch_info(&tx_hash.pack())
    }
    pub(crate) fn add_fetch_header(&self, header_hash: H256, timestamp: u64) {
        self.peers.add_fetch_header(header_hash.pack(), timestamp);
    }
    pub(crate) fn add_fetch_tx(&self, tx_hash: H256, timestamp: u64) {
        self.peers.add_fetch_tx(tx_hash.pack(), timestamp);
    }
}

impl HeaderProvider for StorageWithChainData {
    fn get_header(&self, hash: &packed::Byte32) -> Option<HeaderView> {
        self.storage
            .get_header(hash)
            .or_else(|| self.peers.find_header_in_proved_state(hash))
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
