use super::super::{
    extract_raw_data, parse_matched_blocks, BlockNumber, Byte32, CellIndex, CellType, CpIndex,
    HeaderWithExtension, Key, KeyPrefix, OutputIndex, Script, ScriptStatus, ScriptType,
    SetScriptsCommand, TxIndex, Value, WrappedBlockView, FILTER_SCRIPTS_KEY, GENESIS_BLOCK_KEY,
    LAST_N_HEADERS_KEY, LAST_STATE_KEY, MATCHED_FILTER_BLOCKS_KEY, MAX_CHECK_POINT_INDEX,
    MIN_FILTERED_BLOCK_NUMBER,
};
use crate::error::Result;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        HeaderView, TransactionInfo,
    },
    packed::{self, Block, CellOutput, Header, OutPoint, Transaction},
    prelude::*,
    utilities::{build_filter_data, calc_filter_hash},
    U256,
};
use rocksdb::{
    ops::{Delete, GetPinned},
    prelude::{Get, Iterate, Open, Put, WriteOps},
    DBPinnableSlice, Direction, IteratorMode, Snapshot, WriteBatch, DB,
};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

pub struct PinnedSlice<'a> {
    inner: rocksdb::DBPinnableSlice<'a>,
}

impl<'a> From<DBPinnableSlice<'a>> for PinnedSlice<'a> {
    fn from(value: DBPinnableSlice<'a>) -> Self {
        PinnedSlice { inner: value }
    }
}

impl AsRef<[u8]> for PinnedSlice<'_> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
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

    fn batch(&self) -> Batch {
        Batch {
            db: Arc::clone(&self.db),
            wb: WriteBatch::default(),
        }
    }

    pub fn snapshot(&self) -> Snapshot<'_> {
        self.db.snapshot()
    }

    fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.db.put(key, value).map_err(Into::into)
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key.as_ref())
            .map(|v| v.map(|vi| vi.to_vec()))
            .map_err(Into::into)
    }

    fn get_pinned<K>(&self, key: K) -> Result<Option<PinnedSlice<'_>>>
    where
        K: AsRef<[u8]>,
    {
        self.db
            .get_pinned(key)
            .map_err(Into::into)
            .map(|a| a.map(Into::into))
    }

    fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        self.db.delete(key).map_err(Into::into)
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

        self.update_min_filtered_block_number_by_scripts();
        self.clear_matched_blocks();

        if should_filter_genesis_block {
            let block = self.get_genesis_block();
            self.filter_block(block);
        }
    }

    fn update_min_filtered_block_number_by_scripts(&self) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mode = IteratorMode::From(key_prefix.as_ref(), Direction::Forward);

        let min_block_number = self
            .db
            .iterator(mode)
            .take_while(|(key, _value)| key.starts_with(&key_prefix))
            .map(|(_key, value)| {
                BlockNumber::from_be_bytes(value.as_ref().try_into().expect("stored BlockNumber"))
            })
            .min();

        if let Some(n) = min_block_number {
            self.update_min_filtered_block_number(n);
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

    #[allow(clippy::type_complexity)]
    fn get_matched_blocks(&self, direction: Direction) -> Option<(u64, u64, Vec<(Byte32, bool)>)> {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let iter_from = match direction {
            Direction::Forward => key_prefix.clone(),
            Direction::Reverse => {
                let mut key = key_prefix.clone();
                key.extend(u64::MAX.to_be_bytes());
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
}

pub struct Batch {
    db: Arc<DB>,
    wb: WriteBatch,
}

impl Batch {
    fn put_kv<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) -> Result<()> {
        self.put(Into::<Vec<u8>>::into(key), Into::<Vec<u8>>::into(value))
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

impl Storage {
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

    pub fn update_last_state(
        &self,
        total_difficulty: &U256,
        tip_header: &Header,
        last_n_headers: &[HeaderView],
    ) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let mut value = total_difficulty.to_le_bytes().to_vec();
        value.extend(tip_header.as_slice());
        self.put(key, &value)
            .expect("db put last state should be ok");
        self.update_last_n_headers(last_n_headers);
    }

    pub fn get_last_state(&self) -> (U256, Header) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        self.get_pinned(&key)
            .expect("db get last state should be ok")
            .map(|data| {
                let mut total_difficulty_bytes = [0u8; 32];
                total_difficulty_bytes.copy_from_slice(&data.as_ref()[0..32]);
                let total_difficulty = U256::from_le_bytes(&total_difficulty_bytes);
                let header =
                    packed::HeaderReader::from_slice_should_be_ok(&data.as_ref()[32..]).to_entity();
                (total_difficulty, header)
            })
            .expect("tip header should be inited")
    }

    fn update_last_n_headers(&self, headers: &[HeaderView]) {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        let mut value: Vec<u8> = Vec::with_capacity(headers.len() * 40);
        for header in headers {
            value.extend(header.number().to_le_bytes());
            value.extend(header.hash().as_slice());
        }
        self.put(key, &value)
            .expect("db put last n headers should be ok");
    }

    pub fn get_last_n_headers(&self) -> Vec<(u64, Byte32)> {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        self.get_pinned(&key)
            .expect("db get last n headers should be ok")
            .map(|data| {
                assert!(data.as_ref().len() % 40 == 0);
                let mut headers = Vec::with_capacity(data.as_ref().len() / 40);
                for part in data.as_ref().chunks(40) {
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
        self.delete(&key).expect("delete matched blocks");
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
        self.put(key, &value)
            .expect("db put matched blocks should be ok");
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
        let tx_index = u32::MAX;
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
        self.get_pinned(&key)
            .expect("db get min filtered block number should be ok")
            .map(|data| u64::from_le_bytes(data.as_ref().try_into().unwrap()))
            .unwrap_or_default()
    }

    pub fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        let key = Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec();
        let value = block_number.to_le_bytes();
        self.put(key, value)
            .expect("db put min filtered block number should be ok");
    }

    pub fn get_last_check_point(&self) -> (CpIndex, Byte32) {
        let index = self.get_max_check_point_index();
        let hash = self
            .get_check_points(index, 1)
            .first()
            .cloned()
            .expect("db get last check point should be ok");
        (index, hash)
    }

    pub fn get_max_check_point_index(&self) -> CpIndex {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        self.get_pinned(&key)
            .expect("db get max check point index should be ok")
            .map(|data| CpIndex::from_be_bytes(data.as_ref().try_into().unwrap()))
            .expect("db get max check point index should be ok")
    }

    pub fn update_max_check_point_index(&self, index: CpIndex) {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        let value = index.to_be_bytes();
        self.put(key, value)
            .expect("db put max check point index should be ok");
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

    pub fn filter_block(&self, block: Block) {
        let scripts: HashSet<(Script, ScriptType)> = self
            .get_filter_scripts()
            .into_iter()
            .map(|ss| (ss.script, ss.script_type))
            .collect();
        let block_number: BlockNumber = block.header().raw().number().unpack();
        let mut filter_matched = false;
        let mut batch = self.batch();
        let mut txs: HashMap<Byte32, (u32, Transaction)> = HashMap::new();
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
                        let previous_tx_hash = input.previous_output().tx_hash();
                        if let Some((
                            generated_by_block_number,
                            generated_by_tx_index,
                            previous_tx,
                        )) = self.get_transaction(&previous_tx_hash).or(txs
                            .get(&previous_tx_hash)
                            .map(|(tx_index, tx)| (block_number, *tx_index, tx.clone())))
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

                txs.insert(tx.calc_tx_hash(), (tx_index as u32, tx));
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
