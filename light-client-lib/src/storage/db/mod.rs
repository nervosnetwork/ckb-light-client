#[cfg(all(not(target_arch = "wasm32"), feature = "rocksdb"))]
mod native_rocksdb;
#[cfg(all(not(target_arch = "wasm32"), feature = "rocksdb"))]
pub use native_rocksdb::{Batch, Storage};

#[cfg(all(not(target_arch = "wasm32"), feature = "rusqlite"))]
mod native_rusqlite;
#[cfg(all(not(target_arch = "wasm32"), feature = "rusqlite"))]
pub use native_rusqlite::{Batch, Storage};

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
pub use browser::{Batch, CursorDirection, Storage};


#[cfg(not(target_arch = "wasm32"))]
use ckb_traits::HeaderProvider;
use ckb_types::prelude::Reader;
use ckb_types::prelude::{Builder, FromSliceShouldBeOk};
use ckb_types::{
    core::{BlockNumber, HeaderView},
    packed::{self, Block, Byte32, Header, Script, Transaction},
    prelude::{IntoBlockView, Pack, PackVec, Unpack},
    utilities::{build_filter_data, calc_filter_hash},
};
use std::collections::{HashMap, HashSet};

use crate::storage::{
    CellIndex, CellType, CpIndex, HeaderWithExtension, Key, OutputIndex, ScriptType, TxIndex,
    Value, WrappedBlockView, GENESIS_BLOCK_KEY, LAST_N_HEADERS_KEY, LAST_STATE_KEY,
    MATCHED_FILTER_BLOCKS_KEY, MAX_CHECK_POINT_INDEX, MIN_FILTERED_BLOCK_NUMBER,
};
use ckb_types::prelude::Entity;
use ckb_types::U256;
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
                total_difficulty_bytes.copy_from_slice(&AsRef::<[u8]>::as_ref(&data)[0..32]);
                let total_difficulty = U256::from_le_bytes(&total_difficulty_bytes);
                let header = packed::HeaderReader::from_slice_should_be_ok(
                    &AsRef::<[u8]>::as_ref(&data)[32..],
                )
                .to_entity();
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
                assert!(AsRef::<[u8]>::as_ref(&data).len() % 40 == 0);
                let mut headers = Vec::with_capacity(&AsRef::<[u8]>::as_ref(&data).len() / 40);
                for part in AsRef::<[u8]>::as_ref(&data).chunks(40) {
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

    pub fn cleanup_invalid_matched_blocks(&self) {
        use ckb_types::prelude::Unpack;
        use log::warn;

        let tip_number: u64 = self.get_tip_header().raw().number().unpack();

        loop {
            let entry = self.get_earliest_matched_blocks();
            if entry.is_none() {
                break;
            }

            let matched_blocks = entry.unwrap();
            let start_number = matched_blocks.start_number;
            let blocks_count = matched_blocks.blocks_count;
            let mut should_remove = false;

            for block in &matched_blocks.blocks {
                if let Some(header) = self.get_header(&block.hash) {
                    let stored_number: u64 = header.number();
                    if stored_number < start_number || stored_number >= start_number + blocks_count
                    {
                        warn!(
                            "Invalid matched block {:#x} at number {} outside expected range [{}, {}), removing entry at start_number={}",
                            block.hash, stored_number, start_number, start_number + blocks_count, start_number
                        );
                        should_remove = true;
                        break;
                    }
                } else if start_number + 1000 < tip_number {
                    warn!(
                        "Matched block {:#x} not found in storage, entry at start_number={} is {} blocks behind tip, removing",
                        block.hash, start_number, tip_number - start_number
                    );
                    should_remove = true;
                    break;
                }
            }

            if should_remove {
                self.remove_matched_blocks(start_number);
            } else {
                break;
            }
        }
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
            .map(|data| u64::from_le_bytes(AsRef::<[u8]>::as_ref(&data).try_into().unwrap()))
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
            .map(|data| CpIndex::from_be_bytes(AsRef::<[u8]>::as_ref(&data).try_into().unwrap()))
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
