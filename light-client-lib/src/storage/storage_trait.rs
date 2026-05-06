// Storage trait - unified interface for all storage backends (RocksDB, SQLite, IndexedDB)
//
// This trait builds on top of StorageBackend to provide business logic with default
// implementations. Storage backends only need to implement StorageBackend.

use std::collections::{HashMap, HashSet};

use super::{
    backend::{BatchWriter, StorageBackend},
    db::{IteratorDirection, IteratorStart},
    parse_matched_blocks, BlockNumber, Byte32, CellIndex, CellType, CpIndex, HeaderWithExtension,
    Key, KeyPrefix, MatchedBlock, MatchedBlocks, OutputIndex, Script, ScriptStatus, ScriptType,
    SetScriptsCommand, TxIndex, Value, WrappedBlockView, FILTER_SCRIPTS_KEY, GENESIS_BLOCK_KEY,
    LAST_N_HEADERS_KEY, LAST_STATE_KEY, MATCHED_FILTER_BLOCKS_KEY, MAX_CHECK_POINT_INDEX,
    MIN_FILTERED_BLOCK_NUMBER,
};
use ckb_types::{
    core::HeaderView,
    packed::{self, Block, Header, Transaction},
    prelude::*,
    utilities::{build_filter_data, calc_filter_hash},
    U256,
};

/// High-level storage trait that provides business logic
///
/// This trait extends `StorageBackend` with higher-level operations.
/// All methods have default implementations that use the low-level
/// `StorageBackend` methods, so backends only need to implement `StorageBackend`.
pub trait LightClientStorage: StorageBackend {
    // ========== Filter scripts management ==========

    /// Check if filter scripts are empty
    fn is_filter_scripts_empty(&self) -> bool {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix.clone()),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix)),
            Box::new(|_key, value| Some(value.to_vec())),
            1,
        );
        results.is_empty()
    }

    /// Get all filter scripts
    fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix.clone()),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            usize::MAX,
        );

        results
            .into_iter()
            .map(|kv| {
                let key = &kv.key;
                let value = &kv.value;
                let script = Script::from_slice(&key[key_prefix.len()..key.len() - 1])
                    .expect("stored Script");
                let script_type = match key[key.len() - 1] {
                    0 => ScriptType::Lock,
                    1 => ScriptType::Type,
                    _ => panic!("invalid script type"),
                };
                let block_number = BlockNumber::from_be_bytes(
                    value.as_slice().try_into().expect("stored BlockNumber"),
                );
                ScriptStatus {
                    script,
                    script_type,
                    block_number,
                }
            })
            .collect()
    }

    /// Update filter scripts
    fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        let mut should_filter_genesis_block = false;
        let mut batch = self.batch();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        match command {
            SetScriptsCommand::All => {
                should_filter_genesis_block = scripts.iter().any(|ss| ss.block_number == 0);

                // Delete all existing filter scripts
                let key_prefix_clone = key_prefix.clone();
                let existing_keys = self.collect_iterator(
                    IteratorStart::From(key_prefix.clone()),
                    IteratorDirection::Forward,
                    Box::new(move |key| key.starts_with(&key_prefix_clone)),
                    Box::new(|_key, value| Some(value.to_vec())),
                    usize::MAX,
                );

                for kv in existing_keys {
                    batch.delete(&kv.key);
                }

                // Insert new scripts
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
                    batch.put(&key, &ss.block_number.to_be_bytes());
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
                    batch.put(&key, &ss.block_number.to_be_bytes());
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
                    batch.delete(&key);
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

    /// Get scripts hash by block number
    fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix.clone()),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            usize::MAX,
        );

        results
            .into_iter()
            .filter_map(|kv| {
                let stored_block_number = BlockNumber::from_be_bytes(
                    kv.value.as_slice().try_into().expect("stored BlockNumber"),
                );
                if stored_block_number < block_number {
                    let script = Script::from_slice(&kv.key[key_prefix.len()..kv.key.len() - 1])
                        .expect("stored Script");
                    Some(script.calc_script_hash())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Update block number for filter scripts
    fn update_block_number(&self, block_number: BlockNumber) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            usize::MAX,
        );

        let mut batch = self.batch();
        for kv in results {
            let stored_block_number = BlockNumber::from_be_bytes(
                kv.value.as_slice().try_into().expect("stored BlockNumber"),
            );
            if stored_block_number < block_number {
                batch.put(&kv.key, &block_number.to_be_bytes());
            }
        }
        batch.commit().expect("batch commit should be ok");
    }

    // ========== Matched blocks management ==========

    /// Get earliest matched blocks
    fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks_internal(IteratorDirection::Forward)
    }

    /// Get latest matched blocks
    fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks_internal(IteratorDirection::Reverse)
    }

    /// Add matched blocks
    fn add_matched_blocks(
        &self,
        start_number: u64,
        blocks_count: u64,
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
        StorageBackend::put(self, key, value).expect("db put matched blocks should be ok");
    }

    /// Remove matched blocks by start number
    fn remove_matched_blocks(&self, start_number: u64) {
        let mut key = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        key.extend(start_number.to_be_bytes());
        StorageBackend::delete(self, &key).expect("delete matched blocks");
    }

    /// Cleanup invalid matched blocks
    fn cleanup_invalid_matched_blocks(&self) {
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

    // ========== Check points management ==========

    /// Get check points
    fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        let start_key = Key::CheckPointIndex(start_index).into_vec();
        let key_prefix = [KeyPrefix::CheckPointIndex as u8];
        let results = self.collect_iterator(
            IteratorStart::From(start_key),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix)),
            Box::new(|_key, value| Some(value.to_vec())),
            limit,
        );

        results
            .into_iter()
            .map(|kv| Byte32::from_slice(&kv.value).expect("stored block filter hash"))
            .collect()
    }

    /// Update check points
    fn update_check_points(&self, start_index: CpIndex, check_points: &[Byte32]) {
        let mut batch = self.batch();
        for (index, cp) in (start_index..).zip(check_points.iter()) {
            let key = Key::CheckPointIndex(index).into_vec();
            let value: Vec<u8> = Value::BlockFilterHash(cp).into();
            batch.put(&key, &value);
        }
        batch.commit().expect("batch commit should be ok");
    }

    /// Get last check point
    fn get_last_check_point(&self) -> (CpIndex, Byte32) {
        let index = self.get_max_check_point_index();
        let hash = self
            .get_check_points(index, 1)
            .first()
            .cloned()
            .expect("db get last check point should be ok");
        (index, hash)
    }

    /// Get max check point index
    fn get_max_check_point_index(&self) -> CpIndex {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        StorageBackend::get(self, key)
            .expect("db get max check point index should be ok")
            .map(|data| CpIndex::from_be_bytes(data.as_slice().try_into().unwrap()))
            .expect("db get max check point index should be ok")
    }

    /// Update max check point index
    fn update_max_check_point_index(&self, index: CpIndex) {
        let key = Key::Meta(MAX_CHECK_POINT_INDEX).into_vec();
        let value = index.to_be_bytes().to_vec();
        StorageBackend::put(self, key, value).expect("db put max check point index should be ok");
    }

    // ========== Block and transaction management ==========

    /// Initialize genesis block
    fn init_genesis_block(&self, block: Block) {
        let genesis_hash = block.calc_header_hash();
        let genesis_block_key = Key::Meta(GENESIS_BLOCK_KEY).into_vec();
        if let Some(stored_genesis_hash) = StorageBackend::get(self, genesis_block_key.clone())
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
            batch.put(
                &Key::Meta(LAST_STATE_KEY).into_vec(),
                block.header().as_slice(),
            );
            batch.put(
                &Key::BlockHash(&block_hash).into_vec(),
                block.header().as_slice(),
            );
            batch.put(&Key::BlockNumber(0).into_vec(), block_hash.as_slice());
            let mut genesis_hash_and_txs_hash = genesis_hash.as_slice().to_vec();
            block
                .transactions()
                .into_iter()
                .enumerate()
                .for_each(|(tx_index, tx)| {
                    let tx_hash = tx.calc_tx_hash();
                    genesis_hash_and_txs_hash.extend_from_slice(tx_hash.as_slice());
                    let key = Key::TxHash(&tx_hash).into_vec();
                    let value: Vec<u8> = Value::Transaction(0, tx_index as TxIndex, &tx).into();
                    batch.put(&key, &value);
                });
            batch.put(&genesis_block_key, &genesis_hash_and_txs_hash);
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

    /// Get genesis block
    fn get_genesis_block(&self) -> Block {
        let genesis_hash_and_txs_hash =
            StorageBackend::get(self, Key::Meta(GENESIS_BLOCK_KEY).into_vec())
                .expect("get genesis block")
                .expect("inited storage");
        let genesis_hash = Byte32::from_slice(&genesis_hash_and_txs_hash[0..32])
            .expect("stored genesis block hash");
        let genesis_header = Header::from_slice(
            &StorageBackend::get(self, Key::BlockHash(&genesis_hash).into_vec())
                .expect("db get should be ok")
                .expect("stored block hash / header mapping"),
        )
        .expect("stored header should be OK");

        let transactions: Vec<Transaction> = genesis_hash_and_txs_hash[32..]
            .chunks_exact(32)
            .map(|tx_hash| {
                Transaction::from_slice(
                    &StorageBackend::get(
                        self,
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

    /// Add fetched header
    fn add_fetched_header(&self, hwe: &HeaderWithExtension) {
        let mut batch = self.batch();
        let block_hash = hwe.header.calc_header_hash();
        batch.put(&Key::BlockHash(&block_hash).into_vec(), &hwe.to_vec());
        batch.put(
            &Key::BlockNumber(hwe.header.raw().number().unpack()).into_vec(),
            block_hash.as_slice(),
        );
        batch.commit().expect("batch commit should be ok");
    }

    /// Add fetched transaction
    fn add_fetched_tx(&self, tx: &Transaction, hwe: &HeaderWithExtension) {
        let mut batch = self.batch();
        let block_hash = hwe.header.calc_header_hash();
        let block_number: u64 = hwe.header.raw().number().unpack();
        batch.put(&Key::BlockHash(&block_hash).into_vec(), &hwe.to_vec());
        batch.put(
            &Key::BlockNumber(block_number).into_vec(),
            block_hash.as_slice(),
        );
        let tx_hash = tx.calc_tx_hash();
        let tx_index = u32::MAX;
        let key = Key::TxHash(&tx_hash).into_vec();
        let value: Vec<u8> = Value::Transaction(block_number, tx_index as TxIndex, tx).into();
        batch.put(&key, &value);
        batch.commit().expect("batch commit should be ok");
    }

    /// Filter and store block data
    ///
    /// This method scans through all transactions in a block, matching them against
    /// the registered filter scripts. When matches are found, it:
    /// - Deletes spent UTXOs (cells consumed as inputs)
    /// - Creates new UTXO entries (cells created as outputs)
    /// - Records transaction history for matched scripts
    /// - Stores the matched transactions
    fn filter_block(&self, block: Block) {
        let scripts: HashSet<(packed::Script, ScriptType)> = self
            .get_filter_scripts()
            .into_iter()
            .map(|ss| (ss.script, ss.script_type))
            .collect();
        let block_number: BlockNumber = block.header().raw().number().unpack();
        let mut filter_matched = false;
        let mut batch = self.batch();
        let mut txs: HashMap<Byte32, (u32, Transaction)> = HashMap::new();

        for (tx_index, tx) in block.transactions().into_iter().enumerate() {
            // Process inputs - delete spent UTXOs and record input history
            for (input_index, input) in tx.raw().inputs().into_iter().enumerate() {
                let previous_tx_hash = input.previous_output().tx_hash();
                if let Some((generated_by_block_number, generated_by_tx_index, previous_tx)) =
                    self.get_transaction(&previous_tx_hash).or(txs
                        .get(&previous_tx_hash)
                        .map(|(tx_idx, tx)| (block_number, *tx_idx, tx.clone())))
                {
                    let previous_output_index: u32 = input.previous_output().index().unpack();
                    if let Some(previous_output) = previous_tx
                        .raw()
                        .outputs()
                        .get(previous_output_index as usize)
                    {
                        // Check lock script
                        let lock_script = previous_output.lock();
                        if scripts.contains(&(lock_script.clone(), ScriptType::Lock)) {
                            filter_matched = true;
                            // Delete UTXO
                            let key = Key::CellLockScript(
                                &lock_script,
                                generated_by_block_number,
                                generated_by_tx_index,
                                previous_output_index as OutputIndex,
                            )
                            .into_vec();
                            batch.delete(&key);
                            // Insert tx history
                            let key = Key::TxLockScript(
                                &lock_script,
                                block_number,
                                tx_index as TxIndex,
                                input_index as CellIndex,
                                CellType::Input,
                            )
                            .into_vec();
                            let tx_hash = tx.calc_tx_hash();
                            batch.put(&key, tx_hash.as_slice());
                            // Insert tx
                            let key = Key::TxHash(&tx_hash).into_vec();
                            let value: Vec<u8> =
                                Value::Transaction(block_number, tx_index as TxIndex, &tx).into();
                            batch.put(&key, &value);
                        }
                        // Check type script
                        if let Some(type_script) = previous_output.type_().to_opt() {
                            if scripts.contains(&(type_script.clone(), ScriptType::Type)) {
                                filter_matched = true;
                                // Delete UTXO
                                let key = Key::CellTypeScript(
                                    &type_script,
                                    generated_by_block_number,
                                    generated_by_tx_index,
                                    previous_output_index as OutputIndex,
                                )
                                .into_vec();
                                batch.delete(&key);
                                // Insert tx history
                                let key = Key::TxTypeScript(
                                    &type_script,
                                    block_number,
                                    tx_index as TxIndex,
                                    input_index as CellIndex,
                                    CellType::Input,
                                )
                                .into_vec();
                                let tx_hash = tx.calc_tx_hash();
                                batch.put(&key, tx_hash.as_slice());
                                // Insert tx
                                let key = Key::TxHash(&tx_hash).into_vec();
                                let value: Vec<u8> =
                                    Value::Transaction(block_number, tx_index as TxIndex, &tx)
                                        .into();
                                batch.put(&key, &value);
                            }
                        }
                    }
                }
            }

            // Process outputs - create new UTXOs and record output history
            for (output_index, output) in tx.raw().outputs().into_iter().enumerate() {
                let lock_script = output.lock();
                if scripts.contains(&(lock_script.clone(), ScriptType::Lock)) {
                    filter_matched = true;
                    let tx_hash = tx.calc_tx_hash();
                    // Insert UTXO
                    let key = Key::CellLockScript(
                        &lock_script,
                        block_number,
                        tx_index as TxIndex,
                        output_index as OutputIndex,
                    )
                    .into_vec();
                    batch.put(&key, tx_hash.as_slice());
                    // Insert tx history
                    let key = Key::TxLockScript(
                        &lock_script,
                        block_number,
                        tx_index as TxIndex,
                        output_index as CellIndex,
                        CellType::Output,
                    )
                    .into_vec();
                    batch.put(&key, tx_hash.as_slice());
                    // Insert tx
                    let key = Key::TxHash(&tx_hash).into_vec();
                    let value: Vec<u8> =
                        Value::Transaction(block_number, tx_index as TxIndex, &tx).into();
                    batch.put(&key, &value);
                }
                if let Some(type_script) = output.type_().to_opt() {
                    if scripts.contains(&(type_script.clone(), ScriptType::Type)) {
                        filter_matched = true;
                        let tx_hash = tx.calc_tx_hash();
                        // Insert UTXO
                        let key = Key::CellTypeScript(
                            &type_script,
                            block_number,
                            tx_index as TxIndex,
                            output_index as OutputIndex,
                        )
                        .into_vec();
                        batch.put(&key, tx_hash.as_slice());
                        // Insert tx history
                        let key = Key::TxTypeScript(
                            &type_script,
                            block_number,
                            tx_index as TxIndex,
                            output_index as CellIndex,
                            CellType::Output,
                        )
                        .into_vec();
                        batch.put(&key, tx_hash.as_slice());
                        // Insert tx
                        let key = Key::TxHash(&tx_hash).into_vec();
                        let value: Vec<u8> =
                            Value::Transaction(block_number, tx_index as TxIndex, &tx).into();
                        batch.put(&key, &value);
                    }
                }
            }

            txs.insert(tx.calc_tx_hash(), (tx_index as u32, tx));
        }

        // If any transaction matched, store the block header
        if filter_matched {
            let block_hash = block.calc_header_hash();
            let hwe = HeaderWithExtension {
                header: block.header(),
                extension: block.extension(),
            };
            batch.put(&Key::BlockHash(&block_hash).into_vec(), &hwe.to_vec());
            batch.put(
                &Key::BlockNumber(block_number).into_vec(),
                block_hash.as_slice(),
            );
        }
        batch.commit().expect("batch commit should be ok");
    }

    /// Rollback to specified block number
    ///
    /// N.B. The specified block will be removed.
    fn rollback_to_block(&self, to_number: BlockNumber) {
        use super::extract_raw_data;

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
                let key_prefix_len = key_prefix.len();

                let key_prefix_clone = key_prefix.clone();
                let results = self.collect_iterator(
                    IteratorStart::From(start_key),
                    IteratorDirection::Reverse,
                    Box::new(move |key| {
                        key.starts_with(&key_prefix_clone)
                            && BlockNumber::from_be_bytes(
                                key[key_prefix_len..key_prefix_len + 8]
                                    .try_into()
                                    .expect("stored BlockNumber"),
                            ) >= to_number
                    }),
                    Box::new(|_key, value| Some(value.to_vec())),
                    usize::MAX,
                );

                for kv in results {
                    let key = &kv.key;
                    let value = &kv.value;
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
                    let tx_hash = packed::Byte32Reader::from_slice_should_be_ok(value).to_entity();
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
                            batch.put(
                                &key.into_vec(),
                                input.previous_output().tx_hash().as_slice(),
                            );
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
                        batch.delete(&key);
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
                        batch.delete(&key);

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
                        batch.delete(&key);
                    };
                }

                // update script filter block number
                {
                    let mut key = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
                    key.extend_from_slice(script.as_slice());
                    key.extend_from_slice(match ss.script_type {
                        ScriptType::Lock => &[0],
                        ScriptType::Type => &[1],
                    });
                    let value = to_number.to_be_bytes().to_vec();
                    batch.put(&key, &value);
                }
            }
        }

        // we should also sync block filters again
        if self.get_min_filtered_block_number() >= to_number {
            batch.put(
                &Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec(),
                &to_number.saturating_sub(1).to_le_bytes(),
            );
        }

        batch.commit().expect("batch commit should be ok");
    }

    /// Get transaction with header by transaction hash
    fn get_transaction_with_header(&self, tx_hash: &Byte32) -> Option<(Transaction, Header)> {
        self.get_transaction(tx_hash)
            .map(|(block_number, _tx_index, tx)| {
                let block_hash = Byte32::from_slice(
                    &StorageBackend::get(self, Key::BlockNumber(block_number).into_vec())
                        .expect("db get should be ok")
                        .expect("stored block number / hash mapping"),
                )
                .expect("stored block hash should be OK");

                let header = Header::from_slice(
                    &StorageBackend::get(self, Key::BlockHash(&block_hash).into_vec())
                        .expect("db get should be ok")
                        .expect("stored block hash / header mapping")[..Header::TOTAL_SIZE],
                )
                .expect("stored header should be OK");
                (tx, header)
            })
    }

    // ========== Chain state management ==========

    /// Update last state (tip header and total difficulty)
    fn update_last_state(
        &self,
        total_difficulty: &U256,
        tip_header: &Header,
        last_n_headers: &[HeaderView],
    ) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let mut value = total_difficulty.to_le_bytes().to_vec();
        value.extend(tip_header.as_slice());
        StorageBackend::put(self, key, value).expect("db put last state should be ok");
        self.update_last_n_headers(last_n_headers);
    }

    /// Get last state (total difficulty and tip header)
    fn get_last_state(&self) -> (U256, Header) {
        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        StorageBackend::get(self, key)
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

    /// Get last N headers
    fn get_last_n_headers(&self) -> Vec<(u64, Byte32)> {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        StorageBackend::get(self, key)
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

    /// Get tip header
    fn get_tip_header(&self) -> Header {
        self.get_last_state().1
    }

    /// Get minimum filtered block number
    fn get_min_filtered_block_number(&self) -> BlockNumber {
        let key = Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec();
        StorageBackend::get(self, key)
            .expect("db get min filtered block number should be ok")
            .map(|data| u64::from_le_bytes(data.as_slice().try_into().unwrap()))
            .unwrap_or_default()
    }

    /// Update minimum filtered block number
    fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        let key = Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec();
        let value = block_number.to_le_bytes().to_vec();
        StorageBackend::put(self, key, value)
            .expect("db put min filtered block number should be ok");
    }

    // ========== Additional methods ==========

    /// Get block hash by number
    fn get_block_hash(&self, block_number: BlockNumber) -> Option<Byte32> {
        StorageBackend::get(self, Key::BlockNumber(block_number).into_vec())
            .ok()
            .flatten()
            .map(|v| Byte32::from_slice(&v).expect("stored block hash"))
    }

    /// Get transaction
    fn get_transaction(&self, tx_hash: &Byte32) -> Option<(BlockNumber, u32, Transaction)> {
        StorageBackend::get(self, Key::TxHash(tx_hash).into_vec())
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

    /// Get header by hash
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        StorageBackend::get(self, Key::BlockHash(hash).into_vec())
            .map(|v| {
                v.map(|v| {
                    Header::from_slice(&v[..Header::TOTAL_SIZE])
                        .expect("stored Header")
                        .into_view()
                })
            })
            .expect("db get should be ok")
    }

    // ========== Private helper methods ==========

    /// Update last N headers
    fn update_last_n_headers(&self, headers: &[HeaderView]) {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        let mut value: Vec<u8> = Vec::with_capacity(headers.len() * 40);
        for header in headers {
            value.extend(header.number().to_le_bytes());
            value.extend(header.hash().as_slice());
        }
        StorageBackend::put(self, key, value).expect("db put last n headers should be ok");
    }

    /// Update min filtered block number by scripts
    fn update_min_filtered_block_number_by_scripts(&self) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            usize::MAX,
        );

        let min_block_number = results
            .into_iter()
            .map(|kv| {
                BlockNumber::from_be_bytes(
                    kv.value.as_slice().try_into().expect("stored BlockNumber"),
                )
            })
            .min();

        if let Some(n) = min_block_number {
            self.update_min_filtered_block_number(n);
        }
    }

    /// Clear matched blocks
    fn clear_matched_blocks(&self) {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(key_prefix),
            IteratorDirection::Forward,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            usize::MAX,
        );

        let mut batch = self.batch();
        for kv in results {
            batch.delete(&kv.key);
        }
        batch.commit().expect("batch commit should be ok");
    }

    /// Get matched blocks internal helper
    fn get_matched_blocks_internal(&self, direction: IteratorDirection) -> Option<MatchedBlocks> {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let iter_from = match direction {
            IteratorDirection::Forward => key_prefix.clone(),
            IteratorDirection::Reverse => {
                let mut key = key_prefix.clone();
                key.extend(u64::MAX.to_be_bytes());
                key
            }
        };

        let key_prefix_clone = key_prefix.clone();
        let results = self.collect_iterator(
            IteratorStart::From(iter_from),
            direction,
            Box::new(move |key| key.starts_with(&key_prefix_clone)),
            Box::new(|_key, value| Some(value.to_vec())),
            1,
        );

        results.into_iter().next().map(|kv| {
            let key = &kv.key;
            let value = &kv.value;
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&key[key_prefix.len()..]);
            let start_number = u64::from_be_bytes(u64_bytes);
            let (blocks_count, raw_blocks) = parse_matched_blocks(value);
            let blocks = raw_blocks
                .into_iter()
                .map(|(hash, proved)| MatchedBlock { hash, proved })
                .collect();
            MatchedBlocks {
                start_number,
                blocks_count,
                blocks,
            }
        })
    }
}
