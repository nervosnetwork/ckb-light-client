// Storage trait - unified interface for all storage backends (RocksDB, SQLite, IndexedDB)
//
// This trait builds on top of StorageBackend to provide business logic with default
// implementations. Storage backends only need to implement StorageBackend.

use std::collections::{HashMap, HashSet};

use super::{
    backend::StorageBackend, BlockNumber, Byte32, CellIndex, CellType, CpIndex,
    HeaderWithExtension, Key, MatchedBlocks, OutputIndex, ScriptStatus, ScriptType,
    SetScriptsCommand, TxIndex, Value,
};
use ckb_types::{
    packed::{self, Block, Header, Transaction},
    prelude::*,
    U256,
};

/// High-level storage trait that provides business logic
///
/// This trait extends `StorageBackend` with higher-level operations.
/// Most methods have default implementations that use the low-level
/// `StorageBackend` methods, so backends only need to implement `StorageBackend`.
///
/// Methods without default implementations are those that:
/// 1. Have significantly different implementations across backends
/// 2. Or are still being migrated to default implementations
pub trait LightClientStorage: StorageBackend {
    // ========== Filter scripts management ==========

    /// Check if filter scripts are empty
    fn is_filter_scripts_empty(&self) -> bool;

    /// Get all filter scripts
    fn get_filter_scripts(&self) -> Vec<ScriptStatus>;

    /// Update filter scripts
    fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand);

    /// Get scripts hash by block number
    fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32>;

    /// Update block number for filter scripts
    fn update_block_number(&self, block_number: BlockNumber);

    // ========== Matched blocks management ==========

    /// Get earliest matched blocks
    fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks>;

    /// Get latest matched blocks
    fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks>;

    /// Add matched blocks
    fn add_matched_blocks(
        &self,
        start_number: u64,
        blocks_count: u64,
        matched_blocks: Vec<(Byte32, bool)>,
    );

    /// Remove matched blocks by start number
    fn remove_matched_blocks(&self, start_number: u64);

    /// Cleanup invalid matched blocks
    fn cleanup_invalid_matched_blocks(&self);

    // ========== Check points management ==========

    /// Get check points
    fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32>;

    /// Update check points
    fn update_check_points(&self, start_index: CpIndex, check_points: &[Byte32]);

    /// Get last check point
    fn get_last_check_point(&self) -> (CpIndex, Byte32);

    /// Get max check point index
    fn get_max_check_point_index(&self) -> CpIndex;

    /// Update max check point index
    fn update_max_check_point_index(&self, index: CpIndex);

    // ========== Block and transaction management ==========

    /// Initialize genesis block
    fn init_genesis_block(&self, block: Block);

    /// Get genesis block
    fn get_genesis_block(&self) -> Block;

    /// Add fetched header
    fn add_fetched_header(&self, hwe: &HeaderWithExtension);

    /// Add fetched transaction
    fn add_fetched_tx(&self, tx: &Transaction, hwe: &HeaderWithExtension);

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
    fn rollback_to_block(&self, to_number: BlockNumber);

    /// Get transaction with header by transaction hash
    fn get_transaction_with_header(&self, tx_hash: &Byte32) -> Option<(Transaction, Header)>;

    // ========== Chain state management ==========

    /// Update last state (tip header and total difficulty)
    fn update_last_state(
        &self,
        total_difficulty: &U256,
        tip_header: &Header,
        last_n_headers: &[ckb_types::core::HeaderView],
    );

    /// Get last state (total difficulty and tip header)
    fn get_last_state(&self) -> (U256, Header);

    /// Get last N headers
    fn get_last_n_headers(&self) -> Vec<(u64, Byte32)>;

    /// Get tip header
    fn get_tip_header(&self) -> Header;

    /// Get minimum filtered block number
    fn get_min_filtered_block_number(&self) -> BlockNumber;

    /// Update minimum filtered block number
    fn update_min_filtered_block_number(&self, block_number: BlockNumber);

    // ========== Additional methods ==========

    /// Get block hash by number
    fn get_block_hash(&self, block_number: BlockNumber) -> Option<Byte32>;

    /// Get transaction
    fn get_transaction(&self, tx_hash: &Byte32) -> Option<(BlockNumber, u32, Transaction)>;
}
