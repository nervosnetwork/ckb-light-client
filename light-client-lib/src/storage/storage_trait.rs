// Storage trait - unified interface for all storage backends (RocksDB, SQLite, IndexedDB)
//
// This trait builds on top of StorageBackend to provide business logic with default
// implementations. Storage backends only need to implement StorageBackend.

use super::{
    backend::StorageBackend, BlockNumber, Byte32, CpIndex, HeaderWithExtension, MatchedBlocks,
    ScriptStatus, SetScriptsCommand,
};
use ckb_types::{
    packed::{Block, Header, Transaction},
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
    fn filter_block(&self, block: Block);

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
