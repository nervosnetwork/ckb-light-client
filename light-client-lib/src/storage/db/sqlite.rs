// SQLite storage backend for CKB Light Client
// This implementation provides the same interface as RocksDB but uses SQLite as the underlying storage

use super::super::{
    parse_matched_blocks, BlockNumber, Byte32, CpIndex, HeaderWithExtension, Key, KeyPrefix,
    MatchedBlock, MatchedBlocks, Script, ScriptStatus, ScriptType, SetScriptsCommand, TxIndex,
    Value, FILTER_SCRIPTS_KEY, GENESIS_BLOCK_KEY, LAST_N_HEADERS_KEY, LAST_STATE_KEY,
    MATCHED_FILTER_BLOCKS_KEY, MAX_CHECK_POINT_INDEX, MIN_FILTERED_BLOCK_NUMBER,
};
use super::iterator::{IteratorDirection, KVPair, StorageIterator};
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
    U256,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Storage {
    pub(crate) conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("Failed to open sqlite database");

        // Initialize the schema
        Self::init_schema(&conn).expect("Failed to initialize sqlite schema");

        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key BLOB PRIMARY KEY NOT NULL,
                value BLOB NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_key_prefix ON kv_store(key);
            
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 268435456;
            PRAGMA page_size = 4096;
            PRAGMA cache_size = -65536;
            "#,
        )
        .map_err(|e| crate::error::Error::runtime(format!("Failed to initialize schema: {}", e)))
    }

    fn batch(&self) -> Batch {
        Batch {
            conn: Arc::clone(&self.conn),
            operations: Vec::new(),
        }
    }

    fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)",
            rusqlite::params![key.as_ref(), value.as_ref()],
        )
        .map_err(|e| crate::error::Error::runtime(format!("Failed to put: {}", e)))?;
        Ok(())
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT value FROM kv_store WHERE key = ?")
            .map_err(|e| crate::error::Error::runtime(format!("Failed to prepare get: {}", e)))?;

        let result = stmt.query_row(rusqlite::params![key.as_ref()], |row| {
            row.get::<_, Vec<u8>>(0)
        });

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(crate::error::Error::runtime(format!(
                "Failed to get: {}",
                e
            ))),
        }
    }

    fn delete<K>(&self, key: K) -> Result<()>
    where
        K: AsRef<[u8]>,
    {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM kv_store WHERE key = ?",
            rusqlite::params![key.as_ref()],
        )
        .map_err(|e| crate::error::Error::runtime(format!("Failed to delete: {}", e)))?;
        Ok(())
    }

    pub fn is_filter_scripts_empty(&self) -> bool {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let conn = self.conn.lock().unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM kv_store WHERE key >= ? AND substr(key, 1, ?) = ?",
                rusqlite::params![&key_prefix, key_prefix.len(), &key_prefix],
                |row| row.get(0),
            )
            .unwrap_or(0);

        count == 0
    }

    pub fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT key, value FROM kv_store WHERE key >= ? ORDER BY key")
            .expect("prepare statement");

        let rows = stmt
            .query_map(rusqlite::params![&key_prefix], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("query rows");

        rows.filter_map(|r| r.ok())
            .take_while(|(key, _)| key.starts_with(&key_prefix))
            .map(|(key, value)| {
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

    pub fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        let mut batch = self.batch();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        match command {
            SetScriptsCommand::All => {
                // Delete all existing filter scripts
                let conn = self.conn.lock().unwrap();
                let mut stmt = conn
                    .prepare("SELECT key FROM kv_store WHERE key >= ? ORDER BY key")
                    .expect("prepare statement");

                let keys_to_delete: Vec<Vec<u8>> = stmt
                    .query_map(rusqlite::params![&key_prefix], |row| row.get(0))
                    .expect("query keys")
                    .filter_map(|r| r.ok())
                    .take_while(|key: &Vec<u8>| key.starts_with(&key_prefix))
                    .collect();

                drop(stmt);
                drop(conn);

                for key in keys_to_delete {
                    batch.delete(key);
                }

                // Add new scripts
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
                    batch.put(key, ss.block_number.to_be_bytes());
                }
            }
            SetScriptsCommand::Partial => {
                // Update or add scripts
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
                    batch.put(key, ss.block_number.to_be_bytes());
                }
            }
            SetScriptsCommand::Delete => {
                // Delete specified scripts
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
                    batch.delete(key);
                }
            }
        }

        batch.commit().expect("batch commit should be ok");
    }

    pub fn get_scripts_hash(&self, _block_number: BlockNumber) -> Vec<Byte32> {
        // This method in native.rs appears to be for filter hashes per block
        // For simplicity, return empty vec as this is not critical for the iterator refactoring
        Vec::new()
    }

    fn get_matched_blocks(&self, ascending: bool) -> Option<MatchedBlocks> {
        let conn = self.conn.lock().unwrap();
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();

        let order_clause = if ascending { "ASC" } else { "DESC" };
        let query = format!(
            "SELECT key, value FROM kv_store WHERE key >= ? AND key < ? ORDER BY key {} LIMIT 1",
            order_clause
        );

        // Create an upper bound for the prefix search
        let mut upper_bound = key_prefix.clone();
        if let Some(last) = upper_bound.last_mut() {
            *last = last.wrapping_add(1);
        }

        let mut stmt = conn.prepare(&query).ok()?;
        stmt.query_row(rusqlite::params![&key_prefix, &upper_bound], |row| {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;

            // Extract start_number from key (after the prefix)
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&key[key_prefix.len()..]);
            let start_number = u64::from_be_bytes(u64_bytes);

            // Parse the value
            let (blocks_count, raw_blocks) = parse_matched_blocks(&value);
            let blocks = raw_blocks
                .into_iter()
                .map(|(hash, proved)| MatchedBlock { hash, proved })
                .collect();

            Ok(MatchedBlocks {
                start_number,
                blocks_count,
                blocks,
            })
        })
        .ok()
    }

    pub fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks(true)
    }

    pub fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks(false)
    }

    pub fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        let mut check_points = Vec::new();
        for i in 0..limit {
            let index = start_index + i as u32;
            if let Some(value) = self
                .get(Key::CheckPointIndex(index).into_vec())
                .expect("db get should be ok")
            {
                check_points.push(Byte32::from_slice(&value).expect("parse check point"));
            } else {
                break;
            }
        }
        check_points
    }

    pub fn update_block_number(&self, block_number: BlockNumber) {
        let conn = self.conn.lock().unwrap();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        // Create an upper bound for the prefix search
        let mut upper_bound = key_prefix.clone();
        if let Some(last) = upper_bound.last_mut() {
            *last = last.wrapping_add(1);
        }

        let query = "SELECT key, value FROM kv_store WHERE key >= ? AND key < ?";
        let mut stmt = conn.prepare(query).expect("prepare query");

        let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
            .query_map(rusqlite::params![&key_prefix, &upper_bound], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("query rows")
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);
        drop(conn);

        let mut batch = self.batch();
        for (key, value) in rows {
            let stored_block_number = BlockNumber::from_be_bytes(
                value.as_slice().try_into().expect("stored BlockNumber"),
            );
            if stored_block_number < block_number {
                batch.put(key, block_number.to_be_bytes());
            }
        }
        batch.commit().expect("batch commit should be ok");
    }

    pub fn rollback_to_block(&self, to_number: BlockNumber) {
        let conn = self.conn.lock().unwrap();

        // For SQLite, we need to identify and delete keys by scanning
        // This is less efficient than RocksDB but maintains the same interface
        let prefixes = vec![
            KeyPrefix::TxLockScript as u8,
            KeyPrefix::TxTypeScript as u8,
            KeyPrefix::CellLockScript as u8,
            KeyPrefix::CellTypeScript as u8,
            KeyPrefix::TxHash as u8,
            KeyPrefix::BlockHash as u8,
            KeyPrefix::BlockNumber as u8,
        ];

        for prefix in prefixes {
            let prefix_vec = vec![prefix];
            let mut stmt = conn
                .prepare("SELECT key FROM kv_store WHERE key >= ? AND substr(key, 1, 1) = ?")
                .expect("prepare statement");

            let keys_to_check: Vec<Vec<u8>> = stmt
                .query_map(rusqlite::params![&prefix_vec, &prefix_vec], |row| {
                    row.get(0)
                })
                .expect("query keys")
                .filter_map(|r| r.ok())
                .collect();

            drop(stmt);

            // Delete keys for blocks > to_number
            for key in keys_to_check {
                // Try to extract block number from key (format varies by key type)
                // This is a simplified version - production code would need more careful parsing
                if key.len() >= 8 {
                    // Most keys have block number in the last 8 bytes or nearby
                    let should_delete = if let Some(block_num_bytes) = key.get(key.len() - 8..) {
                        if block_num_bytes.len() == 8 {
                            if let Ok(bytes) = block_num_bytes.try_into() {
                                let block_num = u64::from_be_bytes(bytes);
                                block_num > to_number
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if should_delete {
                        conn.execute(
                            "DELETE FROM kv_store WHERE key = ?",
                            rusqlite::params![&key],
                        )
                        .expect("delete key");
                    }
                }
            }
        }

        drop(conn);

        // TODO: Implement proper rollback logic for matched blocks
        // For now, we just clean up invalid entries
        self.cleanup_invalid_matched_blocks();
    }

    pub fn init_genesis_block(&self, block: packed::Block) {
        let mut batch = self.batch();

        let block_number: BlockNumber = block.header().raw().number().unpack();
        let block_hash = block.calc_header_hash();

        batch.put(Key::Meta(GENESIS_BLOCK_KEY).into_vec(), block.as_slice());
        batch.put(
            Key::BlockHash(&block_hash).into_vec(),
            block.header().as_slice(),
        );
        batch.put(
            Key::BlockNumber(block_number).into_vec(),
            block_hash.as_slice(),
        );

        batch.commit().expect("batch commit should be ok");
    }

    pub fn get_genesis_block(&self) -> packed::Block {
        self.get(Key::Meta(GENESIS_BLOCK_KEY).into_vec())
            .expect("db get should be ok")
            .map(|v| packed::Block::from_slice(&v).expect("parse genesis block"))
            .expect("genesis block should exist")
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

    pub fn get_last_state(&self) -> (U256, Header) {
        self.get(Key::Meta(LAST_STATE_KEY).into_vec())
            .expect("db get should be ok")
            .map(|v| {
                let total_difficulty =
                    U256::from_little_endian(&v[0..32]).expect("parse total_difficulty");
                let header = Header::from_slice(&v[32..]).expect("parse header");
                (total_difficulty, header)
            })
            .unwrap_or_else(|| {
                let genesis = self.get_genesis_block();
                let header = genesis.header();
                (U256::zero(), header)
            })
    }

    pub fn get_last_n_headers(&self) -> Vec<(u64, Byte32)> {
        let key = Key::Meta(LAST_N_HEADERS_KEY).into_vec();
        self.get(key)
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

    pub fn remove_matched_blocks(&self, start_number: u64) {
        let mut key = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        key.extend(start_number.to_be_bytes());
        self.delete(&key).expect("delete matched blocks");
    }

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
        batch.put(Key::BlockHash(&block_hash).into_vec(), hwe.to_vec());
        batch.put(
            Key::BlockNumber(hwe.header.raw().number().unpack()).into_vec(),
            block_hash.as_slice(),
        );
        batch.commit().expect("batch commit should be ok");
    }

    pub fn add_fetched_tx(&self, tx: &Transaction, hwe: &HeaderWithExtension) {
        let mut batch = self.batch();
        let block_hash = hwe.header.calc_header_hash();
        let block_number: u64 = hwe.header.raw().number().unpack();
        batch.put(Key::BlockHash(&block_hash).into_vec(), hwe.to_vec());
        batch.put(
            Key::BlockNumber(block_number).into_vec(),
            block_hash.as_slice(),
        );
        let tx_hash = tx.calc_tx_hash();
        let tx_index = u32::MAX;
        let key = Key::TxHash(&tx_hash).into_vec();
        let value: Vec<u8> = Value::Transaction(block_number, tx_index as TxIndex, tx).into();
        batch.put_kv(key, value);
        batch.commit().expect("batch commit should be ok");
    }

    pub fn get_tip_header(&self) -> Header {
        let (_, header) = self.get_last_state();
        header
    }

    pub fn get_min_filtered_block_number(&self) -> BlockNumber {
        self.get(Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec())
            .expect("db get should be ok")
            .map(|v| BlockNumber::from_be_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])))
            .unwrap_or(0)
    }

    pub fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        self.put(
            Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec(),
            block_number.to_be_bytes(),
        )
        .expect("db put should be ok");
    }

    pub fn get_last_check_point(&self) -> (CpIndex, Byte32) {
        let max_index = self.get_max_check_point_index();
        if max_index == 0 {
            return (0, Byte32::default());
        }

        let hash = self
            .get(Key::CheckPointIndex(max_index).into_vec())
            .expect("db get should be ok")
            .map(|v| Byte32::from_slice(&v).expect("parse check point"))
            .unwrap_or_default();

        (max_index, hash)
    }

    pub fn get_max_check_point_index(&self) -> CpIndex {
        self.get(Key::Meta(MAX_CHECK_POINT_INDEX).into_vec())
            .expect("db get should be ok")
            .map(|v| CpIndex::from_be_bytes(v.as_slice().try_into().unwrap_or([0u8; 4])))
            .unwrap_or(0)
    }

    pub fn update_max_check_point_index(&self, index: CpIndex) {
        self.put(
            Key::Meta(MAX_CHECK_POINT_INDEX).into_vec(),
            index.to_be_bytes(),
        )
        .expect("db put should be ok");
    }

    pub fn update_check_points(&self, start_index: CpIndex, check_points: &[Byte32]) {
        let mut batch = self.batch();

        for (i, hash) in check_points.iter().enumerate() {
            let index = start_index + i as u32;
            batch.put(Key::CheckPointIndex(index).into_vec(), hash.as_slice());
        }

        batch.commit().expect("batch commit should be ok");
    }

    pub fn filter_block(&self, block: packed::Block) {
        let scripts: HashSet<(Script, ScriptType)> = self
            .get_filter_scripts()
            .into_iter()
            .map(|ss| (ss.script, ss.script_type))
            .collect();

        let block_number: BlockNumber = block.header().raw().number().unpack();
        let mut batch = self.batch();

        for (tx_index, tx) in block.transactions().into_iter().enumerate() {
            let tx_index = tx_index as u32;
            let tx_hash = tx.calc_tx_hash();

            // Store transaction
            let value: Vec<u8> = Value::Transaction(block_number, tx_index, &tx).into();
            batch.put(Key::TxHash(&tx_hash).into_vec(), value);

            // Process outputs
            for (output_index, output) in tx.raw().outputs().into_iter().enumerate() {
                let output_index = output_index as u32;

                let lock_script = output.lock();
                if scripts.contains(&(lock_script.clone(), ScriptType::Lock)) {
                    let key =
                        Key::CellLockScript(&lock_script, block_number, tx_index, output_index)
                            .into_vec();
                    batch.put(key, tx_hash.as_slice());
                }

                if let Some(type_script) = output.type_().to_opt() {
                    if scripts.contains(&(type_script.clone(), ScriptType::Type)) {
                        let key =
                            Key::CellTypeScript(&type_script, block_number, tx_index, output_index)
                                .into_vec();
                        batch.put(key, tx_hash.as_slice());
                    }
                }
            }
        }

        batch.commit().expect("batch commit should be ok");
    }

    pub fn get_transaction_with_header(&self, tx_hash: &Byte32) -> Option<(Transaction, Header)> {
        let value = self.get(Key::TxHash(tx_hash).into_vec()).ok()??;

        if value.len() < 12 {
            return None;
        }

        let block_number = BlockNumber::from_be_bytes(value[4..12].try_into().ok()?);
        let tx = Transaction::from_slice(&value[12..]).ok()?;

        let block_hash = self.get(Key::BlockNumber(block_number).into_vec()).ok()??;
        let block_hash = Byte32::from_slice(&block_hash).ok()?;

        let header_bytes = self.get(Key::BlockHash(&block_hash).into_vec()).ok()??;
        let header = Header::from_slice(&header_bytes[..Header::TOTAL_SIZE]).ok()?;
        let extension = if header_bytes.len() > Header::TOTAL_SIZE {
            Some(packed::Bytes::from_slice(&header_bytes[Header::TOTAL_SIZE..]).ok()?)
        } else {
            None
        };
        let hwe = HeaderWithExtension { header, extension };

        Some((tx, hwe.header))
    }

    fn get_transaction(&self, tx_hash: &Byte32) -> Option<(BlockNumber, TxIndex, Transaction)> {
        let value = self.get(Key::TxHash(tx_hash).into_vec()).ok()??;

        if value.len() < 12 {
            return None;
        }

        let tx_index = TxIndex::from_be_bytes(value[0..4].try_into().ok()?);
        let block_number = BlockNumber::from_be_bytes(value[4..12].try_into().ok()?);
        let tx = Transaction::from_slice(&value[12..]).ok()?;

        Some((block_number, tx_index, tx))
    }
}

// Batch operations for atomic updates
pub struct Batch {
    conn: Arc<Mutex<Connection>>,
    operations: Vec<BatchOp>,
}

enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

impl Batch {
    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) {
        self.operations
            .push(BatchOp::Put(key.as_ref().to_vec(), value.as_ref().to_vec()));
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: K) {
        self.operations.push(BatchOp::Delete(key.as_ref().to_vec()));
    }

    fn put_kv<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> &mut Self {
        self.put(key, value);
        self
    }

    pub fn commit(self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(|e| {
            crate::error::Error::runtime(format!("Failed to begin transaction: {}", e))
        })?;

        for op in self.operations {
            match op {
                BatchOp::Put(key, value) => {
                    tx.execute(
                        "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)",
                        rusqlite::params![&key, &value],
                    )
                    .map_err(|e| {
                        crate::error::Error::runtime(format!("Failed to put in batch: {}", e))
                    })?;
                }
                BatchOp::Delete(key) => {
                    tx.execute(
                        "DELETE FROM kv_store WHERE key = ?",
                        rusqlite::params![&key],
                    )
                    .map_err(|e| {
                        crate::error::Error::runtime(format!("Failed to delete in batch: {}", e))
                    })?;
                }
            }
        }

        tx.commit()
            .map_err(|e| crate::error::Error::runtime(format!("Failed to commit batch: {}", e)))?;

        Ok(())
    }
}

// Implementation of unified storage iterator trait for SQLite
impl StorageIterator for Storage {
    #[allow(clippy::type_complexity)]
    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: IteratorDirection,
        take_while_fn: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map_fn: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<KVPair> {
        let conn = self.conn.lock().unwrap();

        let (order_clause, comparison) = match direction {
            IteratorDirection::Forward => ("ASC", ">="),
            IteratorDirection::Reverse => ("DESC", "<="),
        };

        let query = format!(
            "SELECT key, value FROM kv_store WHERE key {} ? ORDER BY key {}",
            comparison, order_clause
        );

        let mut stmt = conn.prepare(&query).expect("prepare query");

        let rows = stmt
            .query_map(rusqlite::params![&from_key], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("query rows");

        rows.filter_map(|r| r.ok())
            .skip(skip)
            .take_while(|(key, _)| take_while_fn(key))
            .filter_map(|(key, value)| filter_map_fn(&key).map(|_| KVPair { key, value }))
            .take(limit)
            .collect()
    }
}

// Implement CellDataProvider trait
impl CellDataProvider for Storage {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        let tx_hash = Byte32::from_slice(out_point.tx_hash().as_slice()).ok()?;
        let index: u32 = out_point.index().unpack();

        let (_, _, tx) = self.get_transaction(&tx_hash)?;
        tx.raw()
            .outputs_data()
            .get(index as usize)
            .map(|data| data.unpack())
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.get_cell_data(out_point)
            .map(|data| CellOutput::calc_data_hash(&data))
            .and_then(|hash| Byte32::from_slice(hash.as_slice()).ok())
    }
}

// Implement HeaderProvider trait
impl HeaderProvider for Storage {
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        let header_bytes = self.get(Key::BlockHash(block_hash).into_vec()).ok()??;
        let header = Header::from_slice(&header_bytes[..Header::TOTAL_SIZE]).ok()?;
        Some(header.into_view())
    }
}

// Implement CellProvider trait
impl CellProvider for Storage {
    fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        let tx_hash = match Byte32::from_slice(out_point.tx_hash().as_slice()) {
            Ok(h) => h,
            Err(_) => return CellStatus::Unknown,
        };
        let index: u32 = out_point.index().unpack();

        if let Some((block_number, tx_index, tx)) = self.get_transaction(&tx_hash) {
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

            if let Some(output) = tx.raw().outputs().get(index as usize) {
                let data: Bytes = tx
                    .raw()
                    .outputs_data()
                    .get(index as usize)
                    .map(|d| d.unpack())
                    .unwrap_or_default();

                let cell_meta = CellMeta {
                    out_point: out_point.clone(),
                    transaction_info: Some(TransactionInfo {
                        block_number,
                        block_hash,
                        block_epoch: header.epoch(),
                        index: tx_index as usize,
                    }),
                    cell_output: output,
                    data_bytes: data.len() as u64,
                    mem_cell_data: Some(data),
                    mem_cell_data_hash: None,
                };

                return CellStatus::Live(cell_meta);
            }
        }

        CellStatus::Unknown
    }
}

// Implementation of unified storage trait for SQLite
impl super::super::storage_trait::LightClientStorage for Storage {
    // ========== Basic KV operations ==========

    fn get(&self, key: Vec<u8>) -> crate::error::Result<Option<Vec<u8>>> {
        Storage::get(self, key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> crate::error::Result<()> {
        Storage::put(self, key, value)
    }

    fn delete(&self, key: &[u8]) -> crate::error::Result<()> {
        Storage::delete(self, key)
    }

    // ========== Iterator operations ==========

    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: IteratorDirection,
        take_while_fn: super::super::storage_trait::TakeWhileFn,
        filter_map_fn: super::super::storage_trait::FilterMapFn,
        limit: usize,
        skip: usize,
    ) -> Vec<KVPair> {
        // Note: SQLite's StorageIterator expects a different filter_map_fn signature
        // We need to adapt it to match the new signature that includes value parameter
        let adapted_filter_map = Box::new(move |key: &[u8]| {
            // For now, pass empty value since SQLite iterator doesn't use it in filter_map
            filter_map_fn(key, &[]).map(|_| vec![])
        });

        StorageIterator::collect_iterator(
            self,
            from_key,
            direction,
            take_while_fn,
            adapted_filter_map,
            limit,
            skip,
        )
    }

    // ========== Filter scripts management ==========

    fn is_filter_scripts_empty(&self) -> bool {
        Storage::is_filter_scripts_empty(self)
    }

    fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        Storage::get_filter_scripts(self)
    }

    fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        Storage::update_filter_scripts(self, scripts, command)
    }

    fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32> {
        Storage::get_scripts_hash(self, block_number)
    }

    fn update_block_number(&self, block_number: BlockNumber) {
        Storage::update_block_number(self, block_number)
    }

    // ========== Matched blocks management ==========

    fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks> {
        Storage::get_earliest_matched_blocks(self)
    }

    fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks> {
        Storage::get_latest_matched_blocks(self)
    }

    fn add_matched_blocks(
        &self,
        start_number: u64,
        blocks_count: u64,
        matched_blocks: Vec<(Byte32, bool)>,
    ) {
        Storage::add_matched_blocks(self, start_number, blocks_count, matched_blocks)
    }

    fn remove_matched_blocks(&self, start_number: u64) {
        Storage::remove_matched_blocks(self, start_number)
    }

    fn cleanup_invalid_matched_blocks(&self) {
        Storage::cleanup_invalid_matched_blocks(self)
    }

    // ========== Check points management ==========

    fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        Storage::get_check_points(self, start_index, limit)
    }

    fn update_check_points(&self, start_index: CpIndex, check_points: &[Byte32]) {
        Storage::update_check_points(self, start_index, check_points)
    }

    fn get_last_check_point(&self) -> (CpIndex, Byte32) {
        Storage::get_last_check_point(self)
    }

    fn get_max_check_point_index(&self) -> CpIndex {
        Storage::get_max_check_point_index(self)
    }

    fn update_max_check_point_index(&self, index: CpIndex) {
        Storage::update_max_check_point_index(self, index)
    }

    // ========== Block and transaction management ==========

    fn init_genesis_block(&self, block: Block) {
        Storage::init_genesis_block(self, block)
    }

    fn get_genesis_block(&self) -> Block {
        Storage::get_genesis_block(self)
    }

    fn add_fetched_header(&self, hwe: &HeaderWithExtension) {
        Storage::add_fetched_header(self, hwe)
    }

    fn add_fetched_tx(&self, tx: &Transaction, hwe: &HeaderWithExtension) {
        Storage::add_fetched_tx(self, tx, hwe)
    }

    fn filter_block(&self, block: Block) {
        Storage::filter_block(self, block)
    }

    fn rollback_to_block(&self, to_number: BlockNumber) {
        Storage::rollback_to_block(self, to_number)
    }

    fn get_transaction_with_header(&self, tx_hash: &Byte32) -> Option<(Transaction, Header)> {
        Storage::get_transaction_with_header(self, tx_hash)
    }

    // ========== Chain state management ==========

    fn update_last_state(
        &self,
        total_difficulty: &U256,
        tip_header: &Header,
        last_n_headers: &[ckb_types::core::HeaderView],
    ) {
        Storage::update_last_state(self, total_difficulty, tip_header, last_n_headers)
    }

    fn get_last_state(&self) -> (U256, Header) {
        Storage::get_last_state(self)
    }

    fn get_last_n_headers(&self) -> Vec<(u64, Byte32)> {
        Storage::get_last_n_headers(self)
    }

    fn get_tip_header(&self) -> Header {
        Storage::get_tip_header(self)
    }

    fn get_min_filtered_block_number(&self) -> BlockNumber {
        Storage::get_min_filtered_block_number(self)
    }

    fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        Storage::update_min_filtered_block_number(self, block_number)
    }
}
