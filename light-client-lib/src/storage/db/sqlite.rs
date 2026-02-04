// SQLite storage backend for CKB Light Client
// This implementation provides the same interface as RocksDB but uses SQLite as the underlying storage

use super::super::backend::{BatchWriter, FilterMapFn, StorageBackend, TakeWhileFn};
use super::super::storage_trait::LightClientStorage;
use super::super::{Byte32, Key};
use super::iterator::{IteratorDirection, KVPair};
use crate::error::Result;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        HeaderView, TransactionInfo,
    },
    packed::{CellOutput, Header, OutPoint},
    prelude::*,
};
use rusqlite::{Connection, OpenFlags};
use std::{
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
}

pub struct Batch {
    conn: Arc<Mutex<Connection>>,
    operations: Vec<BatchOp>,
}

enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

// Implement BatchWriter trait for Batch
impl BatchWriter for Batch {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.operations
            .push(BatchOp::Put(key.to_vec(), value.to_vec()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.operations.push(BatchOp::Delete(key.to_vec()));
    }

    fn commit(self: Box<Self>) -> Result<()> {
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

// Implementation of StorageBackend trait for SQLite
impl StorageBackend for Storage {
    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Storage::get(self, key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)",
            rusqlite::params![key.as_slice(), value.as_slice()],
        )
        .map_err(|e| crate::error::Error::runtime(format!("Failed to put: {}", e)))?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM kv_store WHERE key = ?", rusqlite::params![key])
            .map_err(|e| crate::error::Error::runtime(format!("Failed to delete: {}", e)))?;
        Ok(())
    }

    fn batch(&self) -> Box<dyn BatchWriter> {
        Box::new(Storage::batch(self))
    }

    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: IteratorDirection,
        take_while_fn: TakeWhileFn,
        filter_map_fn: FilterMapFn,
        skip: usize,
        limit: usize,
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
            .filter_map(|(key, value)| {
                filter_map_fn(&key, &value).map(|transformed_value| KVPair {
                    key,
                    value: transformed_value,
                })
            })
            .take(limit)
            .collect()
    }
}

// Implementation of LightClientStorage trait for SQLite
// All methods use default implementations from the trait
impl LightClientStorage for Storage {}

impl CellProvider for Storage {
    // assume all cells are live and load data eagerly
    fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        if let Some((block_number, tx_index, tx)) = self.get_transaction(&out_point.tx_hash()) {
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
    // we load all cells data eagerly in Storage's CellProvider impl
    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<Bytes> {
        unreachable!()
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        unreachable!()
    }
}

impl HeaderProvider for Storage {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        LightClientStorage::get_header(self, hash)
    }
}
