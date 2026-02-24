use super::super::backend::{BatchWriter, FilterMapFn, StorageBackend, TakeWhileFn};
use super::super::storage_trait::LightClientStorage;
use super::super::{Byte32, Key};
use super::iterator::{IteratorDirection, IteratorStart, KVPair};
use crate::error::Result;
use ckb_types::{
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        TransactionInfo,
    },
    packed::{CellOutput, Header, OutPoint},
    prelude::*,
};
use rocksdb::{
    ops::Delete,
    prelude::{Get, Iterate, Open, Put, WriteOps},
    Direction, IteratorMode, Options, Snapshot, WriteBatch, DB,
};
use std::{path::Path, sync::Arc};

impl From<IteratorDirection> for Direction {
    fn from(dir: IteratorDirection) -> Self {
        match dir {
            IteratorDirection::Forward => Direction::Forward,
            IteratorDirection::Reverse => Direction::Reverse,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    pub(crate) db: Arc<DB>,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_total_wal_size(128 * 1024 * 1024);
        opts.set_write_buffer_size(128 * 1024 * 1024);
        opts.set_max_write_buffer_number(2);
        let db = Arc::new(DB::open(&opts, path).expect("Failed to open rocksdb"));
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

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key.as_ref())
            .map(|v| v.map(|vi| vi.to_vec()))
            .map_err(Into::into)
    }
}

pub struct Batch {
    db: Arc<DB>,
    wb: WriteBatch,
}

// Implement BatchWriter trait for Batch
impl BatchWriter for Batch {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.wb.put(key, value).expect("batch put should be ok");
    }

    fn delete(&mut self, key: &[u8]) {
        self.wb.delete(key).expect("batch delete should be ok");
    }

    fn commit(self) -> Result<()> {
        self.db.write(&self.wb)?;
        Ok(())
    }
}

// Implementation of StorageBackend trait for RocksDB
impl StorageBackend for Storage {
    type Batch = Batch;

    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key.as_slice())
            .map(|v| v.map(|vi| vi.to_vec()))
            .map_err(Into::into)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.db.put(key, value).map_err(Into::into)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.db.delete(key).map_err(Into::into)
    }

    fn batch(&self) -> Self::Batch {
        Storage::batch(self)
    }

    fn collect_iterator(
        &self,
        start: IteratorStart,
        direction: IteratorDirection,
        take_while_fn: TakeWhileFn,
        filter_map_fn: FilterMapFn,
        limit: usize,
    ) -> Vec<KVPair> {
        let rocksdb_direction: Direction = direction.into();
        let mode = IteratorMode::From(start.key(), rocksdb_direction);
        let snapshot = self.snapshot();

        let skip = if start.should_skip_first() { 1 } else { 0 };

        snapshot
            .iterator(mode)
            .skip(skip)
            .take_while(|(key, _)| take_while_fn(key))
            .filter_map(|(key, value)| {
                filter_map_fn(&key, &value).map(|transformed_value| KVPair {
                    key: key.to_vec(),
                    value: transformed_value,
                })
            })
            .take(limit)
            .collect()
    }
}

// Implementation of LightClientStorage trait for RocksDB
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
