use super::super::{Byte32, Key};
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
use rocksdb::{
    ops::Delete,
    prelude::{Get, Iterate, Open, Put, WriteOps},
    DBPinnableSlice, Direction, IteratorMode, Snapshot, WriteBatch, DB,
};
use std::{path::Path, sync::Arc};
pub enum CursorDirection {
    Next,
    NextUnique,
    Prev,
    PrevUnique,
}
/// Represent a key-value pair
pub struct KV {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

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

    pub fn batch(&self) -> Batch {
        Batch {
            db: Arc::clone(&self.db),
            wb: WriteBatch::default(),
        }
    }

    pub fn snapshot(&self) -> Snapshot<'_> {
        self.db.snapshot()
    }

    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
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

    pub fn get_pinned<K>(&self, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        self.get(key)
    }

    pub fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        self.db.delete(key).map_err(Into::into)
    }
    /// filter_map is not used on RocksDB implementation
    #[allow(clippy::type_complexity)]
    pub fn collect_iterator(
        &self,
        start_key_bound: Vec<u8>,
        order: CursorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        _filter_map: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<KV> {
        let mode = match order {
            CursorDirection::NextUnique => IteratorMode::From(&start_key_bound, Direction::Forward),
            CursorDirection::PrevUnique => IteratorMode::From(&start_key_bound, Direction::Reverse),
            _ => panic!("Unsupported order"),
        };

        self.db
            .get_iter(
                &{
                    let mut opts = rocksdb::ReadOptions::default();
                    opts.set_prefix_same_as_start(true);
                    opts
                },
                mode,
            )
            .take_while(|(key, _)| take_while(key))
            .take(limit)
            .skip(skip)
            .map(|(key, value)| KV {
                key: key.to_vec(),
                value: value.to_vec(),
            })
            .collect::<Vec<_>>()
    }
    #[allow(clippy::type_complexity)]
    pub fn collect_iterator_key(
        &self,
        start_key_bound: Vec<u8>,
        order: CursorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        _filter_map: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<Vec<u8>> {
        let mode = match order {
            CursorDirection::NextUnique => IteratorMode::From(&start_key_bound, Direction::Forward),
            CursorDirection::PrevUnique => IteratorMode::From(&start_key_bound, Direction::Reverse),
            _ => panic!("Unsupported order"),
        };

        self.db
            .get_iter(
                &{
                    let mut opts = rocksdb::ReadOptions::default();
                    opts.set_prefix_same_as_start(true);
                    opts
                },
                mode,
            )
            .take_while(|(key, _)| take_while(key))
            .take(limit)
            .skip(skip)
            .map(|(key, _)| key.to_vec())
            .collect::<Vec<_>>()
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

pub struct Batch {
    db: Arc<DB>,
    wb: WriteBatch,
}

impl Batch {
    pub fn put_kv<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) -> Result<()> {
        self.put(Into::<Vec<u8>>::into(key), Into::<Vec<u8>>::into(value))
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<()> {
        self.wb.put(key, value)?;
        Ok(())
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<()> {
        self.wb.delete(key.as_ref())?;
        Ok(())
    }

    pub fn commit(self) -> Result<()> {
        self.db.write(&self.wb)?;
        Ok(())
    }
}
