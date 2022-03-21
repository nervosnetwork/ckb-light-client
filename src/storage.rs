use std::{cell::RefCell, collections::HashMap, path::Path, str::FromStr};

use ckb_types::{
    core::{BlockView, TransactionView},
    packed,
    prelude::*,
};
use rocksdb::ops::{
    DeleteCF as _, Get as _, GetCF as _, GetColumnFamilys as _, IterateCF as _, OpenCF as _,
    Put as _, PutCF as _,
};

use crate::{
    error::{Error, Result},
    utils,
};

const KEY_METADATA: &[u8] = b"meta_data";

pub(crate) struct Storage {
    db: rocksdb::DB,
}

// Construction
impl Storage {
    // Only store those blocks which are not in main chain.
    const CF_HEADERS: &'static str = "headers";

    const CF_NAMES: &'static [&'static str] = &[Self::CF_HEADERS];

    pub(crate) fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Self::open(path, true)?;
        let ret = Self { db };
        Ok(ret)
    }

    fn open<P: AsRef<Path>>(path: P, create: bool) -> Result<rocksdb::DB> {
        let opts = Self::default_dboptions(create);
        let cfs = Self::default_column_family_descriptors();
        let db = rocksdb::DB::open_cf_descriptors(&opts, &path, cfs)?;
        Ok(db)
    }

    fn default_dboptions(create: bool) -> rocksdb::Options {
        let mut opts = rocksdb::Options::default();
        if create {
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
        } else {
            opts.create_if_missing(false);
            opts.create_missing_column_families(false);
        }
        // DBOptions
        opts.set_bytes_per_sync(1 << 20);
        // TODO RocksDB API
        opts.set_max_background_compactions(2);
        opts.set_max_background_flushes(2);
        // opts.set_max_background_jobs(4);
        opts.set_max_total_wal_size((1 << 20) * 64);
        opts.set_keep_log_file_num(64);
        opts.set_max_open_files(64);
        // CFOptions "default"
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_write_buffer_size((1 << 20) * 8);
        opts.set_min_write_buffer_number_to_merge(1);
        opts.set_max_write_buffer_number(2);
        // TODO RocksDB API
        // opts.set_max_write_buffer_size_to_maintain(-1);
        // [TableOptions/BlockBasedTable "default"]
        let block_opts = {
            let mut block_opts = rocksdb::BlockBasedOptions::default();
            block_opts.set_cache_index_and_filter_blocks(true);
            block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
            block_opts
        };

        opts.set_block_based_table_factory(&block_opts);

        opts
    }

    fn default_cfoptions() -> rocksdb::Options {
        let mut opts = rocksdb::Options::default();
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_write_buffer_size((1 << 20) * 8);
        opts.set_min_write_buffer_number_to_merge(1);
        opts.set_max_write_buffer_number(2);
        // TODO RocksDB API
        // opts.set_max_write_buffer_size_to_maintain(-1);
        opts
    }

    fn default_column_family_descriptors() -> Vec<rocksdb::ColumnFamilyDescriptor> {
        let cfopts = Self::default_cfoptions();
        Self::CF_NAMES
            .iter()
            .map(|name| rocksdb::ColumnFamilyDescriptor::new(name.to_owned(), cfopts.clone()))
            .collect()
    }
}

// Common
impl Storage {
    fn cf_handle(&self, cf_name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db.cf_handle(cf_name).ok_or_else(|| {
            let errmsg = format!("column family {} should exists", cf_name);
            Error::storage(errmsg)
        })
    }
}

// CF: Headers
impl Storage {
    /* TODO
    fn put_pending_tx(&self, tx_hash: packed::Byte32) -> Result<()> {
        let cf = self.cf_handle(Self::CF_PENDING_TXS)?;
        self.db.put_cf(cf, tx_hash.as_slice(), &[])?;
        Ok(())
    }

    fn has_pending_tx(&self, tx_hash: &packed::Byte32) -> Result<bool> {
        let cf = self.cf_handle(Self::CF_PENDING_TXS)?;
        let had = self.db.get_cf(cf, tx_hash.as_slice())?.is_some();
        Ok(had)
    }

    fn delete_pending_tx(&self, tx_hash: &packed::Byte32) -> Result<()> {
        let cf = self.cf_handle(Self::CF_PENDING_TXS)?;
        self.db
            .delete_cf(cf, tx_hash.as_slice())
            .map_err(Into::into)
    }
    */
}
