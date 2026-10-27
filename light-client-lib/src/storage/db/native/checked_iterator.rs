//! The pinned RocksDB Rust iterator hides its terminal error status. Use the
//! exported C API and public handles, without depending on private Rust layouts.
use crate::{
    error::{Error, Result},
    storage::IteratorDirection,
};
use rocksdb::{ffi, Handle, ReadOptions, Snapshot, DB};
use std::{
    marker::PhantomData,
    ptr::{self, NonNull},
    slice,
};

pub(super) struct CheckedIterator<'snapshot> {
    inner: NonNull<ffi::rocksdb_iterator_t>,
    // Both constructor inputs, including a separately supplied database, must
    // outlive this iterator. Callers use a snapshot from that same database.
    _snapshot: PhantomData<&'snapshot ()>,
}

impl<'snapshot> CheckedIterator<'snapshot> {
    pub(super) fn new(db: &'snapshot DB, snapshot: &'snapshot Snapshot<'_>) -> Result<Self> {
        Self::with_options(db, snapshot, ReadOptions::default())
    }

    fn with_options(
        db: &'snapshot DB,
        snapshot: &'snapshot Snapshot<'_>,
        mut options: ReadOptions,
    ) -> Result<Self> {
        options.set_snapshot(snapshot);
        // SAFETY: these public handles belong to live objects. RocksDB copies
        // read options at iterator creation; the borrowed snapshot stays alive.
        let inner = unsafe { ffi::rocksdb_create_iterator(db.handle(), options.handle()) };
        Ok(Self {
            inner: NonNull::new(inner)
                .ok_or_else(|| Error::runtime("failed to create RocksDB iterator"))?,
            _snapshot: PhantomData,
        })
    }

    pub(super) fn seek(&mut self, key: &[u8], direction: IteratorDirection) {
        // SAFETY: the iterator is live; RocksDB only borrows key for this call.
        unsafe {
            match direction {
                IteratorDirection::Forward => {
                    ffi::rocksdb_iter_seek(self.inner.as_ptr(), key.as_ptr().cast(), key.len())
                }
                IteratorDirection::Reverse => ffi::rocksdb_iter_seek_for_prev(
                    self.inner.as_ptr(),
                    key.as_ptr().cast(),
                    key.len(),
                ),
            }
        }
    }

    pub(super) fn row(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        // SAFETY: the iterator is live. Borrowed key/value buffers are copied
        // before any seek/advance can invalidate them.
        unsafe {
            if ffi::rocksdb_iter_valid(self.inner.as_ptr()) == 0 {
                let mut error = ptr::null_mut();
                ffi::rocksdb_iter_get_error(self.inner.as_ptr(), &mut error);
                if !error.is_null() {
                    // This library helper converts and frees the C error string.
                    return Err(rocksdb::Error::new(rocksdb::ffi_util::error_message(error)).into());
                }
                return Ok(None);
            }
            let (mut key_len, mut value_len) = (0, 0);
            let key = ffi::rocksdb_iter_key(self.inner.as_ptr(), &mut key_len);
            let value = ffi::rocksdb_iter_value(self.inner.as_ptr(), &mut value_len);
            if (key.is_null() && key_len != 0) || (value.is_null() && value_len != 0) {
                return Err(Error::runtime("invalid RocksDB iterator buffers"));
            }
            let key = if key_len == 0 {
                Vec::new()
            } else {
                slice::from_raw_parts(key.cast(), key_len).to_vec()
            };
            let value = if value_len == 0 {
                Vec::new()
            } else {
                slice::from_raw_parts(value.cast(), value_len).to_vec()
            };
            Ok(Some((key, value)))
        }
    }

    pub(super) fn advance(&mut self, direction: IteratorDirection) {
        // SAFETY: callers advance only after observing a valid row.
        unsafe {
            match direction {
                IteratorDirection::Forward => ffi::rocksdb_iter_next(self.inner.as_ptr()),
                IteratorDirection::Reverse => ffi::rocksdb_iter_prev(self.inner.as_ptr()),
            }
        }
    }
}

impl Drop for CheckedIterator<'_> {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the live C iterator.
        unsafe { ffi::rocksdb_iter_destroy(self.inner.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::prelude::Open;

    #[test]
    fn iterator_error_is_distinct_from_normal_exhaustion() {
        let directory = tempfile::tempdir().unwrap();
        let db = DB::open_default(directory.path()).unwrap();
        let snapshot = db.snapshot();
        let mut empty = CheckedIterator::new(&db, &snapshot).unwrap();
        empty.seek(&[], IteratorDirection::Forward);
        assert!(empty.row().unwrap().is_none());

        let options = ReadOptions::default();
        // SAFETY: options is live. Read tier 2 is RocksDB's kPersistedTier,
        // explicitly unsupported for iterators; it creates a real error iterator.
        unsafe { ffi::rocksdb_readoptions_set_read_tier(options.handle(), 2) };
        let mut failed = CheckedIterator::with_options(&db, &snapshot, options).unwrap();
        failed.seek(&[], IteratorDirection::Forward);
        let error = failed
            .row()
            .err()
            .expect("error iterator must not look empty");
        assert!(error.to_string().contains("kPersistedData"), "{error}");
    }
}
