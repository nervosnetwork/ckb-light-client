use super::*;
use rocksdb::{ops::Flush, BlockBasedOptions, DBCompressionType};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicUsize, Ordering},
};

#[test]
fn checked_scan_propagates_real_corruption_after_a_valid_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let mut options = Options::default();
    options.create_if_missing(true);
    options.set_compression_type(DBCompressionType::None);
    options.set_disable_auto_compactions(true);
    let mut blocks = BlockBasedOptions::default();
    blocks.set_block_size(1024);
    options.set_block_based_table_factory(&blocks);
    {
        let db = DB::open(&options, directory.path()).unwrap();
        for key in 0..32u8 {
            db.put([key], [key; 4096]).unwrap();
        }
        db.flush().unwrap();
    }
    // Damage a middle data block, leaving the index/footer and both ends
    // readable. Closing before the write avoids a cached healthy block.
    let tables: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sst"))
        .collect();
    assert_eq!(tables.len(), 1);
    let mut table = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tables[0])
        .unwrap();
    table.seek(SeekFrom::Start(70_000)).unwrap();
    let mut byte = [0];
    table.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xff;
    table.seek(SeekFrom::Start(70_000)).unwrap();
    table.write_all(&byte).unwrap();
    table.sync_all().unwrap();
    drop(table);

    let storage = Storage {
        db: Arc::new(DB::open(&options, directory.path()).unwrap()),
    };
    for direction in [IteratorDirection::Forward, IteratorDirection::Reverse] {
        let start = IteratorStart::From(match direction {
            IteratorDirection::Forward => vec![0],
            IteratorDirection::Reverse => vec![31],
        });
        // An intentional one-row page must not advance into later errors.
        assert_eq!(
            storage
                .try_collect_iterator(
                    start.clone(),
                    direction,
                    Box::new(|_| true),
                    Box::new(|_, value| Some(value.to_vec())),
                    1
                )
                .unwrap()
                .len(),
            1
        );
        for _ in 0..2 {
            let seen = Arc::new(AtomicUsize::new(0));
            let callback_seen = seen.clone();
            let result = storage.try_collect_iterator(
                start.clone(),
                direction,
                Box::new(|_| true),
                Box::new(move |_, value| {
                    callback_seen.fetch_add(1, Ordering::SeqCst);
                    Some(value.to_vec())
                }),
                100,
            );
            let error = result
                .err()
                .expect("corruption must not become successful truncation");
            assert!(
                error.to_string().to_lowercase().contains("corruption"),
                "{error}"
            );
            let count = seen.load(Ordering::SeqCst);
            assert!(
                count > 0 && count < 32,
                "must fail after a valid prefix: {count}"
            );
            println!("real SST corruption {direction:?}: {count} rows before Err: {error}");
        }
    }
}
