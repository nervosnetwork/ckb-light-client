//! Backend-only contracts; these fixtures do not rely on canonical-state metadata.
#![cfg(not(target_arch = "wasm32"))]
use ckb_light_client_lib::{
    error::Result,
    storage::{
        BatchWriter, FilterMapFn, IteratorDirection, IteratorStart, KVPair, Storage,
        StorageBackend, TakeWhileFn,
    },
};
use std::sync::{Arc, Barrier};

fn maintainer_boundaries(checked: bool) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let keys = vec![
        vec![],
        vec![10],
        vec![20],
        vec![20, 0],
        vec![20, 0, 0],
        vec![20, 1],
        vec![20, 255],
        vec![30],
        vec![255],
    ];
    for key in &keys {
        storage.put(key.clone(), key.clone()).unwrap();
    }
    let mut cases = 0;
    for boundary in [
        vec![],
        vec![0],
        vec![10],
        vec![15],
        vec![20],
        vec![20, 0],
        vec![20, 0, 1],
        vec![20, 254],
        vec![25],
        vec![30],
        vec![255],
        vec![255, 0],
    ] {
        for direction in [IteratorDirection::Forward, IteratorDirection::Reverse] {
            for exclusive in [false, true] {
                for limit in [0, 1, 2, 100] {
                    let start = if exclusive {
                        IteratorStart::After(boundary.clone())
                    } else {
                        IteratorStart::From(boundary.clone())
                    };
                    let mut expected = keys
                        .iter()
                        .filter(|key| match (direction, exclusive) {
                            (IteratorDirection::Forward, false) => *key >= &boundary,
                            (IteratorDirection::Forward, true) => *key > &boundary,
                            (IteratorDirection::Reverse, false) => *key <= &boundary,
                            (IteratorDirection::Reverse, true) => *key < &boundary,
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if direction == IteratorDirection::Reverse {
                        expected.reverse();
                    }
                    expected.truncate(limit);
                    let rows = if checked {
                        storage
                            .try_collect_iterator(
                                start,
                                direction,
                                Box::new(|_| true),
                                Box::new(|_, v| Some(v.to_vec())),
                                limit,
                            )
                            .unwrap()
                    } else {
                        storage.collect_iterator(
                            start,
                            direction,
                            Box::new(|_| true),
                            Box::new(|_, v| Some(v.to_vec())),
                            limit,
                        )
                    };
                    let actual = rows
                        .into_iter()
                        .map(|row| {
                            assert_eq!(row.key, row.value);
                            row.key
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(actual,expected,"checked={checked} boundary={boundary:?} direction={direction:?} exclusive={exclusive} limit={limit}");
                    cases += 1;
                }
            }
        }
    }
    println!("cross-backend boundary contract checked={checked}: {cases} cases");
}
#[test]
fn maintainer_legacy_after_missing_boundary() {
    maintainer_boundaries(false);
}
#[test]
fn maintainer_checked_after_missing_boundary() {
    maintainer_boundaries(true);
}

#[test]
fn binary_prefix_pages_continue_at_exact_boundaries_in_both_modes() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let keys = vec![
        vec![0],
        vec![0, 0],
        vec![0, 0, 0],
        vec![0, 1],
        vec![0, 255],
        vec![1],
        vec![255],
        vec![255, 0],
    ];
    for checked in [false, true] {
        for direction in [IteratorDirection::Forward, IteratorDirection::Reverse] {
            let scan = |start| {
                if checked {
                    storage
                        .try_collect_iterator(
                            start,
                            direction,
                            Box::new(|_| true),
                            Box::new(|_, value| Some(value.to_vec())),
                            2,
                        )
                        .unwrap()
                } else {
                    storage.collect_iterator(
                        start,
                        direction,
                        Box::new(|_| true),
                        Box::new(|_, value| Some(value.to_vec())),
                        2,
                    )
                }
            };
            // Explicit exclusive bounds on an empty database.
            assert!(scan(IteratorStart::After(vec![0, 0])).is_empty());
        }
    }
    for key in &keys {
        storage.put(key.clone(), key.clone()).unwrap();
    }
    for checked in [false, true] {
        for direction in [IteratorDirection::Forward, IteratorDirection::Reverse] {
            let mut start = IteratorStart::From(match direction {
                IteratorDirection::Forward => vec![],
                IteratorDirection::Reverse => vec![255, 255],
            });
            let mut actual = Vec::new();
            for page in 0..5 {
                let rows = if checked {
                    storage
                        .try_collect_iterator(
                            start,
                            direction,
                            Box::new(|_| true),
                            Box::new(|_, value| Some(value.to_vec())),
                            2,
                        )
                        .unwrap()
                } else {
                    storage.collect_iterator(
                        start,
                        direction,
                        Box::new(|_| true),
                        Box::new(|_, value| Some(value.to_vec())),
                        2,
                    )
                };
                assert_eq!(rows.len(), if page == 4 { 0 } else { 2 });
                if rows.is_empty() {
                    break;
                }
                start = IteratorStart::After(rows.last().unwrap().key.clone());
                actual.extend(rows.into_iter().map(|row| {
                    assert_eq!(row.key, row.value);
                    row.key
                }));
            }
            let mut expected = keys.clone();
            if direction == IteratorDirection::Reverse {
                expected.reverse();
            }
            assert_eq!(actual, expected);
        }
    }
}

fn rows(
    storage: &Storage,
    start: IteratorStart,
    direction: IteratorDirection,
    limit: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    storage
        .try_collect_iterator(
            start,
            direction,
            Box::new(|key| key.starts_with(&[250])),
            Box::new(|_, value| Some(value.to_vec())),
            limit,
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.key, row.value))
        .collect()
}

#[test]
fn multikey_order_duplicates_missing_and_empty_values_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    storage.put(vec![], vec![]).unwrap();
    storage.put(vec![250, 2], vec![22]).unwrap();
    let keys = vec![vec![250, 2], vec![250, 1], vec![], vec![250, 2]];
    let expected = vec![Some(vec![22]), None, Some(vec![]), Some(vec![22])];
    assert_eq!(storage.get_many(&keys).unwrap(), expected);
    assert!(storage.get_many(&[]).unwrap().is_empty());
    let scanned = storage
        .try_collect_iterator(
            IteratorStart::From(vec![]),
            IteratorDirection::Forward,
            Box::new(|_| true),
            Box::new(|_, value| Some(value.to_vec())),
            10,
        )
        .unwrap();
    assert_eq!(scanned.len(), 2);
    assert!(scanned[0].key.is_empty());
    assert!(scanned[0].value.is_empty());
    drop(storage);
    let reopened = Storage::new(directory.path());
    assert_eq!(reopened.get_many(&keys).unwrap(), expected);
}

#[test]
fn multikey_snapshot_never_mixes_concurrent_batch_generations() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let mut initial = storage.batch();
    initial.put(&[250, 1], &0u64.to_be_bytes());
    initial.put(&[250, 2], &0u64.to_be_bytes());
    initial.commit().unwrap();
    let ready = Arc::new(Barrier::new(2));
    let writer_ready = ready.clone();
    let writer = storage.clone();
    let handle = std::thread::spawn(move || {
        writer_ready.wait();
        for generation in 1..=400u64 {
            let mut batch = writer.batch();
            batch.put(&[250, 1], &generation.to_be_bytes());
            batch.put(&[250, 2], &generation.to_be_bytes());
            batch.commit().unwrap();
            std::thread::yield_now();
        }
    });
    // A long repeated-key read makes accidental per-key snapshots observable.
    let keys: Vec<_> = (0..128)
        .flat_map(|_| [vec![250, 1], vec![250, 2], vec![250, 3], vec![250, 1]])
        .collect();
    ready.wait();
    for _ in 0..40 {
        let values = storage.get_many(&keys).unwrap();
        assert_eq!(values.len(), keys.len());
        for group in values.chunks_exact(4) {
            assert_eq!(group[0], values[0], "one read mixed batch generations");
            assert_eq!(group[1], values[0]);
            assert_eq!(group[2], None);
            assert_eq!(group[3], values[0]);
        }
    }
    handle.join().unwrap();
    assert_eq!(
        storage.get_many(&[vec![250, 1], vec![250, 2]]).unwrap(),
        vec![Some(400u64.to_be_bytes().to_vec()); 2]
    );
}

#[test]
fn checked_scan_orders_filters_limits_and_handles_exclusive_missing_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    for key in [10, 20, 30] {
        storage.put(vec![250, key], vec![key]).unwrap();
    }
    storage.put(vec![251, 0], vec![99]).unwrap();
    let values = |rows: Vec<(Vec<u8>, Vec<u8>)>| {
        rows.into_iter()
            .map(|(_, value)| value[0])
            .collect::<Vec<_>>()
    };
    assert_eq!(
        values(rows(
            &storage,
            IteratorStart::From(vec![250, 10]),
            IteratorDirection::Forward,
            10
        )),
        vec![10, 20, 30]
    );
    assert_eq!(
        values(rows(
            &storage,
            IteratorStart::After(vec![250, 10]),
            IteratorDirection::Forward,
            10
        )),
        vec![20, 30]
    );
    assert_eq!(
        values(rows(
            &storage,
            IteratorStart::After(vec![250, 15]),
            IteratorDirection::Forward,
            10
        )),
        vec![20, 30]
    );
    assert_eq!(
        values(rows(
            &storage,
            IteratorStart::After(vec![250, 25]),
            IteratorDirection::Reverse,
            10
        )),
        vec![20, 10]
    );
    assert_eq!(
        values(rows(
            &storage,
            IteratorStart::From(vec![250, 30]),
            IteratorDirection::Reverse,
            2
        )),
        vec![30, 20]
    );
    assert!(rows(
        &storage,
        IteratorStart::From(vec![250, 40]),
        IteratorDirection::Forward,
        10
    )
    .is_empty());
    assert!(rows(
        &storage,
        IteratorStart::From(vec![250, 0]),
        IteratorDirection::Reverse,
        10
    )
    .is_empty());
    let filtered = storage
        .try_collect_iterator(
            IteratorStart::From(vec![250]),
            IteratorDirection::Forward,
            Box::new(|key| key.starts_with(&[250])),
            Box::new(|_, value| (value[0] != 10).then(|| vec![value[0] + 1])),
            1,
        )
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].key, vec![250, 20]);
    assert_eq!(filtered[0].value, vec![21]);
    assert!(storage
        .try_collect_iterator(
            IteratorStart::From(vec![]),
            IteratorDirection::Forward,
            Box::new(|_| panic!("zero limit must not invoke a callback")),
            Box::new(|_, _| panic!("zero limit")),
            0
        )
        .unwrap()
        .is_empty());
}

#[test]
fn scan_values_share_a_snapshot_and_filter_callback_can_read_storage() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    storage.put(vec![250, 1], vec![1]).unwrap();
    storage.put(vec![250, 2], vec![1]).unwrap();
    let callback = storage.clone();
    let result = storage
        .try_collect_iterator(
            IteratorStart::From(vec![250]),
            IteratorDirection::Forward,
            Box::new(|key| key.starts_with(&[250])),
            Box::new(move |key, value| {
                assert!(callback.get(key).unwrap().is_some());
                if key == [250, 1] {
                    callback.put(vec![250, 2], vec![2]).unwrap();
                }
                Some(value.to_vec())
            }),
            10,
        )
        .unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].value, vec![1]);
    assert_eq!(
        result[1].value,
        vec![1],
        "scan followed a callback write into a later generation"
    );
    assert_eq!(storage.get(vec![250, 2]).unwrap(), Some(vec![2]));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_decode_errors_return_errors_and_leave_the_connection_usable() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    storage.put(vec![250, 1], vec![1]).unwrap();
    let external = rusqlite::Connection::open(directory.path().join("db.sqlite")).unwrap();
    external
        .execute(
            "INSERT INTO kv_store (key, value) VALUES (X'FA02', 'invalid blob')",
            [],
        )
        .unwrap();
    assert!(storage.get_many(&[vec![250, 1], vec![250, 2]]).is_err());
    let result = storage.try_collect_iterator(
        IteratorStart::From(vec![250]),
        IteratorDirection::Forward,
        Box::new(|key| key.starts_with(&[250])),
        Box::new(|_, value| Some(value.to_vec())),
        10,
    );
    assert!(
        result.is_err(),
        "a decode failure after a valid row must not become a short page"
    );
    external
        .execute("DELETE FROM kv_store WHERE key = X'FA02'", [])
        .unwrap();
    assert_eq!(
        storage.get_many(&[vec![250, 1], vec![250, 2]]).unwrap(),
        vec![Some(vec![1]), None]
    );
    external
        .execute("ALTER TABLE kv_store RENAME TO unavailable", [])
        .unwrap();
    assert!(storage.get_many(&[vec![250, 1]]).is_err());
    assert!(storage
        .try_collect_iterator(
            IteratorStart::From(vec![250]),
            IteratorDirection::Forward,
            Box::new(|_| true),
            Box::new(|_, value| Some(value.to_vec())),
            10
        )
        .is_err());
    external
        .execute("ALTER TABLE unavailable RENAME TO kv_store", [])
        .unwrap();
    assert_eq!(
        rows(
            &storage,
            IteratorStart::From(vec![250]),
            IteratorDirection::Forward,
            10
        )
        .len(),
        1
    );
}

// A third-party backend that implements ONLY the preexisting trait methods.
struct LegacyBackend;
struct LegacyBatch;
impl BatchWriter for LegacyBatch {
    fn put(&mut self, _: &[u8], _: &[u8]) {}
    fn delete(&mut self, _: &[u8]) {}
    fn commit(self) -> Result<()> {
        Ok(())
    }
}
impl StorageBackend for LegacyBackend {
    type Batch = LegacyBatch;
    fn get(&self, _: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(Some(vec![7]))
    }
    fn put(&self, _: Vec<u8>, _: Vec<u8>) -> Result<()> {
        Ok(())
    }
    fn delete(&self, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn batch(&self) -> Self::Batch {
        LegacyBatch
    }
    fn collect_iterator(
        &self,
        _: IteratorStart,
        _: IteratorDirection,
        _: TakeWhileFn,
        _: FilterMapFn,
        _: usize,
    ) -> Vec<KVPair> {
        panic!("checked iteration must never delegate to the old collector")
    }
}

#[test]
fn legacy_backend_compiles_and_new_operations_fail_explicitly() {
    let backend = LegacyBackend;
    assert_eq!(backend.get(vec![1]).unwrap(), Some(vec![7]));
    assert!(backend
        .get_many(&[vec![1]])
        .err()
        .unwrap()
        .to_string()
        .contains("unsupported"));
    assert!(backend
        .try_collect_iterator(
            IteratorStart::From(vec![]),
            IteratorDirection::Forward,
            Box::new(|_| true),
            Box::new(|_, value| Some(value.to_vec())),
            10
        )
        .err()
        .unwrap()
        .to_string()
        .contains("unsupported"));
}
