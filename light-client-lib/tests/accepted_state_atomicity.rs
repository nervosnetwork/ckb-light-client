//! Storage transitions below are fixtures, not live protocol reorganization tests.
#![cfg(not(target_arch = "wasm32"))]
use ckb_light_client_lib::storage::{LightClientStorage, Storage};
use ckb_types::{core, prelude::*, U256};

#[test]
fn accepted_state_and_window_survive_reopen_after_extension_fork_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = Storage::new(directory.path());
    for (number, nonce) in [(10u64, 0u128), (11, 1), (11, 2), (9, 3)] {
        let previous = core::HeaderBuilder::default()
            .number(number - 1)
            .epoch(core::EpochNumberWithFraction::new(0, number - 1, 1000))
            .nonce(nonce)
            .build();
        let tip = core::HeaderBuilder::default()
            .number(number)
            .epoch(core::EpochNumberWithFraction::new(0, number, 1000))
            .nonce(nonce)
            .parent_hash(previous.hash())
            .build();
        storage.update_last_state(
            &U256::from(number),
            &tip.data(),
            std::slice::from_ref(&previous),
        );
        drop(storage);
        let reopened = Storage::new(directory.path());
        let (work, header) = reopened.get_last_state();
        assert_eq!(work, U256::from(number));
        assert_eq!(header.as_slice(), tip.data().as_slice());
        assert_eq!(
            reopened.get_last_n_headers(),
            vec![(number - 1, previous.hash())]
        );
        storage = reopened;
    }
}

#[cfg(feature = "sqlite")]
fn abort_update(failing_key: &str) {
    use ckb_light_client_lib::storage::Key;
    use ckb_types::packed;
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let old = core::HeaderBuilder::default()
        .number(10u64)
        .epoch(core::EpochNumberWithFraction::new(0, 10, 1000))
        .build();
    let previous = core::HeaderBuilder::default()
        .number(9u64)
        .epoch(core::EpochNumberWithFraction::new(0, 9, 1000))
        .build();
    let next = old
        .clone()
        .as_advanced_builder()
        .number(11u64)
        .parent_hash(old.hash())
        .build();
    storage.update_last_state(
        &U256::from(10u64),
        &old.data(),
        std::slice::from_ref(&previous),
    );
    let connection = rusqlite::Connection::open(directory.path().join("db.sqlite")).unwrap();
    let key = Key::Meta(failing_key)
        .into_vec()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    connection.execute_batch(&format!("CREATE TRIGGER reject_state BEFORE INSERT ON kv_store WHEN hex(NEW.key) = '{key}' BEGIN SELECT RAISE(ABORT, 'injected accepted-state failure'); END;")).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        storage.update_last_state(&U256::from(11u64), &next.data(), std::slice::from_ref(&old));
    }))
    .is_err());
    // Reopen independently: the invariant must persist after the writer failed.
    let reopened = rusqlite::Connection::open(directory.path().join("db.sqlite")).unwrap();
    let read = |name| -> Vec<u8> {
        reopened
            .query_row(
                "SELECT value FROM kv_store WHERE key = ?",
                rusqlite::params![Key::Meta(name).into_vec()],
                |row| row.get(0),
            )
            .unwrap()
    };
    let state = read("LAST_STATE");
    assert_eq!(
        U256::from_le_bytes(state[..32].try_into().unwrap()),
        U256::from(10u64)
    );
    assert_eq!(
        packed::Header::from_slice(&state[32..]).unwrap().as_slice(),
        old.data().as_slice()
    );
    let window = read("LAST_N_HEADERS");
    assert_eq!(&window[..8], &9u64.to_le_bytes());
    assert_eq!(&window[8..], previous.hash().as_slice());
}

#[cfg(feature = "sqlite")]
#[test]
fn aborting_recent_window_preserves_previous_accepted_state() {
    abort_update("LAST_N_HEADERS");
}

#[cfg(feature = "sqlite")]
#[test]
fn aborting_accepted_state_preserves_previous_recent_window() {
    abort_update("LAST_STATE");
}

#[cfg(feature = "sqlite")]
#[test]
fn concurrent_database_snapshots_never_mix_tip_and_recent_window() {
    use ckb_light_client_lib::storage::Key;
    use ckb_types::packed;
    use std::sync::{Arc, Barrier};
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let initial = core::HeaderBuilder::default()
        .number(1u64)
        .epoch(core::EpochNumberWithFraction::new(0, 1, 1000))
        .build();
    let previous = core::HeaderBuilder::default().build();
    storage.update_last_state(&U256::one(), &initial.data(), &[previous]);
    let reader = rusqlite::Connection::open(directory.path().join("db.sqlite")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let ready = barrier.clone();
    let writer = storage.clone();
    let handle = std::thread::spawn(move || {
        ready.wait();
        for number in 2..=300u64 {
            let previous = core::HeaderBuilder::default()
                .number(number - 1)
                .epoch(core::EpochNumberWithFraction::new(0, number - 1, 1000))
                .build();
            let tip = core::HeaderBuilder::default()
                .number(number)
                .epoch(core::EpochNumberWithFraction::new(0, number, 1000))
                .parent_hash(previous.hash())
                .build();
            writer.update_last_state(&U256::from(number), &tip.data(), &[previous]);
        }
    });
    barrier.wait();
    let mut inconsistent = 0;
    for _ in 0..300 {
        let snapshot = reader.unchecked_transaction().unwrap();
        let read = |name| -> Vec<u8> {
            snapshot
                .query_row(
                    "SELECT value FROM kv_store WHERE key = ?",
                    rusqlite::params![Key::Meta(name).into_vec()],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let state = read("LAST_STATE");
        let window = read("LAST_N_HEADERS");
        let tip = packed::Header::from_slice(&state[32..])
            .unwrap()
            .into_view();
        let previous = u64::from_le_bytes(window[..8].try_into().unwrap());
        if previous + 1 != tip.number() {
            inconsistent += 1;
        }
        snapshot.commit().unwrap();
    }
    handle.join().unwrap();
    assert_eq!(
        inconsistent, 0,
        "snapshot observed a partially persisted transition"
    );
}

#[test]
fn backend_multikey_snapshot_preserves_batch_generation_order_and_missing_entries() {
    use ckb_light_client_lib::storage::{BatchWriter, StorageBackend};
    use std::sync::{Arc, Barrier};
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let keys = vec![vec![250, 1], vec![250, 2], vec![250, 3], vec![250, 1]];
    let mut initial = storage.batch();
    initial.put(&keys[0], &[0]);
    initial.put(&keys[1], &[0]);
    initial.commit().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let ready = barrier.clone();
    let writer = storage.clone();
    let handle = std::thread::spawn(move || {
        ready.wait();
        for generation in 1..=200u8 {
            let mut batch = writer.batch();
            batch.put(&[250, 1], &[generation]);
            batch.put(&[250, 2], &[generation]);
            batch.commit().unwrap();
        }
    });
    barrier.wait();
    for _ in 0..200 {
        let rows = storage.get_many(&keys).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0], rows[1]);
        assert_eq!(rows[0], rows[3]);
        assert!(rows[2].is_none());
    }
    handle.join().unwrap();
    drop(storage);
    let reopened = Storage::new(directory.path());
    assert_eq!(
        reopened.get_many(&keys).unwrap(),
        vec![Some(vec![200]), Some(vec![200]), None, Some(vec![200])]
    );
}
