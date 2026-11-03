use super::{handle_db_command, open_database};
use crate::STORE_NAME;
use idb::{Database, DatabaseEvent, Factory, IndexParams, KeyPath, ObjectStoreParams};
use light_client_db_common::{BatchOperation, DbCommandRequest, DbCommandResponse, KVPair};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = "
let originalPut;
export function failPut(key, abort) {
    originalPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function(value, suppliedKey) {
        if (suppliedKey[0] !== key) return originalPut.call(this, value, suppliedKey);
        if (!abort) throw new DOMException('injected batch put failure', 'QuotaExceededError');
        const request = originalPut.call(this, value, suppliedKey);
        request.addEventListener('success', () => this.transaction.abort());
        return request;
    };
}
export function restorePut() {
    IDBObjectStore.prototype.put = originalPut;
}
")]
extern "C" {
    #[wasm_bindgen(js_name = failPut)]
    fn fail_put(key: u8, abort: bool);
    #[wasm_bindgen(js_name = restorePut)]
    fn restore_put();
}

fn put(key: &[u8], value: &[u8]) -> BatchOperation {
    BatchOperation::Put(KVPair {
        key: key.to_vec(),
        value: value.to_vec(),
    })
}

fn delete(key: &[u8]) -> BatchOperation {
    BatchOperation::Delete(key.to_vec())
}

async fn command(db: &Database, cmd: DbCommandRequest) -> anyhow::Result<DbCommandResponse> {
    handle_db_command(
        db,
        STORE_NAME,
        cmd,
        |_| true,
        |_, _, _| async { None },
        None,
    )
    .await
}

async fn batch(
    db: &Database,
    operations: Vec<BatchOperation>,
) -> anyhow::Result<DbCommandResponse> {
    command(db, DbCommandRequest::Batch { operations }).await
}

async fn read(db: &Database, keys: &[&[u8]]) -> Vec<Option<Vec<u8>>> {
    match command(
        db,
        DbCommandRequest::Read {
            keys: keys.iter().map(|key| key.to_vec()).collect(),
        },
    )
    .await
    .unwrap()
    {
        DbCommandResponse::Read { values } => values,
        other => panic!("Unexpected read response: {other:?}"),
    }
}

fn database_name() -> String {
    format!(
        "batch-regression-{}-{}",
        web_sys::js_sys::Date::now(),
        web_sys::js_sys::Math::random()
    )
}

async fn remove(db: Database, name: &str) {
    db.close();
    Factory::new().unwrap().delete(name).unwrap().await.unwrap();
}

#[wasm_bindgen_test]
async fn ordered_mutations_persist_after_reopen() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    let operations = vec![
        put(&[0, 255], &[1]),
        put(&[0], &[2]),
        delete(&[0, 255]), // create then spend
        delete(&[1]),
        put(&[1], &[3]), // replace
        put(&[0], &[4]), // repeated put
        delete(&[2]),
        delete(&[2]), // repeated delete
        put(&[3], &[5]),
        delete(&[3]),
        put(&[3], &[6]), // put/delete/put
        delete(&[4]),
        put(&[4], &[7]),
        delete(&[4]),  // delete/put/delete
        put(&[], &[]), // empty key and value
    ];
    assert!(matches!(
        batch(&db, operations).await.unwrap(),
        DbCommandResponse::Batch
    ));
    let keys: &[&[u8]] = &[&[0, 255], &[0], &[1], &[2], &[3], &[4], &[]];
    let expected = vec![
        None,
        Some(vec![4]),
        Some(vec![3]),
        None,
        Some(vec![6]),
        None,
        Some(vec![]),
    ];
    assert_eq!(read(&db, keys).await, expected);
    batch(&db, vec![]).await.unwrap();
    db.close();
    let db = open_database(&name).await.unwrap();
    assert_eq!(read(&db, keys).await, expected);
    remove(db, &name).await;
}

async fn failed_batch_rolls_back(abort: bool) {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[12])])
        .await
        .unwrap();
    fail_put(3, abort);
    let result = batch(&db, vec![delete(&[1]), put(&[2], &[22]), put(&[3], &[33])]).await;
    restore_put();
    assert!(result.is_err(), "Failed batch reported success: {result:?}");
    let expected = vec![Some(vec![11]), Some(vec![12]), None];
    assert_eq!(read(&db, &[&[1], &[2], &[3]]).await, expected);
    // Error handling must leave the worker usable for the next command.
    batch(&db, vec![put(&[4], &[44])]).await.unwrap();
    db.close();
    let db = open_database(&name).await.unwrap();
    assert_eq!(read(&db, &[&[1], &[2], &[3]]).await, expected);
    assert_eq!(read(&db, &[&[4]]).await, vec![Some(vec![44])]);
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn synchronous_failure_rolls_back_after_reopen() {
    failed_batch_rolls_back(false).await;
}

#[wasm_bindgen_test]
async fn transaction_abort_is_not_success() {
    failed_batch_rolls_back(true).await;
}

#[wasm_bindgen_test]
async fn asynchronous_request_failure_rolls_back_after_reopen() {
    let name = database_name();
    // A unique secondary index produces a real asynchronous ConstraintError.
    let factory = Factory::new().unwrap();
    let mut request = factory.open(&name, Some(1)).unwrap();
    request.on_upgrade_needed(|event| {
        let db = event.database().unwrap();
        let store = db
            .create_object_store(STORE_NAME, ObjectStoreParams::new())
            .unwrap();
        let mut params = IndexParams::new();
        params.unique(true);
        store
            .create_index("unique-value", KeyPath::new_single("value"), Some(params))
            .unwrap();
    });
    let db = request.await.unwrap();
    batch(&db, vec![put(&[1], &[11])]).await.unwrap();
    let result = batch(&db, vec![delete(&[1]), put(&[2], &[22]), put(&[3], &[22])]).await;
    assert!(
        result.is_err(),
        "Constraint failure reported success: {result:?}"
    );
    let expected = vec![Some(vec![11]), None, None];
    assert_eq!(read(&db, &[&[1], &[2], &[3]]).await, expected);
    db.close();
    let db = open_database(&name).await.unwrap();
    assert_eq!(read(&db, &[&[1], &[2], &[3]]).await, expected);
    remove(db, &name).await;
}

// Backend read/scan regressions, independent of canonical-state handling.
use idb::{TransactionMode, TransactionResult};
use light_client_db_common::{IteratorDirection, IteratorStart};

#[wasm_bindgen_test]
async fn maintainer_browser_matches_native_boundary_contract() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
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
    batch(&db, keys.iter().map(|key| put(key, key)).collect())
        .await
        .unwrap();
    for mode in 0..4 {
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
                        let command = match mode {
                            0 => DbCommandRequest::LegacyIterator {
                                start,
                                direction,
                                limit,
                            },
                            1 => DbCommandRequest::CheckedIterator {
                                start,
                                direction,
                                limit,
                            },
                            2 => DbCommandRequest::IteratorKey {
                                start,
                                direction,
                                limit,
                            },
                            _ => DbCommandRequest::Iterator {
                                start,
                                direction,
                                limit,
                            },
                        };
                        let response = handle_db_command(
                            &db,
                            STORE_NAME,
                            command,
                            |_| true,
                            |key, value, _| {
                                let output = if mode == 2 {
                                    key.to_vec()
                                } else {
                                    value.to_vec()
                                };
                                async move { Some(output) }
                            },
                            None,
                        )
                        .await
                        .unwrap();
                        let actual = match response {
                            DbCommandResponse::Iterator { kvs } => kvs
                                .into_iter()
                                .map(|row| {
                                    assert_eq!(row.key, row.value);
                                    row.key
                                })
                                .collect::<Vec<_>>(),
                            DbCommandResponse::IteratorKey { keys } => keys,
                            other => panic!("unexpected response {other:?}"),
                        };
                        assert_eq!(actual,expected,"mode={mode} boundary={boundary:?} direction={direction:?} exclusive={exclusive} limit={limit}");
                        cases += 1;
                    }
                }
            }
        }
        wasm_bindgen_test::console_log!(
            "cross-backend boundary contract mode={mode}: {cases} cases"
        );
    }
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn binary_prefix_pages_continue_at_exact_boundaries_in_all_modes() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
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
    for populated in [false, true] {
        if populated {
            batch(&db, keys.iter().map(|key| put(key, key)).collect())
                .await
                .unwrap();
        }
        for mode in 0..4 {
            for direction in [IteratorDirection::Forward, IteratorDirection::Reverse] {
                let mut start = if populated {
                    IteratorStart::From(match direction {
                        IteratorDirection::Forward => vec![],
                        IteratorDirection::Reverse => vec![255, 255],
                    })
                } else {
                    IteratorStart::After(vec![0, 0])
                };
                let mut actual = Vec::new();
                for page in 0..5 {
                    let request = match mode {
                        0 => DbCommandRequest::LegacyIterator {
                            start,
                            direction,
                            limit: 2,
                        },
                        1 => DbCommandRequest::CheckedIterator {
                            start,
                            direction,
                            limit: 2,
                        },
                        2 => DbCommandRequest::IteratorKey {
                            start,
                            direction,
                            limit: 2,
                        },
                        _ => DbCommandRequest::Iterator {
                            start,
                            direction,
                            limit: 2,
                        },
                    };
                    let response = handle_db_command(
                        &db,
                        STORE_NAME,
                        request,
                        |_| true,
                        |key, _, _| {
                            let key = key.to_vec();
                            async move { Some(key) }
                        },
                        None,
                    )
                    .await
                    .unwrap();
                    let rows = match response {
                        DbCommandResponse::Iterator { kvs } => kvs
                            .into_iter()
                            .map(|row| {
                                assert_eq!(row.key, row.value);
                                row.key
                            })
                            .collect::<Vec<_>>(),
                        DbCommandResponse::IteratorKey { keys } => keys,
                        other => panic!("unexpected response {other:?}"),
                    };
                    assert_eq!(rows.len(), if !populated || page == 4 { 0 } else { 2 });
                    if rows.is_empty() {
                        break;
                    }
                    start = IteratorStart::After(rows.last().unwrap().clone());
                    actual.extend(rows);
                }
                let mut expected = if populated { keys.clone() } else { vec![] };
                if direction == IteratorDirection::Reverse {
                    expected.reverse();
                }
                assert_eq!(actual, expected);
            }
        }
    }
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn maintainer_legacy_cursor_failure_preserves_partial_rows_and_keys() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[22])])
        .await
        .unwrap();
    for keys_only in [false, true] {
        fail_advance();
        let cmd = if keys_only {
            DbCommandRequest::IteratorKey {
                start: IteratorStart::From(vec![1]),
                direction: IteratorDirection::Forward,
                limit: 10,
            }
        } else {
            DbCommandRequest::LegacyIterator {
                start: IteratorStart::From(vec![1]),
                direction: IteratorDirection::Forward,
                limit: 10,
            }
        };
        let result = handle_db_command(
            &db,
            STORE_NAME,
            cmd,
            |_| true,
            |key, value, _| {
                let output = if keys_only {
                    key.to_vec()
                } else {
                    value.to_vec()
                };
                async move { Some(output) }
            },
            None,
        )
        .await;
        restore_advance();
        match result.expect("legacy advance failure must preserve its retrieved prefix") {
            DbCommandResponse::Iterator { kvs } => {
                assert_eq!(kvs.len(), 1);
                assert_eq!(kvs[0].key, vec![1]);
                assert_eq!(kvs[0].value, vec![11]);
            }
            DbCommandResponse::IteratorKey { keys } => assert_eq!(keys, vec![vec![1]]),
            other => panic!("unexpected legacy response: {other:?}"),
        }
    }
    assert_eq!(
        scan(
            &db,
            IteratorStart::From(vec![1]),
            IteratorDirection::Forward,
            10
        )
        .await
        .unwrap()
        .len(),
        2
    );
    remove(db, &name).await;
}

#[wasm_bindgen(inline_js = "
let oldGet, oldContinue;
export function failRead(key, abort) {
    oldGet = IDBObjectStore.prototype.get;
    IDBObjectStore.prototype.get = function(query) {
        if (query[0] !== key) return oldGet.call(this, query);
        if (!abort) throw new DOMException('injected read failure', 'InvalidStateError');
        const request = oldGet.call(this, query);
        request.addEventListener('success', () => this.transaction.abort());
        return request;
    };
}
export function restoreRead() { IDBObjectStore.prototype.get = oldGet; }
export function failAdvance() {
    oldContinue = IDBCursor.prototype.continue;
    IDBCursor.prototype.continue = function() {
        throw new DOMException('injected cursor failure', 'InvalidStateError');
    };
}
export function restoreAdvance() { IDBCursor.prototype.continue = oldContinue; }
export function abortAdvance() {
    oldContinue = IDBCursor.prototype.continue;
    IDBCursor.prototype.continue = function() {
        this.source.objectStore.transaction.abort();
        throw new DOMException('injected abort during cursor advance', 'AbortError');
    };
}
")]
extern "C" {
    #[wasm_bindgen(js_name = failRead)]
    fn fail_read(key: u8, abort: bool);
    #[wasm_bindgen(js_name = restoreRead)]
    fn restore_read();
    #[wasm_bindgen(js_name = failAdvance)]
    fn fail_advance();
    #[wasm_bindgen(js_name = restoreAdvance)]
    fn restore_advance();
    #[wasm_bindgen(js_name = abortAdvance)]
    fn abort_advance();
}

#[wasm_bindgen_test]
async fn maintainer_aborted_cursor_transactions_never_return_partial_success() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[22])])
        .await
        .unwrap();
    for mode in 0..3 {
        abort_advance();
        let start = IteratorStart::From(vec![1]);
        let direction = IteratorDirection::Forward;
        let command = match mode {
            0 => DbCommandRequest::LegacyIterator {
                start,
                direction,
                limit: 10,
            },
            1 => DbCommandRequest::CheckedIterator {
                start,
                direction,
                limit: 10,
            },
            _ => DbCommandRequest::IteratorKey {
                start,
                direction,
                limit: 10,
            },
        };
        let result = handle_db_command(
            &db,
            STORE_NAME,
            command,
            |_| true,
            |_, value, _| {
                let value = value.to_vec();
                async move { Some(value) }
            },
            None,
        )
        .await;
        restore_advance();
        assert!(
            result.is_err(),
            "mode={mode} certified an aborted scan: {result:?}"
        );
        assert_eq!(
            scan(&db, IteratorStart::From(vec![1]), direction, 10)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    fail_advance();
    let page = scan(
        &db,
        IteratorStart::From(vec![1]),
        IteratorDirection::Forward,
        1,
    )
    .await;
    restore_advance();
    assert_eq!(
        page.unwrap().len(),
        1,
        "a completed requested page must not advance beyond its limit"
    );
    db.close();
    let db = open_database(&name).await.unwrap();
    assert_eq!(
        read(&db, &[&[1], &[2]]).await,
        vec![Some(vec![11]), Some(vec![22])]
    );
    remove(db, &name).await;
}

async fn scan(
    db: &Database,
    start: IteratorStart,
    direction: IteratorDirection,
    limit: usize,
) -> anyhow::Result<Vec<KVPair>> {
    match handle_db_command(
        db,
        STORE_NAME,
        DbCommandRequest::CheckedIterator {
            start,
            direction,
            limit,
        },
        |_| true,
        |_, value, _| {
            let value = value.to_vec();
            async move { Some(value) }
        },
        None,
    )
    .await?
    {
        DbCommandResponse::Iterator { kvs } => Ok(kvs),
        other => panic!("Unexpected scan response: {other:?}"),
    }
}

#[wasm_bindgen_test]
async fn multikey_snapshot_preserves_order_duplicates_and_missing_entries() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[10], &[0]), put(&[11], &[0]), put(&[], &[])])
        .await
        .unwrap();
    assert!(read(&db, &[]).await.is_empty());
    assert_eq!(
        read(&db, &[&[11], &[12], &[], &[11]]).await,
        vec![Some(vec![0]), None, Some(vec![]), Some(vec![0])]
    );
    let writer = open_database(&name).await.unwrap();
    let (done, finished) = tokio::sync::oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        for generation in 1..=64u8 {
            batch(
                &writer,
                vec![put(&[10], &[generation]), put(&[11], &[generation])],
            )
            .await
            .unwrap();
        }
        writer.close();
        done.send(()).unwrap();
    });
    for _ in 0..64 {
        let values = read(&db, &[&[10], &[11], &[12], &[10]]).await;
        assert_eq!(values[0], values[1]);
        assert_eq!(values[0], values[3]);
        assert_eq!(values[2], None);
    }
    finished.await.unwrap();
    db.close();
    let db = open_database(&name).await.unwrap();
    assert_eq!(
        read(&db, &[&[10], &[11]]).await,
        vec![Some(vec![64]), Some(vec![64])]
    );
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn scans_handle_empty_ranges_limits_and_exclusive_missing_boundaries() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    assert!(scan(
        &db,
        IteratorStart::From(vec![]),
        IteratorDirection::Forward,
        10
    )
    .await
    .unwrap()
    .is_empty());
    batch(
        &db,
        vec![put(&[10], &[10]), put(&[20], &[20]), put(&[30], &[30])],
    )
    .await
    .unwrap();
    for (start, direction, limit, expected) in [
        (
            IteratorStart::From(vec![10]),
            IteratorDirection::Forward,
            10,
            vec![10, 20, 30],
        ),
        (
            IteratorStart::After(vec![10]),
            IteratorDirection::Forward,
            10,
            vec![20, 30],
        ),
        (
            IteratorStart::After(vec![15]),
            IteratorDirection::Forward,
            10,
            vec![20, 30],
        ),
        (
            IteratorStart::After(vec![25]),
            IteratorDirection::Reverse,
            10,
            vec![20, 10],
        ),
        (
            IteratorStart::From(vec![30]),
            IteratorDirection::Reverse,
            2,
            vec![30, 20],
        ),
        (
            IteratorStart::From(vec![40]),
            IteratorDirection::Forward,
            10,
            vec![],
        ),
        (
            IteratorStart::From(vec![0]),
            IteratorDirection::Reverse,
            10,
            vec![],
        ),
        (
            IteratorStart::From(vec![10]),
            IteratorDirection::Forward,
            0,
            vec![],
        ),
    ] {
        let rows = scan(&db, start, direction, limit).await.unwrap();
        assert_eq!(
            rows.into_iter().map(|row| row.value[0]).collect::<Vec<_>>(),
            expected
        );
    }
    let result = handle_db_command(
        &db,
        STORE_NAME,
        DbCommandRequest::Iterator {
            start: IteratorStart::From(vec![10]),
            direction: IteratorDirection::Forward,
            limit: 1,
        },
        |key| key[0] < 30,
        |key, value, _| {
            let result = (key[0] != 10).then(|| vec![value[0] + 1]);
            async move { result }
        },
        None,
    )
    .await
    .unwrap();
    if let DbCommandResponse::Iterator { kvs } = result {
        assert_eq!(kvs.len(), 1);
        assert_eq!(kvs[0].value, vec![21]);
    } else {
        panic!("wrong scan response");
    }
    batch(&db, vec![put(&[], &[])]).await.unwrap();
    let empty = scan(
        &db,
        IteratorStart::From(vec![]),
        IteratorDirection::Forward,
        1,
    )
    .await
    .unwrap();
    assert_eq!(empty.len(), 1);
    assert!(empty[0].key.is_empty());
    assert!(empty[0].value.is_empty());
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn cursor_advance_failure_discards_the_partial_page() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[22])])
        .await
        .unwrap();
    fail_advance();
    let result = scan(
        &db,
        IteratorStart::From(vec![1]),
        IteratorDirection::Forward,
        10,
    )
    .await;
    restore_advance();
    assert!(
        result.is_err(),
        "cursor failure returned partial success: {result:?}"
    );
    assert_eq!(
        scan(
            &db,
            IteratorStart::From(vec![1]),
            IteratorDirection::Forward,
            10
        )
        .await
        .unwrap()
        .len(),
        2
    );
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn maintainer_old_checked_client_iterator_tag_remains_strict() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[22])])
        .await
        .unwrap();
    fail_advance();
    let result = handle_db_command(
        &db,
        STORE_NAME,
        DbCommandRequest::Iterator {
            start: IteratorStart::From(vec![1]),
            direction: IteratorDirection::Forward,
            limit: 10,
        },
        |_| true,
        |_, value, _| {
            let value = value.to_vec();
            async move { Some(value) }
        },
        None,
    )
    .await;
    restore_advance();
    assert!(
        result.is_err(),
        "old #304/#302 checked client received uncertified partial rows: {result:?}"
    );
    assert_eq!(
        scan(
            &db,
            IteratorStart::From(vec![1]),
            IteratorDirection::Forward,
            10
        )
        .await
        .unwrap()
        .len(),
        2
    );
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn read_request_error_and_transaction_abort_are_errors() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11]), put(&[2], &[22])])
        .await
        .unwrap();
    for abort in [false, true] {
        fail_read(2, abort);
        let result = command(
            &db,
            DbCommandRequest::Read {
                keys: vec![vec![1], vec![2]],
            },
        )
        .await;
        restore_read();
        assert!(result.is_err(), "read failure reported success: {result:?}");
    }
    assert_eq!(
        read(&db, &[&[1], &[2]]).await,
        vec![Some(vec![11]), Some(vec![22])]
    );
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn malformed_values_fail_reads_and_scans_without_trapping() {
    #[derive(serde::Serialize)]
    struct BadRow {
        key: Vec<u8>,
        value: String,
    }
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    batch(&db, vec![put(&[1], &[11])]).await.unwrap();
    let transaction = db
        .transaction(&[STORE_NAME], TransactionMode::ReadWrite)
        .unwrap();
    let store = transaction.object_store(STORE_NAME).unwrap();
    let row = serde_wasm_bindgen::to_value(&BadRow {
        key: vec![2],
        value: "invalid byte array".into(),
    })
    .unwrap();
    let key = serde_wasm_bindgen::to_value(&vec![2u8]).unwrap();
    store.put(&row, Some(&key)).unwrap().await.unwrap();
    assert_eq!(transaction.await.unwrap(), TransactionResult::Committed);
    assert!(command(
        &db,
        DbCommandRequest::Read {
            keys: vec![vec![1], vec![2]]
        }
    )
    .await
    .is_err());
    assert!(scan(
        &db,
        IteratorStart::From(vec![1]),
        IteratorDirection::Forward,
        10
    )
    .await
    .is_err());
    batch(&db, vec![delete(&[2])]).await.unwrap();
    assert_eq!(
        scan(
            &db,
            IteratorStart::From(vec![1]),
            IteratorDirection::Forward,
            10
        )
        .await
        .unwrap()
        .len(),
        1
    );
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn scan_missing_index_is_an_error_not_an_empty_page() {
    let name = database_name();
    let mut request = Factory::new().unwrap().open(&name, Some(1)).unwrap();
    request.on_upgrade_needed(|event| {
        event
            .database()
            .unwrap()
            .create_object_store(STORE_NAME, ObjectStoreParams::new())
            .unwrap();
    });
    let db = request.await.unwrap();
    assert!(scan(
        &db,
        IteratorStart::From(vec![]),
        IteratorDirection::Forward,
        10
    )
    .await
    .is_err());
    remove(db, &name).await;
}

#[wasm_bindgen_test]
async fn key_scans_share_exclusive_bounds_and_preserve_legacy_advance_prefix() {
    let name = database_name();
    let db = open_database(&name).await.unwrap();
    let request = || DbCommandRequest::IteratorKey {
        start: IteratorStart::After(vec![15]),
        direction: IteratorDirection::Forward,
        limit: 10,
    };
    batch(
        &db,
        vec![put(&[10], &[1]), put(&[20], &[2]), put(&[30], &[3])],
    )
    .await
    .unwrap();
    let result = handle_db_command(
        &db,
        STORE_NAME,
        request(),
        |_| true,
        |key, _, _| {
            let key = key.to_vec();
            async move { Some(key) }
        },
        None,
    )
    .await
    .unwrap();
    match result {
        DbCommandResponse::IteratorKey { keys } => assert_eq!(keys, vec![vec![20], vec![30]]),
        other => panic!("Unexpected key response: {other:?}"),
    }
    fail_advance();
    let result = handle_db_command(
        &db,
        STORE_NAME,
        request(),
        |_| true,
        |key, _, _| {
            let key = key.to_vec();
            async move { Some(key) }
        },
        None,
    )
    .await;
    restore_advance();
    match result.unwrap() {
        DbCommandResponse::IteratorKey { keys } => assert_eq!(keys, vec![vec![20]]),
        other => panic!("unexpected legacy key response: {other:?}"),
    }
    remove(db, &name).await;
}
