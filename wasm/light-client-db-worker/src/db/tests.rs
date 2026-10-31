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
        DbCommandRequest::Iterator {
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
async fn key_scans_share_exclusive_bounds_and_propagate_cursor_errors() {
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
    assert!(
        result.is_err(),
        "key cursor returned partial success: {result:?}"
    );
    remove(db, &name).await;
}
