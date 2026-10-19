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
