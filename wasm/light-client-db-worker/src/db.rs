use anyhow::{anyhow, Context};
use idb::{
    CursorDirection, Database, DatabaseEvent, Factory, IndexParams, KeyPath, KeyRange,
    ManagedCursor, ObjectStore, ObjectStoreParams, TransactionMode, TransactionResult,
};
use light_client_db_common::{
    ckb_cursor_direction_to_idb, DbCommandRequest, DbCommandResponse, KV,
};
use log::debug;

use crate::STORE_NAME;

async fn open_iterator(
    store: &ObjectStore,
    start_key_bound: &[u8],
    order: CursorDirection,
) -> Result<ManagedCursor, idb::Error> {
    let index = store.index("key").unwrap();

    Ok(index
        .open_cursor(
            Some(
                match order {
                    CursorDirection::NextUnique => KeyRange::lower_bound(
                        &serde_wasm_bindgen::to_value(&start_key_bound).unwrap(),
                        Some(false),
                    ),
                    CursorDirection::PrevUnique => KeyRange::upper_bound(
                        &serde_wasm_bindgen::to_value(&start_key_bound).unwrap(),
                        Some(false),
                    ),
                    _ => unreachable!(),
                }
                .unwrap()
                .into(),
            ),
            Some(order),
        )?
        .await?
        .unwrap()
        .into_managed())
}

pub async fn collect_iterator<F>(
    store: &ObjectStore,
    start_key_bound: &[u8],
    order: CursorDirection,
    take_while: F,
    limit: usize,
    skip: usize,
) -> anyhow::Result<Vec<KV>>
where
    F: Fn(&[u8]) -> bool,
{
    let mut iter = open_iterator(store, start_key_bound, order)
        .await
        .map_err(|e| anyhow!("Failed to open iterator: {e:?}"))?;

    let mut res = Vec::new();

    let mut skip_index = 0;

    if iter.key().is_err() {
        return Ok(res);
    }

    let raw_kv = serde_wasm_bindgen::from_value::<KV>(
        iter.value()
            .map_err(|e| anyhow!("Failed to read value from cursor: {e:?}"))?
            .unwrap(),
    )
    .unwrap();

    if take_while(&raw_kv.key) {
        skip_index += 1;
        if skip_index > skip {
            res.push(raw_kv);
        }
    } else {
        return Ok(res);
    }
    while iter.next(None).await.is_ok() {
        if iter.key().is_err() {
            return Ok(res);
        }

        if res.len() >= limit {
            return Ok(res);
        }

        let key = iter.key().unwrap();
        if key.is_none() {
            return Ok(res);
        }

        let raw_kv = serde_wasm_bindgen::from_value::<KV>(
            iter.value()
                .map_err(|e| anyhow!("Failed to read value from cursor: {e:?}"))?
                .unwrap(),
        )
        .unwrap();
        if take_while(&raw_kv.key) {
            skip_index += 1;
            if skip_index > skip {
                res.push(raw_kv);
            }
        } else {
            return Ok(res);
        }
    }
    Ok(res)
}

async fn collect_iterator_keys<F>(
    store: &ObjectStore,
    start_key_bound: &[u8],
    order: CursorDirection,
    take_while: F,
    limit: usize,
    skip: usize,
) -> anyhow::Result<Vec<Vec<u8>>>
where
    F: Fn(&[u8]) -> bool,
{
    let mut iter = open_iterator(store, start_key_bound, order)
        .await
        .map_err(|e| anyhow!("Failed to open iterator: {e:?}"))?;

    let mut res = Vec::new();
    let mut skip_index = 0;

    if iter.key().is_err() {
        return Ok(res);
    }

    let raw_key = serde_wasm_bindgen::from_value::<Vec<u8>>(
        iter.key()
            .map_err(|e| anyhow!("Failed to read value from cursor: {e:?}"))?
            .unwrap(),
    )
    .unwrap();

    if take_while(&raw_key) {
        skip_index += 1;
        if skip_index > skip {
            res.push(raw_key);
        }
    } else {
        return Ok(res);
    }

    while iter.next(None).await.is_ok() {
        if iter.key().is_err() {
            return Ok(res);
        }

        if res.len() >= limit {
            return Ok(res);
        }

        let key = iter.key().unwrap();
        if key.is_none() {
            return Ok(res);
        }

        let raw_key = serde_wasm_bindgen::from_value::<Vec<u8>>(key.unwrap()).unwrap();
        if take_while(&raw_key) {
            skip_index += 1;
            if skip_index > skip {
                res.push(raw_key);
            }
        } else {
            return Ok(res);
        }
    }
    Ok(res)
}

pub(crate) async fn handle_db_command<F>(
    db: &Database,
    store_name: &str,
    cmd: DbCommandRequest,
    invoke_take_while: F,
) -> anyhow::Result<DbCommandResponse>
where
    F: Fn(&[u8]) -> bool,
{
    debug!("Handle command: {:?}", cmd);
    let tx_mode = match cmd {
        DbCommandRequest::Iterator { .. } | DbCommandRequest::IteratorKey { .. } => {
            TransactionMode::ReadOnly
        }
        DbCommandRequest::Read { .. } => TransactionMode::ReadOnly,
        DbCommandRequest::Put { .. } | DbCommandRequest::Delete { .. } => {
            TransactionMode::ReadWrite
        }
    };
    let tran = db
        .transaction(&[&store_name], tx_mode)
        .map_err(|e| anyhow!("Failed to create transaction: {:?}", e))?;

    let store = tran
        .object_store(store_name)
        .map_err(|e| anyhow!("Unable to find store {}: {}", store_name, e))?;

    let result = match cmd {
        DbCommandRequest::Read { keys } => {
            let mut res = Vec::new();
            for key in keys {
                let key = serde_wasm_bindgen::to_value(&key)
                    .map_err(|e| anyhow!("Unable to convert key to JsValue: {:?}", e))?;

                res.push(
                    store
                        .get(key)
                        .map_err(|e| anyhow!("Failed to send get request: {:?}", e))?
                        .await
                        .map_err(|e| anyhow!("Failed to fetch value: {:?}", e))?
                        .map(|v| serde_wasm_bindgen::from_value::<KV>(v).unwrap().value),
                );
            }
            DbCommandResponse::Read { values: res }
        }
        DbCommandRequest::Put { kvs } => {
            debug!("Putting: {:?}", kvs);
            for kv in kvs {
                let key = serde_wasm_bindgen::to_value(&kv.key).unwrap();
                let value = serde_wasm_bindgen::to_value(&kv).unwrap();
                store
                    .put(&value, Some(&key))
                    .map_err(|e| anyhow!("Failed to send put request: {:?}", e))?
                    .await
                    .map_err(|e| anyhow!("Failed to put: {:?}", e))?;
            }
            DbCommandResponse::Put
        }
        DbCommandRequest::Delete { keys } => {
            for key in keys {
                let key = serde_wasm_bindgen::to_value(&key).unwrap();
                store
                    .delete(key)
                    .map_err(|e| anyhow!("Failed to send delete request: {:?}", e))?
                    .await
                    .map_err(|e| anyhow!("Failed to delete: {:?}", e))?;
            }
            DbCommandResponse::Delete
        }

        DbCommandRequest::Iterator {
            start_key_bound,
            order,
            limit,
            skip,
        } => {
            let kvs = collect_iterator(
                &store,
                &start_key_bound,
                ckb_cursor_direction_to_idb(order),
                invoke_take_while,
                limit,
                skip,
            )
            .await
            .with_context(|| anyhow!("Failed to collect iterator"))?;
            debug!(
                "Called iterator, args=<{:?}, {:?}, {:?}, {:?}>, result={:?}",
                start_key_bound, order, limit, skip, kvs
            );
            DbCommandResponse::Iterator { kvs }
        }
        DbCommandRequest::IteratorKey {
            start_key_bound,
            order,
            limit,
            skip,
        } => {
            let keys = collect_iterator_keys(
                &store,
                &start_key_bound,
                ckb_cursor_direction_to_idb(order),
                invoke_take_while,
                limit,
                skip,
            )
            .await
            .with_context(|| anyhow!("Failed to collect iterator keys"))?;
            DbCommandResponse::IteratorKey { keys }
        }
    };
    assert_eq!(TransactionResult::Committed, tran.await.unwrap());
    debug!("Command result={:?}", result);
    Ok(result)
}

pub(crate) async fn open_database(database_name: impl AsRef<str>) -> anyhow::Result<Database> {
    let factory = Factory::new().map_err(|e| anyhow!("Failed to create db factory: {:?}", e))?;
    let mut open_request = factory
        .open(database_name.as_ref(), Some(1))
        .map_err(|e| anyhow!("Failed to send db open request: {:?}", e))?;
    open_request.on_upgrade_needed(move |event| {
        let database = event.database().unwrap();
        let store_params = ObjectStoreParams::new();

        let store = database
            .create_object_store(STORE_NAME, store_params)
            .unwrap();
        let mut index_params = IndexParams::new();
        index_params.unique(true);
        store
            .create_index("key", KeyPath::new_single("key"), Some(index_params))
            .unwrap();
    });
    open_request
        .await
        .map_err(|e| anyhow!("Failed to open database: {:?}", e))
}
