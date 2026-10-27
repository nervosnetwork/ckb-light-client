use std::future::Future;

use anyhow::{anyhow, bail, Context};
use idb::{
    Database, DatabaseEvent, Factory, IndexParams, KeyPath, KeyRange, ManagedCursor, ObjectStore,
    ObjectStoreParams, TransactionMode, TransactionResult,
};
use light_client_db_common::{
    iterator_direction_to_idb, BatchOperation, DbCommandRequest, DbCommandResponse,
    IteratorDirection, IteratorStart, KVPair,
};
use log::debug;

use crate::STORE_NAME;

async fn commit_batch(
    db: &Database,
    store_name: &str,
    operations: Vec<BatchOperation>,
) -> anyhow::Result<DbCommandResponse> {
    let transaction = db
        .transaction(&[store_name], TransactionMode::ReadWrite)
        .map_err(|e| anyhow!("Failed to create batch transaction: {e:?}"))?;
    let result: anyhow::Result<()> = async {
        let store = transaction
            .object_store(store_name)
            .map_err(|e| anyhow!("Unable to find store {store_name}: {e:?}"))?;
        for operation in operations {
            match operation {
                BatchOperation::Put(kv) => {
                    let key = serde_wasm_bindgen::to_value(&kv.key)
                        .map_err(|e| anyhow!("Failed to serialize batch key: {e:?}"))?;
                    let value = serde_wasm_bindgen::to_value(&kv)
                        .map_err(|e| anyhow!("Failed to serialize batch value: {e:?}"))?;
                    store
                        .put(&value, Some(&key))
                        .map_err(|e| anyhow!("Failed to send batch put request: {e:?}"))?
                        .await
                        .map_err(|e| anyhow!("Failed to put in batch: {e:?}"))?;
                }
                BatchOperation::Delete(key) => {
                    let key = serde_wasm_bindgen::to_value(&key)
                        .map_err(|e| anyhow!("Failed to serialize batch key: {e:?}"))?;
                    store
                        .delete(key)
                        .map_err(|e| anyhow!("Failed to send batch delete request: {e:?}"))?
                        .await
                        .map_err(|e| anyhow!("Failed to delete in batch: {e:?}"))?;
                }
            }
        }
        Ok(())
    }
    .await;

    if let Err(error) = result {
        // A synchronous request/serialization failure does not abort IndexedDB
        // automatically. Roll back earlier writes before returning the error.
        // An asynchronous request failure may already have aborted it.
        if let Ok(transaction) = transaction.abort() {
            let _ = transaction.await;
        }
        return Err(error);
    }
    match transaction.await {
        Ok(TransactionResult::Committed) => Ok(DbCommandResponse::Batch),
        Ok(TransactionResult::Aborted) => bail!("Batch transaction aborted"),
        Err(error) => bail!("Batch transaction failed: {error:?}"),
    }
}

async fn open_iterator(
    store: &ObjectStore,
    start: &IteratorStart,
    direction: IteratorDirection,
) -> anyhow::Result<Option<ManagedCursor>> {
    let index = store
        .index("key")
        .map_err(|error| anyhow!("Failed to open key index: {error:?}"))?;
    let key = serde_wasm_bindgen::to_value(start.key())
        .map_err(|error| anyhow!("Failed to serialize cursor key: {error:?}"))?;
    let exclusive = Some(start.should_skip_first());
    let range = match direction {
        IteratorDirection::Forward => KeyRange::lower_bound(&key, exclusive),
        IteratorDirection::Reverse => KeyRange::upper_bound(&key, exclusive),
    }
    .map_err(|error| anyhow!("Failed to create cursor range: {error:?}"))?;
    Ok(index
        .open_cursor(
            Some(range.into()),
            Some(iterator_direction_to_idb(direction)),
        )
        .map_err(|error| anyhow!("Failed to send cursor request: {error:?}"))?
        .await
        .map_err(|error| anyhow!("Failed to open cursor: {error:?}"))?
        .map(|cursor| cursor.into_managed()))
}

pub async fn collect_iterator<F, FnFilterMap, FnFilterMapOutput>(
    store: &ObjectStore,
    start: &IteratorStart,
    direction: IteratorDirection,
    take_while: F,
    filter_map: FnFilterMap,
    limit: usize,
) -> anyhow::Result<Vec<KVPair>>
where
    F: Fn(&[u8]) -> bool,
    FnFilterMap: Fn(&[u8], &[u8]) -> FnFilterMapOutput,
    FnFilterMapOutput: Future<Output = Option<Vec<u8>>>,
{
    let mut result = Vec::new();
    if limit == 0 {
        return Ok(result);
    }
    let Some(mut cursor) = open_iterator(store, start, direction).await? else {
        return Ok(result);
    };
    loop {
        if cursor
            .key()
            .map_err(|error| anyhow!("Failed to read cursor key: {error:?}"))?
            .is_none()
        {
            break;
        }
        let value = cursor
            .value()
            .map_err(|error| anyhow!("Failed to read cursor value: {error:?}"))?
            .ok_or_else(|| anyhow!("Cursor key has no value"))?;
        let row: KVPair = serde_wasm_bindgen::from_value(value)
            .map_err(|error| anyhow!("Failed to decode cursor row: {error:?}"))?;
        if !take_while(&row.key) {
            break;
        }
        if let Some(value) = filter_map(&row.key, &row.value).await {
            result.push(KVPair {
                key: row.key,
                value,
            });
        }
        if result.len() == limit {
            break;
        }
        cursor
            .next(None)
            .await
            .map_err(|error| anyhow!("Failed to advance cursor: {error:?}"))?;
    }
    Ok(result)
}

async fn collect_iterator_keys<F, FnFilterMap, FnFilterMapOutput>(
    store: &ObjectStore,
    start: &IteratorStart,
    direction: IteratorDirection,
    take_while: F,
    filter_map: FnFilterMap,
    limit: usize,
) -> anyhow::Result<Vec<Vec<u8>>>
where
    F: Fn(&[u8]) -> bool,
    FnFilterMap: Fn(&[u8]) -> FnFilterMapOutput,
    FnFilterMapOutput: Future<Output = Option<Vec<u8>>>,
{
    let mut result = Vec::new();
    if limit == 0 {
        return Ok(result);
    }
    let Some(mut cursor) = open_iterator(store, start, direction).await? else {
        return Ok(result);
    };
    loop {
        let Some(key) = cursor
            .key()
            .map_err(|error| anyhow!("Failed to read cursor key: {error:?}"))?
        else {
            break;
        };
        let key: Vec<u8> = serde_wasm_bindgen::from_value(key)
            .map_err(|error| anyhow!("Failed to decode cursor key: {error:?}"))?;
        if !take_while(&key) {
            break;
        }
        if let Some(key) = filter_map(&key).await {
            result.push(key);
        }
        if result.len() == limit {
            break;
        }
        cursor
            .next(None)
            .await
            .map_err(|error| anyhow!("Failed to advance cursor: {error:?}"))?;
    }
    Ok(result)
}

pub(crate) async fn handle_db_command<F, FnFilterMap, FnFilterMapOutput>(
    db: &Database,
    store_name: &str,
    cmd: DbCommandRequest,
    invoke_take_while: F,
    invoke_filter_map: FnFilterMap,
    custom_store: Option<ObjectStore>,
) -> anyhow::Result<DbCommandResponse>
where
    F: Fn(&[u8]) -> bool,
    FnFilterMap: Fn(&[u8], &[u8], ObjectStore) -> FnFilterMapOutput + Clone,
    FnFilterMapOutput: Future<Output = Option<Vec<u8>>>,
{
    debug!("Handle command: {:?}", cmd);

    if let DbCommandRequest::Batch { operations } = cmd {
        if custom_store.is_some() {
            bail!("Cannot commit a batch inside an iterator transaction");
        }
        return commit_batch(db, store_name, operations).await;
    }

    let (tran, store) = if let Some(store) = custom_store {
        (None, store)
    } else {
        let tx_mode = match cmd {
            DbCommandRequest::Iterator { .. } | DbCommandRequest::IteratorKey { .. } => {
                TransactionMode::ReadOnly
            }
            DbCommandRequest::Read { .. } => TransactionMode::ReadOnly,
            DbCommandRequest::Put { .. } | DbCommandRequest::Delete { .. } => {
                TransactionMode::ReadWrite
            }
            DbCommandRequest::Batch { .. } => unreachable!(),
        };
        let tran = db
            .transaction(&[&store_name], tx_mode)
            .map_err(|e| anyhow!("Failed to create transaction: {:?}", e))?;

        let store = tran
            .object_store(store_name)
            .map_err(|e| anyhow!("Unable to find store {}: {}", store_name, e))?;
        (Some(tran), store)
    };
    let result = match cmd {
        DbCommandRequest::Batch { .. } => unreachable!(),
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
                        .map(|value| {
                            serde_wasm_bindgen::from_value::<KVPair>(value).map(|row| row.value)
                        })
                        .transpose()
                        .map_err(|error| anyhow!("Failed to decode read value: {error:?}"))?,
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
            start,
            direction,
            limit,
        } => {
            let kvs = collect_iterator(
                &store,
                &start,
                direction,
                invoke_take_while,
                |key, value| {
                    let key = key.to_vec();
                    let value = value.to_vec();
                    let store = store.clone();
                    let invoke_filter_map = invoke_filter_map.clone();
                    async move { invoke_filter_map(&key, &value, store.clone()).await }
                },
                limit,
            )
            .await
            .with_context(|| anyhow!("Failed to collect iterator"))?;
            debug!(
                "Called iterator, args=<{:?}, {:?}, {:?}>, result={:?}",
                start, direction, limit, kvs
            );
            DbCommandResponse::Iterator { kvs }
        }
        DbCommandRequest::IteratorKey {
            start,
            direction,
            limit,
        } => {
            let keys = collect_iterator_keys(
                &store,
                &start,
                direction,
                invoke_take_while,
                |key| {
                    let key = key.to_vec();
                    let store = store.clone();
                    let invoke_filter_map = invoke_filter_map.clone();
                    async move { invoke_filter_map(&key, &[], store.clone()).await }
                },
                limit,
            )
            .await
            .with_context(|| anyhow!("Failed to collect iterator keys"))?;
            DbCommandResponse::IteratorKey { keys }
        }
    };
    if let Some(tran) = tran {
        match tran.await {
            Ok(TransactionResult::Committed) => {}
            Ok(TransactionResult::Aborted) => bail!("Database transaction aborted"),
            Err(error) => bail!("Database transaction failed: {error:?}"),
        }
    }
    debug!("Command result={:?}", result);
    Ok(result)
}

#[cfg(test)]
mod tests;

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
