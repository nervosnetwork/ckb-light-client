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
    start_key_bound: &[u8],
    direction: IteratorDirection,
) -> anyhow::Result<Option<ManagedCursor>> {
    let index = store
        .index("key")
        .map_err(|e| anyhow!("Unable to open key index: {e:?}"))?;
    let cursor_direction = iterator_direction_to_idb(direction);
    let start_key = serde_wasm_bindgen::to_value(&start_key_bound)
        .map_err(|e| anyhow!("Unable to convert key to JsValue: {e:?}"))?;
    let key_range = match direction {
        IteratorDirection::Forward => KeyRange::lower_bound(&start_key, Some(false)),
        IteratorDirection::Reverse => KeyRange::upper_bound(&start_key, Some(false)),
    }
    .map_err(|e| anyhow!("Unable to build key range: {e:?}"))?;

    let cursor = index
        .open_cursor(Some(key_range.into()), Some(cursor_direction))
        .map_err(|e| anyhow!("Failed to open cursor: {e:?}"))?
        .await
        .map_err(|e| anyhow!("Failed to open cursor: {e:?}"))?;
    Ok(cursor.map(|cursor| cursor.into_managed()))
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
    let mut res = Vec::new();
    let skip_first = start.should_skip_first();
    let Some(mut iter) = open_iterator(store, start.key(), direction)
        .await
        .map_err(|e| anyhow!("Failed to open iterator: {e:?}"))?
    else {
        return Ok(res);
    };

    if iter
        .key()
        .map_err(|e| anyhow!("Failed to read key from cursor: {e:?}"))?
        .is_none()
    {
        return Ok(res);
    }

    let raw_value = iter
        .value()
        .map_err(|e| anyhow!("Failed to read value from cursor: {e:?}"))?
        .ok_or_else(|| anyhow!("cursor value is missing"))?;
    let raw_kv: KVPair = serde_wasm_bindgen::from_value(raw_value)
        .map_err(|e| anyhow!("Failed to deserialize key-value: {e:?}"))?;

    if take_while(&raw_kv.key) {
        if !skip_first {
            if let Some(transformed_value) = filter_map(&raw_kv.key, &raw_kv.value).await {
                res.push(KVPair {
                    key: raw_kv.key,
                    value: transformed_value,
                });
            }
        }
    } else {
        return Ok(res);
    }
    loop {
        iter.next(None)
            .await
            .map_err(|e| anyhow!("Failed to advance cursor: {e:?}"))?;
        if res.len() >= limit {
            return Ok(res);
        }

        if iter
            .key()
            .map_err(|e| anyhow!("Failed to read key from cursor: {e:?}"))?
            .is_none()
        {
            return Ok(res);
        }

        let raw_value = iter
            .value()
            .map_err(|e| anyhow!("Failed to read value from cursor: {e:?}"))?
            .ok_or_else(|| anyhow!("cursor value is missing"))?;
        let raw_kv: KVPair = serde_wasm_bindgen::from_value(raw_value)
            .map_err(|e| anyhow!("Failed to deserialize key-value: {e:?}"))?;
        if take_while(&raw_kv.key) {
            if let Some(transformed_value) = filter_map(&raw_kv.key, &raw_kv.value).await {
                res.push(KVPair {
                    key: raw_kv.key,
                    value: transformed_value,
                });
            }
        } else {
            return Ok(res);
        }
    }
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
    let mut res = Vec::new();
    let skip_first = start.should_skip_first();
    let Some(mut iter) = open_iterator(store, start.key(), direction)
        .await
        .map_err(|e| anyhow!("Failed to open iterator: {e:?}"))?
    else {
        return Ok(res);
    };

    let Some(raw_key) = iter
        .key()
        .map_err(|e| anyhow!("Failed to read key from cursor: {e:?}"))?
    else {
        return Ok(res);
    };
    let raw_key: Vec<u8> = serde_wasm_bindgen::from_value(raw_key)
        .map_err(|e| anyhow!("Failed to deserialize key: {e:?}"))?;

    if take_while(&raw_key) {
        if !skip_first {
            if let Some(new_key) = filter_map(&raw_key).await {
                res.push(new_key);
            }
        }
    } else {
        return Ok(res);
    }

    loop {
        iter.next(None)
            .await
            .map_err(|e| anyhow!("Failed to advance cursor: {e:?}"))?;
        if res.len() >= limit {
            return Ok(res);
        }

        let key = iter
            .key()
            .map_err(|e| anyhow!("Failed to read key from cursor: {e:?}"))?;
        let Some(key) = key else {
            return Ok(res);
        };

        let raw_key: Vec<u8> = serde_wasm_bindgen::from_value(key)
            .map_err(|e| anyhow!("Failed to deserialize key: {e:?}"))?;
        if take_while(&raw_key) {
            if let Some(new_key) = filter_map(&raw_key).await {
                res.push(new_key);
            }
        } else {
            return Ok(res);
        }
    }
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

                let value = match store
                    .get(key)
                    .map_err(|e| anyhow!("Failed to send get request: {:?}", e))?
                    .await
                    .map_err(|e| anyhow!("Failed to fetch value: {:?}", e))?
                {
                    Some(value) => Some(
                        serde_wasm_bindgen::from_value::<KVPair>(value)
                            .map_err(|e| anyhow!("Failed to deserialize key-value: {:?}", e))?
                            .value,
                    ),
                    None => None,
                };
                res.push(value);
            }
            DbCommandResponse::Read { values: res }
        }
        DbCommandRequest::Put { kvs } => {
            debug!("Putting: {:?}", kvs);
            for kv in kvs {
                let key = serde_wasm_bindgen::to_value(&kv.key)
                    .map_err(|e| anyhow!("Unable to convert key to JsValue: {:?}", e))?;
                let value = serde_wasm_bindgen::to_value(&kv)
                    .map_err(|e| anyhow!("Unable to convert value to JsValue: {:?}", e))?;
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
                let key = serde_wasm_bindgen::to_value(&key)
                    .map_err(|e| anyhow!("Unable to convert key to JsValue: {:?}", e))?;
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
        let transaction_result = tran
            .await
            .map_err(|e| anyhow!("Failed to commit transaction: {e:?}"))?;
        if transaction_result != TransactionResult::Committed {
            return Err(anyhow!(
                "transaction was not committed: {transaction_result:?}"
            ));
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
        let database = match event.database() {
            Ok(database) => database,
            Err(err) => {
                log::error!("failed to get database on upgrade: {err:?}");
                return;
            }
        };
        let store_params = ObjectStoreParams::new();

        let store = match database.create_object_store(STORE_NAME, store_params) {
            Ok(store) => store,
            Err(err) => {
                log::error!("failed to create object store: {err:?}");
                return;
            }
        };
        let mut index_params = IndexParams::new();
        index_params.unique(true);
        if let Err(err) = store.create_index("key", KeyPath::new_single("key"), Some(index_params))
        {
            log::error!("failed to create key index: {err:?}");
        }
    });
    open_request
        .await
        .map_err(|e| anyhow!("Failed to open database: {:?}", e))
}
