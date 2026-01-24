/// Unified Service Layer Implementation
///
/// This module contains the business logic for get_cells, get_transactions, and get_cells_capacity
/// that was previously duplicated between RPC and WASM implementations.
///
/// The Service struct is generic over storage backends via the LightClientStorage trait,
/// allowing it to work with RocksDB, SQLite, or IndexedDB without code duplication.
use crate::{
    error::{Error, Result},
    service::{
        Cell, CellType, CellsCapacity, Order, Pagination, ScriptType, SearchKey, Tx, TxWithCell,
        TxWithCells,
    },
    service_helpers::{build_filter_options, build_query_options},
    storage::{extract_raw_data, Key, KeyPrefix, LightClientStorage, Storage, LAST_STATE_KEY},
};
use ckb_jsonrpc_types::{JsonBytes, Uint32};
use ckb_types::{core, packed, prelude::*};
use std::sync::Arc;

/// Unified Service struct that works with any storage backend
pub struct LightClientService<S: LightClientStorage> {
    storage: Arc<S>,
}

impl<S: LightClientStorage + 'static> LightClientService<S> {
    /// Create a new service instance with the given storage backend
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    /// Get cells by search key with pagination
    ///
    /// This method implements the core business logic for retrieving cells,
    /// including filtering by script, capacity, data length, and block range.
    pub fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        let (prefix, from_key, iter_direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::CellLockScript,
            KeyPrefix::CellTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::config("limit should be greater than 0".to_string()));
        }

        let with_data = search_key.with_data.unwrap_or(true);
        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let (
            filter_prefix,
            filter_script_len_range,
            filter_output_data_len_range,
            filter_output_capacity_range,
            filter_block_range,
        ) = build_filter_options(search_key)?;

        // Use collect_iterator with custom logic
        let take_while_fn = Box::new(move |key: &[u8]| key.starts_with(&prefix));

        let storage_clone = Arc::clone(&self.storage);
        let filter_map_fn = Box::new(move |key: &[u8], value: &[u8]| -> Option<Vec<u8>> {
            let tx_hash = packed::Byte32::from_slice(value).ok()?;
            let output_index = u32::from_be_bytes(key[key.len() - 4..].try_into().ok()?);
            let _tx_index = u32::from_be_bytes(key[key.len() - 8..key.len() - 4].try_into().ok()?);
            let block_number =
                u64::from_be_bytes(key[key.len() - 16..key.len() - 8].try_into().ok()?);

            // Get transaction from storage
            let tx_data = storage_clone.get(Key::TxHash(&tx_hash).into_vec()).ok()??;
            let tx = packed::Transaction::from_slice(&tx_data[12..]).ok()?;

            let output = tx.raw().outputs().get(output_index as usize)?;
            let output_data = tx.raw().outputs_data().get(output_index as usize)?;

            // Apply filters
            if let Some(prefix) = filter_prefix.as_ref() {
                match filter_script_type {
                    ScriptType::Lock => {
                        if !extract_raw_data(&output.lock())
                            .as_slice()
                            .starts_with(prefix)
                        {
                            return None;
                        }
                    }
                    ScriptType::Type => {
                        if output.type_().is_none()
                            || !extract_raw_data(&output.type_().to_opt().unwrap())
                                .as_slice()
                                .starts_with(prefix)
                        {
                            return None;
                        }
                    }
                }
            }

            if let Some([r0, r1]) = filter_script_len_range {
                match filter_script_type {
                    ScriptType::Lock => {
                        let script_len = extract_raw_data(&output.lock()).len();
                        if script_len < r0 || script_len > r1 {
                            return None;
                        }
                    }
                    ScriptType::Type => {
                        let script_len = output
                            .type_()
                            .to_opt()
                            .map(|script| extract_raw_data(&script).len())
                            .unwrap_or_default();
                        if script_len < r0 || script_len > r1 {
                            return None;
                        }
                    }
                }
            }

            if let Some([r0, r1]) = filter_output_data_len_range {
                if output_data.len() < r0 || output_data.len() >= r1 {
                    return None;
                }
            }

            if let Some([r0, r1]) = filter_output_capacity_range {
                let capacity: core::Capacity = output.capacity().unpack();
                if capacity < r0 || capacity >= r1 {
                    return None;
                }
            }

            if let Some([r0, r1]) = filter_block_range {
                if block_number < r0 || block_number >= r1 {
                    return None;
                }
            }

            // Return the key to indicate this item passed all filters
            Some(key.to_vec())
        });

        let results = self.storage.collect_iterator(
            from_key,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            limit,
            skip,
        );

        // Convert results to Cell objects
        let mut last_key = Vec::new();
        let cells = results
            .into_iter()
            .filter_map(|kv_pair| {
                let key = kv_pair.key;
                let value = kv_pair.value;

                let tx_hash = packed::Byte32::from_slice(&value).ok()?;
                let output_index = u32::from_be_bytes(key[key.len() - 4..].try_into().ok()?);
                let tx_index =
                    u32::from_be_bytes(key[key.len() - 8..key.len() - 4].try_into().ok()?);
                let block_number =
                    u64::from_be_bytes(key[key.len() - 16..key.len() - 8].try_into().ok()?);

                let tx_data = self.storage.get(Key::TxHash(&tx_hash).into_vec()).ok()??;
                let tx = packed::Transaction::from_slice(&tx_data[12..]).ok()?;
                let output = tx.raw().outputs().get(output_index as usize)?;
                let output_data = tx.raw().outputs_data().get(output_index as usize)?;

                last_key = key;

                Some(Cell {
                    output: output.into(),
                    output_data: if with_data {
                        Some(output_data.into())
                    } else {
                        None
                    },
                    out_point: packed::OutPoint::new(tx_hash, output_index).into(),
                    block_number: block_number.into(),
                    tx_index: tx_index.into(),
                })
            })
            .collect();

        Ok(Pagination {
            objects: cells,
            last_cursor: JsonBytes::from_vec(last_key),
        })
    }

    /// Get transactions by search key with pagination
    ///
    /// This method supports two modes:
    /// - group_by_transaction=false: Returns each cell (input/output) as separate transaction entry
    /// - group_by_transaction=true: Groups all cells belonging to same transaction together
    pub fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>> {
        let (prefix, from_key, iter_direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::TxLockScript,
            KeyPrefix::TxTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::config("limit should be greater than 0".to_string()));
        }

        let (filter_script, filter_block_range) = if let Some(filter) = search_key.filter.as_ref() {
            if filter.output_data_len_range.is_some() {
                return Err(Error::config(
                    "doesn't support search_key.filter.output_data_len_range parameter".to_string(),
                ));
            }
            if filter.output_capacity_range.is_some() {
                return Err(Error::config(
                    "doesn't support search_key.filter.output_capacity_range parameter".to_string(),
                ));
            }
            let filter_script: Option<packed::Script> =
                filter.script.as_ref().map(|script| script.clone().into());
            let filter_block_range: Option<[core::BlockNumber; 2]> =
                filter.block_range.map(|r| [r[0].into(), r[1].into()]);
            (filter_script, filter_block_range)
        } else {
            (None, None)
        };

        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let take_while_fn = Box::new(move |key: &[u8]| key.starts_with(&prefix));

        let storage_clone = Arc::clone(&self.storage);
        let filter_script_clone = filter_script.clone();

        let filter_map_fn = Box::new(move |key: &[u8], value: &[u8]| -> Option<Vec<u8>> {
            let _tx_hash = packed::Byte32::from_slice(value).ok()?;
            let block_number =
                u64::from_be_bytes(key[key.len() - 17..key.len() - 9].try_into().ok()?);
            let tx_index = u32::from_be_bytes(key[key.len() - 9..key.len() - 5].try_into().ok()?);
            let io_index = u32::from_be_bytes(key[key.len() - 5..key.len() - 1].try_into().ok()?);
            let io_type = if *key.last()? == 0 {
                crate::storage::CellType::Input
            } else {
                crate::storage::CellType::Output
            };

            if let Some(filter_script) = filter_script_clone.as_ref() {
                let filter_script_matched = match filter_script_type {
                    ScriptType::Lock => storage_clone
                        .get(
                            Key::TxLockScript(
                                filter_script,
                                block_number,
                                tx_index,
                                io_index,
                                io_type,
                            )
                            .into_vec(),
                        )
                        .ok()?
                        .is_some(),
                    ScriptType::Type => storage_clone
                        .get(
                            Key::TxTypeScript(
                                filter_script,
                                block_number,
                                tx_index,
                                io_index,
                                io_type,
                            )
                            .into_vec(),
                        )
                        .ok()?
                        .is_some(),
                };

                if !filter_script_matched {
                    return None;
                }
            }

            if let Some([r0, r1]) = filter_block_range {
                if block_number < r0 || block_number >= r1 {
                    return None;
                }
            }

            Some(key.to_vec())
        });

        let results = self.storage.collect_iterator(
            from_key,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            usize::MAX, // Don't limit at iterator level for grouping
            skip,
        );

        if search_key.group_by_transaction.unwrap_or_default() {
            let mut tx_with_cells: Vec<TxWithCells> = Vec::new();
            let mut last_key = Vec::new();

            for kv_pair in results {
                let key = kv_pair.key;
                let value = kv_pair.value;

                let tx_hash = packed::Byte32::from_slice(&value).ok().unwrap();

                if tx_with_cells.len() == limit
                    && tx_with_cells.last().unwrap().transaction.hash != tx_hash.unpack()
                {
                    break;
                }

                last_key = key.clone();

                let tx_data = self
                    .storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .ok()
                    .unwrap()
                    .unwrap();
                let tx = packed::Transaction::from_slice(&tx_data[12..])
                    .ok()
                    .unwrap();

                let block_number =
                    u64::from_be_bytes(key[key.len() - 17..key.len() - 9].try_into().unwrap());
                let tx_index =
                    u32::from_be_bytes(key[key.len() - 9..key.len() - 5].try_into().unwrap());
                let io_index =
                    u32::from_be_bytes(key[key.len() - 5..key.len() - 1].try_into().unwrap());
                let io_type = if *key.last().unwrap() == 0 {
                    CellType::Input
                } else {
                    CellType::Output
                };

                let last_tx_hash_is_same = tx_with_cells
                    .last_mut()
                    .map(|last| {
                        if last.transaction.hash == tx_hash.unpack() {
                            last.cells.push((io_type.clone(), io_index.into()));
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or_default();

                if !last_tx_hash_is_same {
                    tx_with_cells.push(TxWithCells {
                        transaction: tx.into_view().into(),
                        block_number: block_number.into(),
                        tx_index: tx_index.into(),
                        cells: vec![(io_type, io_index.into())],
                    });
                }
            }

            Ok(Pagination {
                objects: tx_with_cells.into_iter().map(Tx::Grouped).collect(),
                last_cursor: JsonBytes::from_vec(last_key),
            })
        } else {
            let mut last_key = Vec::new();
            let txs = results
                .into_iter()
                .filter_map(|kv_pair| {
                    let key = kv_pair.key;
                    let value = kv_pair.value;

                    let tx_hash = packed::Byte32::from_slice(&value).ok()?;
                    let tx_data = self.storage.get(Key::TxHash(&tx_hash).into_vec()).ok()??;
                    let tx = packed::Transaction::from_slice(&tx_data[12..]).ok()?;

                    let block_number =
                        u64::from_be_bytes(key[key.len() - 17..key.len() - 9].try_into().ok()?);
                    let tx_index =
                        u32::from_be_bytes(key[key.len() - 9..key.len() - 5].try_into().ok()?);
                    let io_index =
                        u32::from_be_bytes(key[key.len() - 5..key.len() - 1].try_into().ok()?);
                    let io_type = if *key.last()? == 0 {
                        CellType::Input
                    } else {
                        CellType::Output
                    };

                    last_key = key;
                    Some(Tx::Ungrouped(TxWithCell {
                        transaction: tx.into_view().into(),
                        block_number: block_number.into(),
                        tx_index: tx_index.into(),
                        io_index: io_index.into(),
                        io_type,
                    }))
                })
                .take(limit)
                .collect::<Vec<_>>();

            Ok(Pagination {
                objects: txs,
                last_cursor: JsonBytes::from_vec(last_key),
            })
        }
    }

    /// Get total capacity of cells matching the search key
    ///
    /// This method calculates the sum of capacities for all cells matching
    /// the search criteria and returns the total along with current tip block info.
    pub fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        let (prefix, from_key, iter_direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::CellLockScript,
            KeyPrefix::CellTypeScript,
            Order::Asc,
            None,
        )?;

        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let (
            filter_prefix,
            filter_script_len_range,
            filter_output_data_len_range,
            filter_output_capacity_range,
            filter_block_range,
        ) = build_filter_options(search_key)?;

        let take_while_fn = Box::new(move |key: &[u8]| key.starts_with(&prefix));

        let storage_clone = Arc::clone(&self.storage);
        let filter_map_fn = Box::new(move |key: &[u8], value: &[u8]| -> Option<Vec<u8>> {
            let tx_hash = packed::Byte32::from_slice(value).ok()?;
            let output_index = u32::from_be_bytes(key[key.len() - 4..].try_into().ok()?);
            let block_number =
                u64::from_be_bytes(key[key.len() - 16..key.len() - 8].try_into().ok()?);

            let tx_data = storage_clone.get(Key::TxHash(&tx_hash).into_vec()).ok()??;
            let tx = packed::Transaction::from_slice(&tx_data[12..]).ok()?;
            let output = tx.raw().outputs().get(output_index as usize)?;
            let output_data = tx.raw().outputs_data().get(output_index as usize)?;

            // Apply filters
            if let Some(prefix) = filter_prefix.as_ref() {
                match filter_script_type {
                    ScriptType::Lock => {
                        if !extract_raw_data(&output.lock())
                            .as_slice()
                            .starts_with(prefix)
                        {
                            return None;
                        }
                    }
                    ScriptType::Type => {
                        if output.type_().is_none()
                            || !extract_raw_data(&output.type_().to_opt().unwrap())
                                .as_slice()
                                .starts_with(prefix)
                        {
                            return None;
                        }
                    }
                }
            }

            if let Some([r0, r1]) = filter_script_len_range {
                match filter_script_type {
                    ScriptType::Lock => {
                        let script_len = extract_raw_data(&output.lock()).len();
                        if script_len < r0 || script_len > r1 {
                            return None;
                        }
                    }
                    ScriptType::Type => {
                        let script_len = output
                            .type_()
                            .to_opt()
                            .map(|script| extract_raw_data(&script).len())
                            .unwrap_or_default();
                        if script_len < r0 || script_len > r1 {
                            return None;
                        }
                    }
                }
            }

            if let Some([r0, r1]) = filter_output_data_len_range {
                if output_data.len() < r0 || output_data.len() >= r1 {
                    return None;
                }
            }

            if let Some([r0, r1]) = filter_output_capacity_range {
                let capacity: core::Capacity = output.capacity().unpack();
                if capacity < r0 || capacity >= r1 {
                    return None;
                }
            }

            if let Some([r0, r1]) = filter_block_range {
                if block_number < r0 || block_number >= r1 {
                    return None;
                }
            }

            // Return capacity as bytes
            Some(
                Unpack::<core::Capacity>::unpack(&output.capacity())
                    .as_u64()
                    .to_le_bytes()
                    .to_vec(),
            )
        });

        let results = self.storage.collect_iterator(
            from_key,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            usize::MAX,
            skip,
        );

        let capacity: u64 = results
            .into_iter()
            .filter_map(|kv_pair| {
                let value = kv_pair.value;
                Some(u64::from_le_bytes(value.try_into().ok()?))
            })
            .sum();

        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let tip_header = self
            .storage
            .get(key)?
            .map(|data| packed::HeaderReader::from_slice_should_be_ok(&data[32..]).to_entity())
            .ok_or_else(|| Error::config("tip header should be inited".to_string()))?;

        Ok(CellsCapacity {
            capacity: capacity.into(),
            block_hash: tip_header.calc_header_hash().unpack(),
            block_number: tip_header.raw().number().unpack(),
        })
    }
}

// Convenience type aliases for common configurations
#[cfg(not(target_arch = "wasm32"))]
pub type NativeService = LightClientService<Storage>;
