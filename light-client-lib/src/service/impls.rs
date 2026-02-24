/// Unified Service Layer Implementation
///
/// This module contains the business logic for get_cells, get_transactions, get_cells_capacity,
/// and other methods that were previously duplicated between RPC and WASM implementations.
///
/// The Service struct is generic over storage backends via the LightClientStorage trait,
/// allowing it to work with RocksDB, SQLite, or IndexedDB without code duplication.
use crate::{
    error::{Error, Result},
    service::{
        helpers::{build_filter_options, build_query_options},
        Cell, CellType, CellsCapacity, FetchStatus, Order, Pagination, ScriptType, SearchKey,
        Status, TransactionWithStatus, Tx, TxStatus, TxWithCell, TxWithCells,
    },
    storage::{
        extract_raw_data, Key, KeyPrefix, LightClientStorage, StorageWithChainData, LAST_STATE_KEY,
    },
};
use ckb_chain_spec::consensus::Consensus;
use ckb_jsonrpc_types::{JsonBytes, Transaction, Uint32, Uint64};
use ckb_systemtime::unix_time_as_millis;
use ckb_traits::HeaderProvider;
use ckb_types::{core, packed, prelude::*, H256};
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
        let (prefix, iter_start, iter_direction) = build_query_options(
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

            // Return the original value (tx_hash) to indicate this item passed all filters
            Some(value.to_vec())
        });

        let results = self.storage.collect_iterator(
            iter_start,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            limit,
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
        let (prefix, iter_start, iter_direction) = build_query_options(
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

            Some(value.to_vec())
        });

        let results = self.storage.collect_iterator(
            iter_start,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            usize::MAX, // Don't limit at iterator level for grouping
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
        let (prefix, iter_start, iter_direction) = build_query_options(
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
            iter_start,
            iter_direction,
            take_while_fn,
            filter_map_fn,
            usize::MAX,
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

/// Extended Service Layer for Chain Data Operations
///
/// This service provides business logic for operations that require access to
/// StorageWithChainData (storage + peers + pending_txs), such as:
/// - Transaction operations (send, get, fetch)
/// - Header operations (get_tip, get_genesis, get, fetch)
/// - Cycle estimation
#[derive(Clone)]
pub struct LightClientChainService {
    swc: StorageWithChainData,
    consensus: Arc<Consensus>,
}

impl LightClientChainService {
    /// Create a new chain service instance
    pub fn new(swc: StorageWithChainData, consensus: Arc<Consensus>) -> Self {
        Self { swc, consensus }
    }

    /// Get tip header
    pub fn get_tip_header(&self) -> ckb_jsonrpc_types::HeaderView {
        self.swc.storage().get_tip_header().into_view().into()
    }

    /// Get genesis block
    pub fn get_genesis_block(&self) -> ckb_jsonrpc_types::BlockView {
        self.swc.storage().get_genesis_block().into_view().into()
    }

    /// Get header by block hash
    pub fn get_header(&self, block_hash: &H256) -> Option<ckb_jsonrpc_types::HeaderView> {
        self.swc.get_header(&block_hash.pack()).map(Into::into)
    }

    /// Fetch header by block hash (with fetch status tracking)
    pub fn fetch_header(&self, block_hash: &H256) -> FetchStatus<ckb_jsonrpc_types::HeaderView> {
        if let Some(value) = self.swc.get_header(&block_hash.pack()) {
            return FetchStatus::Fetched { data: value.into() };
        }

        let now = unix_time_as_millis();
        if let Some((added_ts, first_sent, missing)) = self.swc.get_header_fetch_info(block_hash) {
            if missing {
                // re-fetch the header
                self.swc.add_fetch_header(block_hash.clone(), now);
                return FetchStatus::NotFound;
            } else if first_sent > 0 {
                return FetchStatus::Fetching {
                    first_sent: first_sent.into(),
                };
            } else {
                return FetchStatus::Added {
                    timestamp: added_ts.into(),
                };
            }
        } else {
            self.swc.add_fetch_header(block_hash.clone(), now);
        }
        FetchStatus::Added {
            timestamp: now.into(),
        }
    }

    /// Send transaction
    pub fn send_transaction(&self, tx: Transaction) -> Result<H256> {
        let tx: packed::Transaction = tx.into();
        let tx = tx.into_view();
        let cycles = crate::verify::verify_tx(
            tx.clone(),
            &self.swc,
            Arc::clone(&self.consensus),
            &self.swc.storage().get_last_state().1.into_view(),
        )
        .map_err(|e| Error::runtime(format!("invalid transaction: {:?}", e)))?;

        // Platform-specific pending_txs access
        #[cfg(target_arch = "wasm32")]
        self.swc
            .pending_txs()
            .blocking_write()
            .push(tx.clone(), cycles);
        #[cfg(not(target_arch = "wasm32"))]
        self.swc
            .pending_txs()
            .write()
            .expect("pending_txs lock is poisoned")
            .push(tx.clone(), cycles);

        Ok(tx.hash().unpack())
    }

    /// Get transaction by tx hash
    pub fn get_transaction(&self, tx_hash: &H256) -> TransactionWithStatus {
        // Check storage first
        if let Some((transaction, header)) = self
            .swc
            .storage()
            .get_transaction_with_header(&tx_hash.pack())
        {
            return TransactionWithStatus {
                transaction: Some(transaction.into_view().into()),
                cycles: None,
                tx_status: TxStatus {
                    block_hash: Some(header.into_view().hash().unpack()),
                    status: Status::Committed,
                },
            };
        }

        // Check pending transactions
        #[cfg(target_arch = "wasm32")]
        let pending_result = self.swc.pending_txs().blocking_read().get(&tx_hash.pack());
        #[cfg(not(target_arch = "wasm32"))]
        let pending_result = self
            .swc
            .pending_txs()
            .read()
            .expect("pending_txs lock is poisoned")
            .get(&tx_hash.pack());

        if let Some((transaction, cycles, _)) = pending_result {
            return TransactionWithStatus {
                transaction: Some(transaction.into_view().into()),
                cycles: Some(cycles.into()),
                tx_status: TxStatus {
                    block_hash: None,
                    status: Status::Pending,
                },
            };
        }

        // Not found
        TransactionWithStatus {
            transaction: None,
            cycles: None,
            tx_status: TxStatus {
                block_hash: None,
                status: Status::Unknown,
            },
        }
    }

    /// Fetch transaction by tx hash (with fetch status tracking)
    pub fn fetch_transaction(&self, tx_hash: &H256) -> FetchStatus<TransactionWithStatus> {
        let tws = self.get_transaction(tx_hash);
        if tws.transaction.is_some() {
            return FetchStatus::Fetched { data: tws };
        }

        let now = unix_time_as_millis();
        if let Some((added_ts, first_sent, missing)) = self.swc.get_tx_fetch_info(tx_hash) {
            if missing {
                // re-fetch the transaction
                self.swc.add_fetch_tx(tx_hash.clone(), now);
                return FetchStatus::NotFound;
            } else if first_sent > 0 {
                return FetchStatus::Fetching {
                    first_sent: first_sent.into(),
                };
            } else {
                return FetchStatus::Added {
                    timestamp: added_ts.into(),
                };
            }
        } else {
            self.swc.add_fetch_tx(tx_hash.clone(), now);
        }
        FetchStatus::Added {
            timestamp: now.into(),
        }
    }

    /// Estimate cycles for a transaction
    pub fn estimate_cycles(&self, tx: Transaction) -> Result<Uint64> {
        let tx: packed::Transaction = tx.into();
        let tx = tx.into_view();
        let cycles = crate::verify::verify_tx(
            tx.clone(),
            &self.swc,
            Arc::clone(&self.consensus),
            &self.swc.storage().get_last_state().1.into_view(),
        )
        .map_err(|e| Error::runtime(format!("invalid transaction: {:?}", e)))?;
        Ok(cycles.into())
    }

    /// Set filter scripts
    pub fn set_scripts(
        &self,
        scripts: Vec<crate::service::ScriptStatus>,
        command: Option<crate::service::SetScriptsCommand>,
    ) {
        // Platform-specific matched_blocks access
        // On native, use block_in_place to allow blocking operations within an async runtime context.
        // This is necessary because set_scripts may be called from RPC handlers running
        // inside a tokio runtime, where blocking_write() would panic.
        // On wasm, blocking_write() can be called directly since it's single-threaded.
        #[cfg(target_arch = "wasm32")]
        let mut matched_blocks = self.swc.matched_blocks().blocking_write();
        #[cfg(not(target_arch = "wasm32"))]
        let mut matched_blocks =
            tokio::task::block_in_place(|| self.swc.matched_blocks().blocking_write());

        let scripts = scripts.into_iter().map(Into::into).collect();
        self.swc
            .storage()
            .update_filter_scripts(scripts, command.map(Into::into).unwrap_or_default());
        matched_blocks.clear();
    }

    /// Get filter scripts
    pub fn get_scripts(&self) -> Vec<crate::service::ScriptStatus> {
        let scripts = self.swc.storage().get_filter_scripts();
        scripts.into_iter().map(Into::into).collect()
    }
}

/// Network Service Layer
///
/// This service provides business logic for network operations that require access to
/// NetworkController and Peers, such as:
/// - Local node info
/// - Peer information
pub struct LightClientNetworkService {
    network_controller: ckb_network::NetworkController,
    peers: Arc<crate::protocols::Peers>,
}

impl LightClientNetworkService {
    /// Create a new network service instance
    pub fn new(
        network_controller: ckb_network::NetworkController,
        peers: Arc<crate::protocols::Peers>,
    ) -> Self {
        Self {
            network_controller,
            peers,
        }
    }

    /// Get local node info
    pub fn local_node_info(&self, max_addrs: usize) -> crate::service::LocalNode {
        crate::service::LocalNode {
            version: self.network_controller.version().to_owned(),
            node_id: self.network_controller.node_id(),
            active: self.network_controller.is_active(),
            addresses: self
                .network_controller
                .public_urls(max_addrs)
                .into_iter()
                .map(|(address, score)| ckb_jsonrpc_types::NodeAddress {
                    address,
                    score: u64::from(score).into(),
                })
                .collect(),
            protocols: self
                .network_controller
                .protocols()
                .into_iter()
                .map(
                    |(protocol_id, name, support_versions)| crate::service::LocalNodeProtocol {
                        id: (protocol_id.value() as u64).into(),
                        name,
                        support_versions,
                    },
                )
                .collect::<Vec<_>>(),
            connections: (self.network_controller.connected_peers().len() as u64).into(),
        }
    }

    /// Get peers
    pub fn get_peers(&self) -> Vec<crate::service::RemoteNode> {
        self.network_controller
            .connected_peers()
            .iter()
            .map(|(peer_index, peer)| {
                let mut addresses = vec![&peer.connected_addr];
                addresses.extend(peer.listened_addrs.iter());

                let node_addresses = addresses
                    .iter()
                    .map(|addr| {
                        let score = self
                            .network_controller
                            .addr_info(addr)
                            .map(|addr_info| addr_info.score)
                            .unwrap_or(1);
                        let non_negative_score = if score > 0 { score as u64 } else { 0 };
                        ckb_jsonrpc_types::NodeAddress {
                            address: addr.to_string(),
                            score: non_negative_score.into(),
                        }
                    })
                    .collect();

                crate::service::RemoteNode {
                    version: peer
                        .identify_info
                        .as_ref()
                        .map(|info| info.client_version.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    node_id: ckb_network::extract_peer_id(&peer.connected_addr)
                        .map(|peer_id| peer_id.to_base58())
                        .unwrap_or_default(),
                    addresses: node_addresses,
                    connected_duration: {
                        #[cfg(target_arch = "wasm32")]
                        {
                            (ckb_systemtime::Instant::now()
                                .saturating_duration_since(peer.connected_time)
                                .as_millis() as u64)
                                .into()
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            (std::time::Instant::now()
                                .saturating_duration_since(peer.connected_time)
                                .as_millis() as u64)
                                .into()
                        }
                    },
                    sync_state: self.peers.get_state(peer_index).map(|state| {
                        crate::service::PeerSyncState {
                            requested_best_known_header: state.get_prove_request().map(|request| {
                                request.get_last_header().header().to_owned().into()
                            }),
                            proved_best_known_header: state.get_prove_state().map(|request| {
                                request.get_last_header().header().to_owned().into()
                            }),
                        }
                    }),
                    protocols: peer
                        .protocols
                        .iter()
                        .map(|(protocol_id, protocol_version)| {
                            ckb_jsonrpc_types::RemoteNodeProtocol {
                                id: (protocol_id.value() as u64).into(),
                                version: protocol_version.clone(),
                            }
                        })
                        .collect(),
                }
            })
            .collect()
    }
}
