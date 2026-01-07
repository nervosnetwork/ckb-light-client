use jsonrpc_core::{Error, Result};

use ckb_light_client_lib::{
    service::{
        Cell, CellType, CellsCapacity, Order, Pagination, ScriptStatus, ScriptType, SearchKey,
        SetScriptsCommand, Tx, TxWithCell, TxWithCells,
    },
    storage::{self, extract_raw_data, CursorDirection, Key, KeyPrefix, KV, LAST_STATE_KEY},
};

use crate::rpc::{BlockFilterRpc, BlockFilterRpcImpl};
use ckb_jsonrpc_types::{JsonBytes, Uint32};
use ckb_types::{core, packed, prelude::*};

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let swc = self.swc.clone();
        std::thread::spawn(move || {
            let mut matched_blocks = swc.matched_blocks().blocking_write();
            let scripts = scripts.into_iter().map(Into::into).collect();
            swc.storage()
                .update_filter_scripts(scripts, command.map(Into::into).unwrap_or_default());
            matched_blocks.clear();
            tx.send(()).unwrap();
        });
        rx.recv().unwrap();
        Ok(())
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        let scripts = self.swc.storage().get_filter_scripts();
        Ok(scripts.into_iter().map(Into::into).collect())
    }

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        let (prefix, from_key, direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::CellLockScript,
            KeyPrefix::CellTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::invalid_params("limit should be greater than 0"));
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

        fn extract_data_from_key(key: &[u8]) -> (u32, u32, u64) {
            let output_index = u32::from_be_bytes(
                key[key.len() - 4..]
                    .try_into()
                    .expect("stored output_index"),
            );
            let tx_index = u32::from_be_bytes(
                key[key.len() - 8..key.len() - 4]
                    .try_into()
                    .expect("stored tx_index"),
            );
            let block_number = u64::from_be_bytes(
                key[key.len() - 16..key.len() - 8]
                    .try_into()
                    .expect("stored block_number"),
            );
            (output_index, tx_index, block_number)
        }

        let storage = self.swc.storage();
        let kvs: Vec<_> = storage
            .collect_iterator(
                &from_key.clone(),
                direction,
                |key| key.starts_with(&prefix),
                |key, value| {
                    let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                    let (output_index, _tx_index, block_number) = extract_data_from_key(key);
                    let tx_data = &storage
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .unwrap()
                        .expect("stored tx")[12..];
                    let tx = packed::Transaction::from_slice(tx_data)
                        .expect("from stored tx slice should be OK");
                    let output = tx
                        .raw()
                        .outputs()
                        .get(output_index as usize)
                        .expect("get output by index should be OK");
                    let output_data = tx
                        .raw()
                        .outputs_data()
                        .get(output_index as usize)
                        .expect("get output data by index should be OK");

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
                    Some(KV {
                        key: key.to_vec(),
                        value: value.to_vec(),
                    })
                },
                limit,
                skip,
            )
            .map_err(|e| Error::invalid_params(&format!("Unable to search transactions: {}", e)))?;
        let mut cells = Vec::new();
        let mut last_key = Vec::new();
        for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
            let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
            let (output_index, tx_index, block_number) = extract_data_from_key(&key);
            let tx = packed::Transaction::from_slice(
                &storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .unwrap()
                    .expect("stored tx")[12..],
            )
            .expect("from stored tx slice should be OK");
            let output = tx
                .raw()
                .outputs()
                .get(output_index as usize)
                .expect("get output by index should be OK");
            let output_data = tx
                .raw()
                .outputs_data()
                .get(output_index as usize)
                .expect("get output data by index should be OK");

            last_key = key.to_vec();
            let cell_to_push = Cell {
                output: output.into(),
                output_data: if with_data {
                    Some(output_data.into())
                } else {
                    None
                },
                out_point: packed::OutPoint::new(tx_hash, output_index).into(),
                block_number: block_number.into(),
                tx_index: tx_index.into(),
            };
            cells.push(cell_to_push);
            if cells.len() >= limit {
                break;
            }
        }

        Ok(Pagination {
            objects: cells,
            last_cursor: JsonBytes::from_vec(last_key),
        })
    }

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>> {
        let (prefix, from_key, direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::TxLockScript,
            KeyPrefix::TxTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::invalid_params("limit should be greater than 0"));
        }

        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let (filter_script, filter_block_range) = if let Some(filter) = search_key.filter.as_ref() {
            if filter.output_data_len_range.is_some() {
                return Err(Error::invalid_params(
                    "doesn't support search_key.filter.output_data_len_range parameter",
                ));
            }
            if filter.output_capacity_range.is_some() {
                return Err(Error::invalid_params(
                    "doesn't support search_key.filter.output_capacity_range parameter",
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

        let storage = self.swc.storage();

        if search_key.group_by_transaction.unwrap_or_default() {
            let prefix_cloned = prefix.clone();
            let mut kvs: Vec<_> = storage
                .collect_iterator(
                    &from_key,
                    direction,
                    |key| key.starts_with(&prefix_cloned),
                    |key, value| {
                        Some(KV {
                            key: key.to_vec(),
                            value: value.to_vec(),
                        })
                    },
                    100,
                    skip,
                )
                .map_err(|e| {
                    Error::invalid_params(&format!("Unable to search transactions: {}", e))
                })?;
            let mut tx_with_cells: Vec<TxWithCells> = Vec::new();
            let mut last_key = Vec::new();

            'outer: while !kvs.is_empty() {
                for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
                    let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                    if tx_with_cells.len() == limit
                        && tx_with_cells.last_mut().unwrap().transaction.hash != tx_hash.unpack()
                    {
                        break 'outer;
                    }
                    last_key = key.to_vec();
                    let tx = packed::Transaction::from_slice(
                        &storage
                            .get(Key::TxHash(&tx_hash).into_vec())
                            .expect("get tx should be OK")
                            .expect("stored tx")[12..],
                    )
                    .expect("from stored tx slice should be OK");

                    let block_number = u64::from_be_bytes(
                        key[key.len() - 17..key.len() - 9]
                            .try_into()
                            .expect("stored block_number"),
                    );
                    let tx_index = u32::from_be_bytes(
                        key[key.len() - 9..key.len() - 5]
                            .try_into()
                            .expect("stored tx_index"),
                    );
                    let io_index = u32::from_be_bytes(
                        key[key.len() - 5..key.len() - 1]
                            .try_into()
                            .expect("stored io_index"),
                    );
                    let io_type = if *key.last().expect("stored io_type") == 0 {
                        CellType::Input
                    } else {
                        CellType::Output
                    };

                    if let Some(filter_script) = filter_script.as_ref() {
                        let filter_script_matched = match filter_script_type {
                            ScriptType::Lock => storage
                                .get(
                                    Key::TxLockScript(
                                        filter_script,
                                        block_number,
                                        tx_index,
                                        io_index,
                                        match io_type {
                                            CellType::Input => storage::CellType::Input,
                                            CellType::Output => storage::CellType::Output,
                                        },
                                    )
                                    .into_vec(),
                                )
                                .expect("get TxLockScript should be OK")
                                .is_some(),
                            ScriptType::Type => storage
                                .get(
                                    Key::TxTypeScript(
                                        filter_script,
                                        block_number,
                                        tx_index,
                                        io_index,
                                        match io_type {
                                            CellType::Input => storage::CellType::Input,
                                            CellType::Output => storage::CellType::Output,
                                        },
                                    )
                                    .into_vec(),
                                )
                                .expect("get TxTypeScript should be OK")
                                .is_some(),
                        };

                        if !filter_script_matched {
                            continue;
                        }
                    }

                    if let Some([r0, r1]) = filter_block_range {
                        if block_number < r0 || block_number >= r1 {
                            continue;
                        }
                    }

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
                let prefix_cloned = prefix.clone();
                kvs = storage
                    .collect_iterator(
                        &last_key.clone(),
                        direction,
                        |key| key.starts_with(&prefix_cloned),
                        |k, v| {
                            Some(KV {
                                key: k.to_vec(),
                                value: v.to_vec(),
                            })
                        },
                        100,
                        1,
                    )
                    .map_err(|e| Error::invalid_params(&format!("Unable to search txs: {}", e)))?;
            }
            Ok(Pagination {
                objects: tx_with_cells.into_iter().map(Tx::Grouped).collect(),
                last_cursor: JsonBytes::from_vec(last_key),
            })
        } else {
            let kvs: Vec<_> = storage
                .collect_iterator(
                    &from_key.clone(),
                    direction,
                    |key| key.starts_with(&prefix),
                    move |key, value| {
                        let block_number = u64::from_be_bytes(
                            key[key.len() - 17..key.len() - 9]
                                .try_into()
                                .expect("stored block_number"),
                        );
                        let tx_index = u32::from_be_bytes(
                            key[key.len() - 9..key.len() - 5]
                                .try_into()
                                .expect("stored tx_index"),
                        );
                        let io_index = u32::from_be_bytes(
                            key[key.len() - 5..key.len() - 1]
                                .try_into()
                                .expect("stored io_index"),
                        );
                        let io_type = if *key.last().expect("stored io_type") == 0 {
                            CellType::Input
                        } else {
                            CellType::Output
                        };

                        if let Some(filter_script) = filter_script.as_ref() {
                            match filter_script_type {
                                ScriptType::Lock => {
                                    if storage
                                        .get(
                                            Key::TxLockScript(
                                                filter_script,
                                                block_number,
                                                tx_index,
                                                io_index,
                                                match io_type {
                                                    CellType::Input => storage::CellType::Input,
                                                    CellType::Output => storage::CellType::Output,
                                                },
                                            )
                                            .into_vec(),
                                        )
                                        .expect("get TxLockScript should be OK")
                                        .is_none()
                                    {
                                        return None;
                                    };
                                }
                                ScriptType::Type => {
                                    if storage
                                        .get(
                                            Key::TxTypeScript(
                                                filter_script,
                                                block_number,
                                                tx_index,
                                                io_index,
                                                match io_type {
                                                    CellType::Input => storage::CellType::Input,
                                                    CellType::Output => storage::CellType::Output,
                                                },
                                            )
                                            .into_vec(),
                                        )
                                        .expect("get TxTypeScript should be OK")
                                        .is_none()
                                    {
                                        return None;
                                    };
                                }
                            }
                        }

                        if let Some([r0, r1]) = filter_block_range {
                            if block_number < r0 || block_number >= r1 {
                                return None;
                            }
                        }

                        Some(KV {
                            key: key.to_vec(),
                            value: value.to_vec(),
                        })
                    },
                    limit,
                    skip,
                )
                .map_err(|e| Error::invalid_params(&format!("Unable to search txs: {}", e)))?;

            let mut last_key = Vec::new();
            let mut txs = Vec::new();

            for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                let tx = packed::Transaction::from_slice(
                    &storage
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx")[12..],
                )
                .expect("from stored tx slice should be OK");

                let block_number = u64::from_be_bytes(
                    key[key.len() - 17..key.len() - 9]
                        .try_into()
                        .expect("stored block_number"),
                );
                let tx_index = u32::from_be_bytes(
                    key[key.len() - 9..key.len() - 5]
                        .try_into()
                        .expect("stored tx_index"),
                );
                let io_index = u32::from_be_bytes(
                    key[key.len() - 5..key.len() - 1]
                        .try_into()
                        .expect("stored io_index"),
                );
                let io_type = if *key.last().expect("stored io_type") == 0 {
                    CellType::Input
                } else {
                    CellType::Output
                };

                last_key = key.to_vec();
                let tx_to_push = Tx::Ungrouped(TxWithCell {
                    transaction: tx.into_view().into(),
                    block_number: block_number.into(),
                    tx_index: tx_index.into(),
                    io_index: io_index.into(),
                    io_type,
                });
                txs.push(tx_to_push);
                if txs.len() >= limit {
                    break;
                }
            }

            Ok(Pagination {
                objects: txs,
                last_cursor: JsonBytes::from_vec(last_key),
            })
        }
    }

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        let (prefix, from_key, direction, skip) = build_query_options(
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

        let storage = self.swc.storage();
        log::trace!("get_cells_capacity: before entering collect iterator");

        let kvs: Vec<_> = storage
            .collect_iterator(
                &from_key,
                direction,
                |key| key.starts_with(&prefix),
                |key, value| {
                    let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                    let output_index = u32::from_be_bytes(
                        key[key.len() - 4..]
                            .try_into()
                            .expect("stored output_index"),
                    );
                    let block_number = u64::from_be_bytes(
                        key[key.len() - 16..key.len() - 8]
                            .try_into()
                            .expect("stored block_number"),
                    );

                    let tx = packed::Transaction::from_slice(
                        &storage
                            .get(Key::TxHash(&tx_hash).into_vec())
                            .expect("get tx should be OK")
                            .expect("stored tx")[12..],
                    )
                    .expect("from stored tx slice should be OK");
                    let output = tx
                        .raw()
                        .outputs()
                        .get(output_index as usize)
                        .expect("get output by index should be OK");
                    let output_data = tx
                        .raw()
                        .outputs_data()
                        .get(output_index as usize)
                        .expect("get output data by index should be OK");

                    if let Some(prefix) = filter_prefix.as_ref() {
                        match filter_script_type {
                            ScriptType::Lock => {
                                if !extract_raw_data(&output.lock())
                                    .as_slice()
                                    .starts_with(prefix)
                                {
                                    log::trace!("break at {}", line!());
                                    return None;
                                }
                            }
                            ScriptType::Type => {
                                if output.type_().is_none()
                                    || !extract_raw_data(&output.type_().to_opt().unwrap())
                                        .as_slice()
                                        .starts_with(prefix)
                                {
                                    log::trace!("break at {}", line!());
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
                                    log::trace!("break at {}", line!());
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
                                    log::trace!("break at {}", line!());
                                    return None;
                                }
                            }
                        }
                    }

                    if let Some([r0, r1]) = filter_output_data_len_range {
                        if output_data.len() < r0 || output_data.len() >= r1 {
                            log::trace!("break at {}", line!());
                            return None;
                        }
                    }

                    if let Some([r0, r1]) = filter_output_capacity_range {
                        let capacity: core::Capacity = output.capacity().unpack();
                        if capacity < r0 || capacity >= r1 {
                            log::trace!("break at {}", line!());
                            return None;
                        }
                    }

                    if let Some([r0, r1]) = filter_block_range {
                        if block_number < r0 || block_number >= r1 {
                            log::trace!("break at {}", line!());
                            return None;
                        }
                    }
                    log::trace!("Returning normally at {:?}", key);
                    Some(KV {
                        key: key.to_vec(),
                        value: value.to_vec(),
                    })
                },
                usize::MAX,
                skip,
            )
            .map_err(|e| Error::invalid_params(format!("Unable to search cells: {}", e)))?;

        let mut capacity = 0;
        for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
            let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
            let output_index = u32::from_be_bytes(
                key[key.len() - 4..]
                    .try_into()
                    .expect("stored output_index"),
            );

            let tx = packed::Transaction::from_slice(
                &storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .expect("get tx should be OK")
                    .expect("stored tx")[12..],
            )
            .expect("from stored tx slice should be OK");
            let output = tx
                .raw()
                .outputs()
                .get(output_index as usize)
                .expect("get output by index should be OK");
            capacity += Unpack::<core::Capacity>::unpack(&output.capacity()).as_u64()
        }

        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let tip_header = storage
            .get(key)
            .expect("snapshot get last state should be ok")
            .map(|data| packed::HeaderReader::from_slice_should_be_ok(&data[32..]).to_entity())
            .expect("tip header should be inited");
        log::trace!("Get cells capacity done");
        Ok(CellsCapacity {
            capacity: capacity.into(),
            block_hash: tip_header.calc_header_hash().unpack(),
            block_number: tip_header.raw().number().unpack(),
        })
    }
}

const MAX_PREFIX_SEARCH_SIZE: usize = u16::MAX as usize;

// a helper fn to build query options from search paramters, returns prefix, from_key, direction and skip offset
pub fn build_query_options(
    search_key: &SearchKey,
    lock_prefix: KeyPrefix,
    type_prefix: KeyPrefix,
    order: Order,
    after_cursor: Option<JsonBytes>,
) -> Result<(Vec<u8>, Vec<u8>, CursorDirection, usize)> {
    let mut prefix = match search_key.script_type {
        ScriptType::Lock => vec![lock_prefix as u8],
        ScriptType::Type => vec![type_prefix as u8],
    };
    let script: packed::Script = search_key.script.clone().into();
    let args_len = script.args().len();
    if args_len > MAX_PREFIX_SEARCH_SIZE {
        return Err(Error::invalid_params(&format!(
            "search_key.script.args len should be less than {}",
            MAX_PREFIX_SEARCH_SIZE
        )));
    }
    prefix.extend_from_slice(extract_raw_data(&script).as_slice());

    let (from_key, direction, skip) = match order {
        Order::Asc => after_cursor.map_or_else(
            || (prefix.clone(), CursorDirection::Ascending, 0),
            |json_bytes| (json_bytes.as_bytes().into(), CursorDirection::Ascending, 1),
        ),
        Order::Desc => after_cursor.map_or_else(
            || {
                (
                    [
                        prefix.clone(),
                        vec![0xff; MAX_PREFIX_SEARCH_SIZE - args_len],
                    ]
                    .concat(),
                    CursorDirection::Ascending,
                    0,
                )
            },
            |json_bytes| (json_bytes.as_bytes().into(), CursorDirection::Descending, 1),
        ),
    };

    Ok((prefix, from_key, direction, skip))
}

#[allow(clippy::type_complexity)]
pub fn build_filter_options(
    search_key: SearchKey,
) -> Result<(
    Option<Vec<u8>>,
    Option<[usize; 2]>,
    Option<[usize; 2]>,
    Option<[core::Capacity; 2]>,
    Option<[core::BlockNumber; 2]>,
)> {
    let filter = search_key.filter.unwrap_or_default();
    let filter_script_prefix = if let Some(script) = filter.script {
        let script: packed::Script = script.into();
        if script.args().len() > MAX_PREFIX_SEARCH_SIZE {
            return Err(Error::invalid_params(&format!(
                "search_key.filter.script.args len should be less than {}",
                MAX_PREFIX_SEARCH_SIZE
            )));
        }
        let mut prefix = Vec::new();
        prefix.extend_from_slice(extract_raw_data(&script).as_slice());
        Some(prefix)
    } else {
        None
    };

    let filter_script_len_range = filter.script_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });

    let filter_output_data_len_range = filter.output_data_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });
    let filter_output_capacity_range = filter.output_capacity_range.map(|[r0, r1]| {
        [
            core::Capacity::shannons(r0.into()),
            core::Capacity::shannons(r1.into()),
        ]
    });
    let filter_block_range = filter.block_range.map(|r| [r[0].into(), r[1].into()]);

    Ok((
        filter_script_prefix,
        filter_script_len_range,
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ))
}
