use ckb_jsonrpc_types::{
    BlockNumber, CellOutput, JsonBytes, OutPoint, Script, TransactionView, Uint32, Uint64,
};
use ckb_types::{core, packed, prelude::*, H256};
use jsonrpc_core::{Error, IoHandler, Result};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use rocksdb::{
    ops::{Get, Iterate},
    Direction, IteratorMode,
};
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;

use crate::storage::{self, extract_raw_data, Key, KeyPrefix, Storage};

#[rpc(server)]
pub trait BlockFilterRpc {
    /// curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [[{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}], ["0x59F74D"]], "id": 1}'
    #[rpc(name = "set_scripts")]
    fn set_scripts(&self, scripts: Vec<Script>, block_numbers: Vec<BlockNumber>) -> Result<()>;

    #[rpc(name = "get_cells")]
    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>>;

    #[rpc(name = "get_transactions")]
    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>>;
}

#[derive(Deserialize)]
pub struct SearchKey {
    script: Script,
    script_type: ScriptType,
    filter: Option<SearchKeyFilter>,
}

#[derive(Deserialize, Default)]
pub struct SearchKeyFilter {
    script: Option<Script>,
    output_data_len_range: Option<[Uint64; 2]>,
    output_capacity_range: Option<[Uint64; 2]>,
    block_range: Option<[BlockNumber; 2]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    Lock,
    Type,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    Desc,
    Asc,
}

#[derive(Serialize)]
pub struct Cell {
    output: CellOutput,
    output_data: JsonBytes,
    out_point: OutPoint,
    block_number: BlockNumber,
    tx_index: Uint32,
}

#[derive(Serialize)]
pub struct Tx {
    transaction: TransactionView,
    block_number: BlockNumber,
    tx_index: Uint32,
    io_index: Uint32,
    io_type: CellType,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellType {
    Input,
    Output,
}

#[derive(Serialize)]
pub struct Pagination<T> {
    objects: Vec<T>,
    last_cursor: JsonBytes,
}

pub struct BlockFilterRpcImpl {
    storage: Storage,
}

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(&self, scripts: Vec<Script>, block_numbers: Vec<BlockNumber>) -> Result<()> {
        let scripts = scripts
            .into_iter()
            .zip(block_numbers)
            .map(|(script, block_number)| (script.into(), block_number.into()))
            .collect();

        self.storage.update_filter_scripts(scripts);
        Ok(())
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
        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };
        let (
            filter_prefix,
            filter_output_data_len_range,
            filter_output_capacity_range,
            filter_block_range,
        ) = build_filter_options(search_key)?;
        let mode = IteratorMode::From(from_key.as_ref(), direction);
        let snapshot = self.storage.db.snapshot();
        let iter = snapshot.iterator(mode).skip(skip);

        let mut last_key = Vec::new();
        let cells = iter
            .take_while(|(key, _value)| key.starts_with(&prefix))
            .filter_map(|(key, value)| {
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
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

                let tx = packed::Transaction::from_slice(
                    &snapshot
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx"),
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

                last_key = key.to_vec();

                Some(Cell {
                    output: output.into(),
                    output_data: output_data.into(),
                    out_point: packed::OutPoint::new(tx_hash, output_index).into(),
                    block_number: block_number.into(),
                    tx_index: tx_index.into(),
                })
            })
            .take(limit.value() as usize)
            .collect::<Vec<_>>();

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

        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let mode = IteratorMode::From(from_key.as_ref(), direction);
        let snapshot = self.storage.db.snapshot();
        let iter = snapshot.iterator(mode).skip(skip);

        let mut last_key = Vec::new();
        let txs = iter
            .take_while(|(key, _value)| key.starts_with(&prefix))
            .filter_map(|(key, value)| {
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                let tx = packed::Transaction::from_slice(
                    &snapshot
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx"),
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
                    match filter_script_type {
                        ScriptType::Lock => {
                            snapshot
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
                                .expect("get TxLockScript should be OK")?;
                        }
                        ScriptType::Type => {
                            snapshot
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
                                .expect("get TxTypeScript should be OK")?;
                        }
                    }
                }

                if let Some([r0, r1]) = filter_block_range {
                    if block_number < r0 || block_number >= r1 {
                        return None;
                    }
                }

                last_key = key.to_vec();
                Some(Tx {
                    transaction: tx.into_view().into(),
                    block_number: block_number.into(),
                    tx_index: tx_index.into(),
                    io_index: io_index.into(),
                    io_type,
                })
            })
            .take(limit.value() as usize)
            .collect::<Vec<_>>();

        Ok(Pagination {
            objects: txs,
            last_cursor: JsonBytes::from_vec(last_key),
        })
    }
}

const MAX_PREFIX_SEARCH_SIZE: usize = u16::max_value() as usize;

// a helper fn to build query options from search paramters, returns prefix, from_key, direction and skip offset
fn build_query_options(
    search_key: &SearchKey,
    lock_prefix: KeyPrefix,
    type_prefix: KeyPrefix,
    order: Order,
    after_cursor: Option<JsonBytes>,
) -> Result<(Vec<u8>, Vec<u8>, Direction, usize)> {
    let mut prefix = match search_key.script_type {
        ScriptType::Lock => vec![lock_prefix as u8],
        ScriptType::Type => vec![type_prefix as u8],
    };
    let script: packed::Script = search_key.script.clone().into();
    let args_len = script.args().len();
    if args_len > MAX_PREFIX_SEARCH_SIZE {
        return Err(Error::invalid_params(format!(
            "search_key.script.args len should be less than {}",
            MAX_PREFIX_SEARCH_SIZE
        )));
    }
    prefix.extend_from_slice(extract_raw_data(&script).as_slice());

    let (from_key, direction, skip) = match order {
        Order::Asc => after_cursor.map_or_else(
            || (prefix.clone(), Direction::Forward, 0),
            |json_bytes| (json_bytes.as_bytes().into(), Direction::Forward, 1),
        ),
        Order::Desc => after_cursor.map_or_else(
            || {
                (
                    [
                        prefix.clone(),
                        vec![0xff; MAX_PREFIX_SEARCH_SIZE - args_len],
                    ]
                    .concat(),
                    Direction::Reverse,
                    0,
                )
            },
            |json_bytes| (json_bytes.as_bytes().into(), Direction::Reverse, 1),
        ),
    };

    Ok((prefix, from_key, direction, skip))
}

// a helper fn to build filter options from search paramters, returns prefix, output_data_len_range, output_capacity_range and block_range
#[allow(clippy::type_complexity)]
fn build_filter_options(
    search_key: SearchKey,
) -> Result<(
    Option<Vec<u8>>,
    Option<[usize; 2]>,
    Option<[core::Capacity; 2]>,
    Option<[core::BlockNumber; 2]>,
)> {
    let SearchKey {
        script: _,
        script_type: _,
        filter,
    } = search_key;
    let filter = filter.unwrap_or_default();
    let filter_script_prefix = if let Some(script) = filter.script {
        let script: packed::Script = script.into();
        if script.args().len() > MAX_PREFIX_SEARCH_SIZE {
            return Err(Error::invalid_params(format!(
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
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ))
}

pub struct Service {
    listen_address: String,
}

impl Service {
    pub fn new(listen_address: &str) -> Self {
        Self {
            listen_address: listen_address.to_string(),
        }
    }

    pub fn start(&self, storage: Storage) -> Server {
        let mut io_handler = IoHandler::new();
        let rpc_impl = BlockFilterRpcImpl { storage };
        io_handler.extend_with(rpc_impl.to_delegate());

        ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .health_api(("/ping", "ping"))
            .start_http(
                &self
                    .listen_address
                    .to_socket_addrs()
                    .expect("config listen_address parsed")
                    .next()
                    .expect("config listen_address parsed"),
            )
            .expect("Start Jsonrpc HTTP service")
    }
}
