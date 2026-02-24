/// Shared helper functions for RPC and WASM modules
/// This module contains common business logic that was previously duplicated
/// between light-client-bin/src/rpc.rs and wasm/light-client-wasm/src/lib.rs
use ckb_jsonrpc_types::JsonBytes;
use ckb_types::{core, packed};

use crate::error::{Error, Result};
use crate::service::{Order, ScriptType, SearchKey};
use crate::storage::{extract_raw_data, IteratorDirection, IteratorStart, KeyPrefix};

const MAX_PREFIX_SEARCH_SIZE: usize = u16::MAX as usize;

/// Query options: (prefix, start, direction)
type QueryOptions = (Vec<u8>, IteratorStart, IteratorDirection);

/// Filter options: (filter_prefix, script_len_range, output_data_len_range, output_capacity_range, block_range)
type FilterOptions = (
    Option<Vec<u8>>,
    Option<[usize; 2]>,
    Option<[usize; 2]>,
    Option<[core::Capacity; 2]>,
    Option<[core::BlockNumber; 2]>,
);

/// Build query options from search parameters
///
/// Returns: (prefix, start, direction)
pub fn build_query_options(
    search_key: &SearchKey,
    lock_prefix: KeyPrefix,
    type_prefix: KeyPrefix,
    order: Order,
    after_cursor: Option<JsonBytes>,
) -> Result<QueryOptions> {
    let mut prefix = match search_key.script_type {
        ScriptType::Lock => vec![lock_prefix as u8],
        ScriptType::Type => vec![type_prefix as u8],
    };

    let script: packed::Script = search_key.script.clone().into();
    let args_len = script.args().len();
    if args_len > MAX_PREFIX_SEARCH_SIZE {
        return Err(Error::config(format!(
            "search_key.script.args len should be less than {}",
            MAX_PREFIX_SEARCH_SIZE
        )));
    }
    prefix.extend_from_slice(extract_raw_data(&script).as_slice());

    let (start, direction) = match order {
        Order::Asc => after_cursor.map_or_else(
            || {
                (
                    IteratorStart::From(prefix.clone()),
                    IteratorDirection::Forward,
                )
            },
            |json_bytes| {
                (
                    IteratorStart::After(json_bytes.as_bytes().into()),
                    IteratorDirection::Forward,
                )
            },
        ),
        Order::Desc => after_cursor.map_or_else(
            || {
                (
                    IteratorStart::From(
                        [
                            prefix.clone(),
                            vec![0xff; MAX_PREFIX_SEARCH_SIZE - args_len],
                        ]
                        .concat(),
                    ),
                    IteratorDirection::Reverse,
                )
            },
            |json_bytes| {
                (
                    IteratorStart::After(json_bytes.as_bytes().into()),
                    IteratorDirection::Reverse,
                )
            },
        ),
    };

    Ok((prefix, start, direction))
}

/// Build filter options from search parameters
///
/// Returns: (filter_prefix, script_len_range, output_data_len_range, output_capacity_range, block_range)
pub fn build_filter_options(search_key: SearchKey) -> Result<FilterOptions> {
    let filter = search_key.filter.unwrap_or_default();

    let filter_script_prefix = if let Some(script) = filter.script {
        let script: packed::Script = script.into();
        if script.args().len() > MAX_PREFIX_SEARCH_SIZE {
            return Err(Error::config(format!(
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
