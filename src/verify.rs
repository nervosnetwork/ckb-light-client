use std::collections::{hash_map::Entry, HashMap, HashSet};

use ckb_chain_spec::consensus::Consensus;
use ckb_error::Error;
use ckb_script::TxVerifyEnv;
use ckb_types::{
    core::{
        cell::{CellMeta, CellProvider, CellStatus, ResolvedTransaction},
        error::OutPointError,
        Cycle, DepType, TransactionView,
    },
    packed::{OutPoint, OutPointVec},
    prelude::Entity,
};
use ckb_verification::{
    CapacityVerifier, NonContextualTransactionVerifier, ScriptVerifier,
    TimeRelativeTransactionVerifier,
};

use crate::storage::StorageWithLastHeaders;

/// Light client can only verify non-cellbase transaction,
/// can not reuse the `ContextualTransactionVerifier` in ckb_verification crate which is used to verify cellbase also.
pub struct ContextualTransactionVerifier<'a> {
    pub(crate) time_relative: TimeRelativeTransactionVerifier<'a, StorageWithLastHeaders>,
    pub(crate) capacity: CapacityVerifier<'a>,
    pub(crate) script: ScriptVerifier<'a, StorageWithLastHeaders>,
}

impl<'a> ContextualTransactionVerifier<'a> {
    /// Creates a new ContextualTransactionVerifier
    pub fn new(
        rtx: &'a ResolvedTransaction,
        consensus: &'a Consensus,
        swl: &'a StorageWithLastHeaders,
        tx_env: &'a TxVerifyEnv,
    ) -> Self {
        ContextualTransactionVerifier {
            time_relative: TimeRelativeTransactionVerifier::new(rtx, consensus, swl, tx_env),
            script: ScriptVerifier::new(rtx, swl),
            capacity: CapacityVerifier::new(rtx, consensus.dao_type_hash()),
        }
    }

    pub fn verify(&self, max_cycles: Cycle) -> Result<Cycle, Error> {
        self.time_relative.verify()?;
        self.capacity.verify()?;
        self.script.verify(max_cycles)
    }
}

pub fn verify_tx(
    transaction: TransactionView,
    swl: &StorageWithLastHeaders,
    consensus: &Consensus,
) -> Result<Cycle, Error> {
    NonContextualTransactionVerifier::new(&transaction, consensus).verify()?;

    let rtx = resolve_tx(swl, transaction)?;
    let (_, tip_header) = swl.storage().get_last_state();
    let tx_env = TxVerifyEnv::new_submit(&tip_header.into_view());
    ContextualTransactionVerifier::new(&rtx, consensus, swl, &tx_env)
        .verify(consensus.max_block_cycles())
}

#[allow(clippy::mutable_key_type)]
fn resolve_tx(
    swl: &StorageWithLastHeaders,
    transaction: TransactionView,
) -> Result<ResolvedTransaction, OutPointError> {
    let (mut resolved_inputs, mut resolved_cell_deps, mut resolved_dep_groups) = (
        Vec::with_capacity(transaction.inputs().len()),
        Vec::with_capacity(transaction.cell_deps().len()),
        Vec::new(),
    );
    let mut current_inputs = HashSet::new();

    let mut resolved_cells: HashMap<(OutPoint, bool), CellMeta> = HashMap::new();
    let mut resolve_cell =
        |out_point: &OutPoint, eager_load: bool| -> Result<CellMeta, OutPointError> {
            match resolved_cells.entry((out_point.clone(), eager_load)) {
                Entry::Occupied(entry) => Ok(entry.get().clone()),
                Entry::Vacant(entry) => {
                    let cell_status = swl.cell(out_point, eager_load);
                    match cell_status {
                        CellStatus::Dead => Err(OutPointError::Dead(out_point.clone())),
                        CellStatus::Unknown => Err(OutPointError::Unknown(out_point.clone())),
                        CellStatus::Live(cell_meta) => {
                            entry.insert(cell_meta.clone());
                            Ok(cell_meta)
                        }
                    }
                }
            }
        };

    for out_point in transaction.input_pts_iter() {
        if !current_inputs.insert(out_point.to_owned()) {
            return Err(OutPointError::Dead(out_point));
        }
        resolved_inputs.push(resolve_cell(&out_point, false)?);
    }

    for cell_dep in transaction.cell_deps_iter() {
        if cell_dep.dep_type() == DepType::DepGroup.into() {
            let outpoint = cell_dep.out_point();
            let dep_group = resolve_cell(&outpoint, true)?;
            let data = dep_group
                .mem_cell_data
                .as_ref()
                .expect("Load cell meta must with data");
            let sub_out_points =
                parse_dep_group_data(data).map_err(|_| OutPointError::InvalidDepGroup(outpoint))?;

            for sub_out_point in sub_out_points.into_iter() {
                resolved_cell_deps.push(resolve_cell(&sub_out_point, false)?);
            }
            resolved_dep_groups.push(dep_group);
        } else {
            resolved_cell_deps.push(resolve_cell(&cell_dep.out_point(), false)?);
        }
    }

    Ok(ResolvedTransaction {
        transaction,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups,
    })
}

fn parse_dep_group_data(slice: &[u8]) -> Result<OutPointVec, String> {
    if slice.is_empty() {
        Err("data is empty".to_owned())
    } else {
        match OutPointVec::from_slice(slice) {
            Ok(v) => {
                if v.is_empty() {
                    Err("dep group is empty".to_owned())
                } else {
                    Ok(v)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }
}
