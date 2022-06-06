use std::collections::{hash_map::Entry, HashMap, HashSet};

use ckb_chain_spec::consensus::Consensus;
use ckb_error::Error;
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus, ResolvedTransaction},
        error::OutPointError,
        Cycle, DepType, HeaderView, TransactionView,
    },
    packed::{Byte32, OutPoint, OutPointVec},
    prelude::Entity,
};

#[derive(Default)]
struct DataLoader {}

impl CellDataProvider for DataLoader {
    // we load all cells data eagerly in Storage's CellProivder impl
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        unreachable!()
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        unreachable!()
    }
}

impl HeaderProvider for DataLoader {
    // TODO retrieve header from full node when tx's header deps is not empty
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        todo!()
    }
}

pub fn verify_tx<CP: CellProvider>(
    cell_provider: &CP,
    tip_header: &HeaderView,
    transaction: TransactionView,
    max_cycles: Cycle,
) -> Result<Cycle, Error> {
    let rtx = resolve_tx(cell_provider, transaction)?;
    let consensus = Consensus::default();
    let data_loader = DataLoader::default();
    let tx_env = TxVerifyEnv::new_submit(tip_header);

    let verifier = TransactionScriptsVerifier::new(&rtx, &consensus, &data_loader, &tx_env);
    verifier.verify(max_cycles)
}

fn resolve_tx<CP: CellProvider>(
    cell_provider: &CP,
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
                    let cell_status = cell_provider.cell(out_point, eager_load);
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
