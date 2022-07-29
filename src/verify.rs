use std::collections::{hash_map::Entry, HashMap, HashSet};

use ckb_error::Error;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    core::{
        cell::{CellMeta, CellProvider, CellStatus, ResolvedTransaction},
        error::OutPointError,
        Cycle, DepType, TransactionView,
    },
    packed::{OutPoint, OutPointVec},
    prelude::Entity,
};

use crate::storage::Storage;

pub fn verify_tx(
    storage: &Storage,
    transaction: TransactionView,
    max_cycles: Cycle,
) -> Result<Cycle, Error> {
    let rtx = resolve_tx(storage, transaction)?;
    let verifier = TransactionScriptsVerifier::new(&rtx, storage);
    verifier.verify(max_cycles)
}

#[allow(clippy::mutable_key_type)]
fn resolve_tx(
    storage: &Storage,
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
                    let cell_status = storage.cell(out_point, eager_load);
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ckb_chain_spec::ChainSpec;
    use ckb_jsonrpc_types::{Block, Script, Transaction};
    use ckb_resource::Resource;
    use ckb_types::packed;

    use crate::storage::Storage;

    use super::verify_tx;

    fn new_storage(prefix: &str) -> Storage {
        let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
        let storage = Storage::new(tmp_dir.path().to_str().unwrap());
        let chain_spec = ChainSpec::load_from(&Resource::bundled("specs/testnet.toml".to_string()))
            .expect("load spec should be OK");
        let consensus = chain_spec
            .build_consensus()
            .expect("build consensus should be OK");
        storage.init_genesis_block(consensus.genesis_block().data());
        storage
    }

    #[test]
    fn verify_transaction() {
        let storage = new_storage("verify_tx");
        // https://pudge.explorer.nervos.org/address/ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0l2z2v9305wm7rs5gqrpsf507ey8wj3tggtl4sj
        let script: packed::Script = serde_json::from_str::<Script>(r#"{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type": "type","args": "0xff5094c2c5f476fc38510018609a3fd921dd28ad"}"#).unwrap().into();
        let mut scripts = HashMap::new();
        scripts.insert(script, 0);
        storage.update_filter_scripts(scripts);

        // https://pudge.explorer.nervos.org/block/261
        let block: packed::Block = serde_json::from_str::<Block>(r#"{"header":{"compact_target":"0x1e015555","dao":"0x18f067d6835aa12e81d52889fd862300aa4aa421700c0000003ef78768fcfe06","epoch":"0x3e80105000000","extra_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x32daf82076f991d5b69674ed257385eb","number":"0x105","parent_hash":"0xe883cd26172309608574ab5e7fad5dbdb4c82d6dcbac407f3d81b4b50f46f513","proposals_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x1723baeb815","transactions_root":"0xf7250b8db808b34d96276a5b146a93b14372ff58abe4eb8927c6955446bca748","version":"0x0"},"proposals":[],"transactions":[{"cell_deps":[],"header_deps":[],"inputs":[{"previous_output":{"index":"0xffffffff","tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"since":"0x105"}],"outputs":[{"capacity":"0x2ecbd5b8aa","lock":{"args":"0xda648442dbb7347e467d1d09da13e5cd3a0ef0e1","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x"],"version":"0x0","witnesses":["0x5d0000000c00000055000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000da648442dbb7347e467d1d09da13e5cd3a0ef0e104000000deadbeef"]},{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}],"uncles":[]}"#).unwrap().into();
        storage.filter_block(block);

        // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
        let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();

        let result = verify_tx(&storage, transaction.into_view(), 3500000).unwrap();
        assert_eq!(1682789, result);
    }
}
