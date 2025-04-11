use std::sync::Arc;

use crate::{
    storage::{ScriptStatus, ScriptType, StorageWithChainData},
    tests::{prelude::*, utils::MockChain},
    verify::{resolve_tx, verify_tx, FeeCalculator},
};
use ckb_chain_spec::consensus::Consensus;
use ckb_dao_utils::pack_dao_data;
use ckb_db::RocksDB;
use ckb_db_schema::COLUMNS;
use ckb_jsonrpc_types::{Block, Script, Transaction};
use ckb_store::{ChainDB, ChainStore};
use ckb_types::{
    bytes::Bytes,
    core::{capacity_bytes, BlockBuilder, Capacity, EpochNumberWithFraction, HeaderBuilder},
    packed::{self, CellOutput},
    prelude::{Entity, IntoHeaderView, IntoTransactionView as _, Pack},
};
use ckb_types::{core::TransactionBuilder, prelude::Builder};
use tempfile::TempDir;
#[test]
fn check_withdraw_calculation() {
    let data = Bytes::from(vec![1; 10]);
    let output = CellOutput::new_builder()
        .capacity(capacity_bytes!(1000000).pack())
        .build();
    let tx = TransactionBuilder::default()
        .output(output.clone())
        .output_data(data.pack())
        .build();
    let epoch = EpochNumberWithFraction::new(1, 100, 1000);
    let deposit_header = HeaderBuilder::default()
        .number(100.pack())
        .epoch(epoch.pack())
        .dao(pack_dao_data(
            10_000_000_000_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let deposit_block = BlockBuilder::default()
        .header(deposit_header)
        .transaction(tx)
        .build();

    let epoch = EpochNumberWithFraction::new(1, 200, 1000);
    let withdrawing_header = HeaderBuilder::default()
        .number(200.pack())
        .epoch(epoch.pack())
        .dao(pack_dao_data(
            10_000_000_001_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let withdrawing_block = BlockBuilder::default().header(withdrawing_header).build();

    let tmp_dir = TempDir::new().unwrap();
    let db = RocksDB::open_in(&tmp_dir, COLUMNS);
    let store = ChainDB::new(db, Default::default());
    let txn = store.begin_transaction();
    txn.insert_block(&deposit_block).unwrap();
    txn.attach_block(&deposit_block).unwrap();
    txn.insert_block(&withdrawing_block).unwrap();
    txn.attach_block(&withdrawing_block).unwrap();
    txn.commit().unwrap();

    let consensus = Arc::new(Consensus::default());
    let data_loader = Arc::new(store.borrow_as_data_loader());
    let calculator = FeeCalculator::new(Arc::clone(&consensus), data_loader);
    let result = calculator.calculate_maximum_withdraw(
        &output,
        Capacity::bytes(data.len()).expect("should not overflow"),
        &deposit_block.hash(),
        &withdrawing_block.hash(),
    );
    assert_eq!(result.unwrap(), Capacity::shannons(100_000_000_009_999));
}

#[test]
fn check_withdraw_calculation_overflows() {
    let output = CellOutput::new_builder()
        .capacity(Capacity::shannons(18_446_744_073_709_550_000).pack())
        .build();
    let tx = TransactionBuilder::default().output(output.clone()).build();
    let epoch = EpochNumberWithFraction::new(1, 100, 1000);
    let deposit_header = HeaderBuilder::default()
        .number(100.pack())
        .epoch(epoch.pack())
        .dao(pack_dao_data(
            10_000_000_000_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let deposit_block = BlockBuilder::default()
        .header(deposit_header)
        .transaction(tx)
        .build();

    let epoch = EpochNumberWithFraction::new(1, 200, 1000);
    let withdrawing_header = HeaderBuilder::default()
        .number(200.pack())
        .epoch(epoch.pack())
        .dao(pack_dao_data(
            10_000_000_001_123_456,
            Default::default(),
            Default::default(),
            Default::default(),
        ))
        .build();
    let withdrawing_block = BlockBuilder::default().header(withdrawing_header).build();

    let tmp_dir = TempDir::new().unwrap();
    let db = RocksDB::open_in(&tmp_dir, COLUMNS);
    let store = ChainDB::new(db, Default::default());
    let txn = store.begin_transaction();
    txn.insert_block(&deposit_block).unwrap();
    txn.attach_block(&deposit_block).unwrap();
    txn.insert_block(&withdrawing_block).unwrap();
    txn.attach_block(&withdrawing_block).unwrap();
    txn.commit().unwrap();

    let consensus = Arc::new(Consensus::default());
    let data_loader = Arc::new(store.borrow_as_data_loader());
    let calculator = FeeCalculator::new(consensus, data_loader);
    let result = calculator.calculate_maximum_withdraw(
        &output,
        Capacity::bytes(0).expect("should not overflow"),
        &deposit_block.hash(),
        &withdrawing_block.hash(),
    );
    assert!(result.is_err());
}

#[test]
fn verify_valid_transaction_and_fee() {
    let chain = MockChain::new_with_default_pow("verify_valid_transaction");
    let storage = chain.client_storage();
    let consensus = Arc::new(chain.consensus().clone());

    // https://pudge.explorer.nervos.org/address/ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0l2z2v9305wm7rs5gqrpsf507ey8wj3tggtl4sj
    let script: packed::Script = serde_json::from_str::<Script>(r#"{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type": "type","args": "0xff5094c2c5f476fc38510018609a3fd921dd28ad"}"#).unwrap().into();
    let scripts = vec![ScriptStatus {
        script,
        script_type: ScriptType::Lock,
        block_number: 0,
    }];
    storage.update_filter_scripts(scripts, Default::default());

    // https://pudge.explorer.nervos.org/block/261
    let block: packed::Block = serde_json::from_str::<Block>(r#"{"header":{"compact_target":"0x1e015555","dao":"0x18f067d6835aa12e81d52889fd862300aa4aa421700c0000003ef78768fcfe06","epoch":"0x3e80105000000","extra_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x32daf82076f991d5b69674ed257385eb","number":"0x105","parent_hash":"0xe883cd26172309608574ab5e7fad5dbdb4c82d6dcbac407f3d81b4b50f46f513","proposals_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x1723baeb815","transactions_root":"0xf7250b8db808b34d96276a5b146a93b14372ff58abe4eb8927c6955446bca748","version":"0x0"},"proposals":[],"transactions":[{"cell_deps":[],"header_deps":[],"inputs":[{"previous_output":{"index":"0xffffffff","tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"since":"0x105"}],"outputs":[{"capacity":"0x2ecbd5b8aa","lock":{"args":"0xda648442dbb7347e467d1d09da13e5cd3a0ef0e1","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x"],"version":"0x0","witnesses":["0x5d0000000c00000055000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000da648442dbb7347e467d1d09da13e5cd3a0ef0e104000000deadbeef"]},{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}],"uncles":[]}"#).unwrap().into();
    storage.filter_block(block);

    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();

    let swc = Arc::new(StorageWithChainData::new(
        storage.to_owned(),
        chain.create_peers(),
        Default::default(),
    ));
    // Also check transaction fee
    let fee_calculator = FeeCalculator::new(Arc::clone(&consensus), Arc::clone(&swc));
    let rtx = resolve_tx(&*swc, transaction.clone().into_view()).unwrap();
    assert_eq!(
        fee_calculator.transaction_fee(&rtx).unwrap(),
        Capacity::shannons(1_0000_0000)
    );
    let result = verify_tx(
        transaction.into_view(),
        &*swc,
        consensus,
        &swc.storage().get_last_state().1.into_view(),
    )
    .unwrap();
    // please note that the cycle (1682789) of this transaction displayed on the explorer is wrong
    // it's fixed in https://github.com/nervosnetwork/ckb/pull/4218
    assert_eq!(1691692, result);
}

#[test]
fn non_contextual_transaction_verifier() {
    let chain = MockChain::new_with_default_pow("non_contextual_transaction_verifier");
    let storage = chain.client_storage();
    let consensus = Arc::new(chain.consensus().clone());
    let swc =
        StorageWithChainData::new(storage.to_owned(), chain.create_peers(), Default::default());

    // duplicate cell deps base on a valid transaction
    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}, {"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();
    let error = verify_tx(
        transaction.into_view(),
        &swc,
        Arc::clone(&consensus),
        &swc.storage().get_last_state().1.into_view(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("DuplicateCellDeps"));

    // insufficient cell capacity
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb6113","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();
    let error = verify_tx(
        transaction.into_view(),
        &swc,
        consensus,
        &swc.storage().get_last_state().1.into_view(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("InsufficientCellCapacity"));
}
