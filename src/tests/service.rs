use std::collections::HashMap;

use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, BlockBuilder, Capacity, EpochNumberWithFraction, HeaderBuilder,
        ScriptHashType, TransactionBuilder,
    },
    packed::{CellInput, CellOutputBuilder, OutPoint, Script, ScriptBuilder},
    prelude::*,
    H256,
};
use tempfile;

use crate::{
    service::{
        BlockFilterRpc, BlockFilterRpcImpl, ChainRpc, ChainRpcImpl, Order, SearchKey,
        SearchKeyFilter, TransactionWithHeader,
    },
    storage::Storage,
};

fn new_storage(prefix: &str) -> Storage {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    Storage::new(tmp_dir.path().to_str().unwrap())
}

#[test]
fn rpc() {
    let storage = new_storage("rpc");
    let rpc = BlockFilterRpcImpl {
        storage: storage.clone(),
    };

    // setup test data
    let lock_script1 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"lock_script1".to_vec()).pack())
        .build();

    let lock_script2 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(b"lock_script2".to_vec()).pack())
        .build();

    let type_script1 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"type_script1".to_vec()).pack())
        .build();

    let type_script2 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(b"type_script2".to_vec()).pack())
        .build();

    let cellbase0 = TransactionBuilder::default()
        .input(CellInput::new_cellbase_input(0))
        .witness(Script::default().into_witness())
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(1000).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .build();

    let tx00 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(1000).pack())
                .lock(lock_script1.clone())
                .type_(Some(type_script1.clone()).pack())
                .build(),
        )
        .output_data(Default::default())
        .build();

    let tx01 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(2000).pack())
                .lock(lock_script2.clone())
                .type_(Some(type_script2.clone()).pack())
                .build(),
        )
        .output_data(Default::default())
        .build();

    let block0 = BlockBuilder::default()
        .transaction(cellbase0)
        .transaction(tx00.clone())
        .transaction(tx01.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 1000).pack())
                .number(0.pack())
                .build(),
        )
        .build();

    storage.init_genesis_block(block0.data());
    storage.update_filter_scripts(HashMap::from([(lock_script1.clone(), 0)]));

    let (mut pre_tx0, mut pre_tx1, mut pre_block) = (tx00, tx01, block0);
    let total_blocks = 255;
    for i in 1..total_blocks {
        let cellbase = TransactionBuilder::default()
            .input(CellInput::new_cellbase_input(i + 1))
            .witness(Script::default().into_witness())
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(1000).pack())
                    .lock(lock_script1.clone())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        pre_tx0 = TransactionBuilder::default()
            .input(CellInput::new(OutPoint::new(pre_tx0.hash(), 0), 0))
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(1000).pack())
                    .lock(lock_script1.clone())
                    .type_(Some(type_script1.clone()).pack())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        pre_tx1 = TransactionBuilder::default()
            .input(CellInput::new(OutPoint::new(pre_tx1.hash(), 0), 0))
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(2000).pack())
                    .lock(lock_script2.clone())
                    .type_(Some(type_script2.clone()).pack())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        pre_block = BlockBuilder::default()
            .transaction(cellbase)
            .transaction(pre_tx0.clone())
            .transaction(pre_tx1.clone())
            .header(
                HeaderBuilder::default()
                    .epoch(EpochNumberWithFraction::new(0, pre_block.number() + 1, 1000).pack())
                    .number((pre_block.number() + 1).pack())
                    .parent_hash(pre_block.hash())
                    .build(),
            )
            .build();

        storage.filter_block(pre_block.data());
    }

    // test get_cells rpc
    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    let cells_page_2 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            Some(cells_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize + 1,
        cells_page_1.objects.len() + cells_page_2.objects.len(),
        "total size should be cellbase cells count + 1 (last block live cell)"
    );

    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script2.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();

    assert_eq!(
        0,
        cells_page_1.objects.len(),
        "total size should be zero with unfiltered lock script"
    );

    let desc_cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Desc,
            150.into(),
            None,
        )
        .unwrap();

    let desc_cells_page_2 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Desc,
            150.into(),
            Some(desc_cells_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize + 1,
        desc_cells_page_1.objects.len() + desc_cells_page_2.objects.len(),
        "total size should be cellbase cells count + 1 (last block live cell)"
    );
    assert_eq!(
        desc_cells_page_1.objects.first().unwrap().out_point,
        cells_page_2.objects.last().unwrap().out_point
    );

    let filter_cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            60.into(),
            None,
        )
        .unwrap();

    let filter_cells_page_2 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            60.into(),
            Some(filter_cells_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        100,
        filter_cells_page_1.objects.len() + filter_cells_page_2.objects.len(),
        "total size should be filtered cellbase cells (100~199)"
    );

    // test get_transactions rpc
    let txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            None,
        )
        .unwrap();
    let txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            Some(txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(total_blocks as usize * 3 - 1, txs_page_1.objects.len() + txs_page_2.objects.len(), "total size should be cellbase tx count + total_block * 2 - 1 (genesis block only has one tx)");

    let desc_txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Desc,
            500.into(),
            None,
        )
        .unwrap();
    let desc_txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Desc,
            500.into(),
            Some(desc_txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(total_blocks as usize * 3 - 1, desc_txs_page_1.objects.len() + desc_txs_page_2.objects.len(), "total size should be cellbase tx count + total_block * 2 - 1 (genesis block only has one tx)");
    assert_eq!(
        desc_txs_page_1.objects.first().unwrap().tx_hash(),
        txs_page_2.objects.last().unwrap().tx_hash(),
    );

    let filter_txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            200.into(),
            None,
        )
        .unwrap();

    let filter_txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            200.into(),
            Some(filter_txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        300,
        filter_txs_page_1.objects.len() + filter_txs_page_2.objects.len(),
        "total size should be filtered blocks count * 3 (100~199 * 3)"
    );

    // test get_transactions rpc group by tx hash
    let txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            None,
        )
        .unwrap();
    let txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            Some(txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize * 2,
        txs_page_1.objects.len() + txs_page_2.objects.len(),
        "total size should be cellbase tx count + total_block"
    );

    let desc_txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Desc,
            500.into(),
            None,
        )
        .unwrap();
    let desc_txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Desc,
            500.into(),
            Some(desc_txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize * 2,
        desc_txs_page_1.objects.len() + desc_txs_page_2.objects.len(),
        "total size should be cellbase tx count + total_block"
    );
    assert_eq!(
        desc_txs_page_1.objects.first().unwrap().tx_hash(),
        txs_page_2.objects.last().unwrap().tx_hash(),
    );

    let filter_txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            200.into(),
            None,
        )
        .unwrap();

    let filter_txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                group_by_transaction: Some(true),
                filter: Some(SearchKeyFilter {
                    block_range: Some([100.into(), 200.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            200.into(),
            Some(filter_txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        200,
        filter_txs_page_1.objects.len() + filter_txs_page_2.objects.len(),
        "total size should be filtered blocks count * 2 (100~199 * 2)"
    );

    // test get_cells_capacity rpc
    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        1000 * 100000000 * (total_blocks + 1),
        capacity.value(),
        "cellbases + last block live cell"
    );

    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script2.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(0, capacity.value(), "lock_script2 is not filtered");

    // test get_header rpc
    let rpc = ChainRpcImpl {
        storage: storage.clone(),
    };
    let header = rpc
        .get_header(pre_block.header().hash().unpack())
        .unwrap()
        .unwrap();
    assert_eq!(pre_block.header().number(), header.inner.number.value(),);

    // test get_transaction rpc
    let TransactionWithHeader {
        transaction,
        header,
    } = rpc
        .get_transaction(pre_tx0.hash().unpack())
        .unwrap()
        .unwrap();
    assert_eq!(transaction.hash, pre_tx0.hash().unpack());
    assert_eq!(header.hash, pre_block.header().hash().unpack());

    // test rollback_filtered_transactions
    // rollback 2 blocks
    storage.update_filter_scripts(HashMap::from([(lock_script1.clone(), total_blocks)]));
    storage.rollback_to_block((total_blocks - 2).into());

    let scripts = storage.get_filter_scripts();
    assert_eq!(
        total_blocks - 2,
        *scripts.values().max().unwrap(),
        "rollback should update script filter block number"
    );

    let rpc = BlockFilterRpcImpl {
        storage: storage.clone(),
    };

    // test get_cells rpc after rollback
    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    let cells_page_2 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            Some(cells_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
            total_blocks as usize - 1,
            cells_page_1.objects.len() + cells_page_2.objects.len(),
            "total size should be cellbase cells count + 1 (last block live cell) - 2 (rollbacked blocks cells)"
        );

    // test get_transactions rpc after rollback
    let txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            None,
        )
        .unwrap();
    let txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            Some(txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!((total_blocks - 2) as usize * 3 - 1, txs_page_1.objects.len() + txs_page_2.objects.len(), "total size should be cellbase tx count + (total_block - 2) * 2 - 1 (genesis block only has one tx)");

    // test get_cells_capacity rpc after rollback
    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        1000 * 100000000 * (total_blocks - 1),
        capacity.value(),
        "cellbases + last block live cell - 2 (rollbacked blocks cells)"
    );
}

#[test]
fn get_cells_capacity_bug() {
    let storage = new_storage("get_cells_capacity_bug");
    let rpc = BlockFilterRpcImpl {
        storage: storage.clone(),
    };

    // setup test data
    let lock_script1 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"lock_script1".to_vec()).pack())
        .build();

    let tx00 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(222).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(333).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block0 = BlockBuilder::default()
        .transaction(tx00.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 1000).pack())
                .number(0.pack())
                .build(),
        )
        .build();
    storage.init_genesis_block(block0.data());
    storage.update_filter_scripts(HashMap::from([(lock_script1.clone(), 0)]));

    let lock_script2 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"lock_script2".to_vec()).pack())
        .build();

    let tx10 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(100).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(1000).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block1 = BlockBuilder::default()
        .transaction(tx10.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 1, 1000).pack())
                .number(1.pack())
                .build(),
        )
        .build();
    storage.filter_block(block1.data());

    let tx20 = TransactionBuilder::default()
        .input(CellInput::new(OutPoint::new(tx00.hash(), 1), 0))
        .input(CellInput::new(OutPoint::new(tx10.hash(), 1), 0))
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(5000).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(3000).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block2 = BlockBuilder::default()
        .transaction(tx20.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 2, 1000).pack())
                .number(2.pack())
                .build(),
        )
        .build();
    storage.filter_block(block2.data());

    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!((222 + 3000) * 100000000, capacity.value());
}

#[test]
fn get_cells_after_rollback_bug() {
    let storage = new_storage("get_cells_after_rollback_bug");
    let rpc = BlockFilterRpcImpl {
        storage: storage.clone(),
    };

    // setup test data
    let lock_script1 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"lock_script1".to_vec()).pack())
        .build();

    let lock_script2 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(b"lock_script2".to_vec()).pack())
        .build();

    let tx00 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(222).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(333).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block0 = BlockBuilder::default()
        .transaction(tx00.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 1000).pack())
                .number(0.pack())
                .build(),
        )
        .build();
    storage.init_genesis_block(block0.data());
    storage.update_filter_scripts(HashMap::from([
        (lock_script1.clone(), 0),
        (lock_script2.clone(), 0),
    ]));

    let tx10 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(100).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(1000).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block1 = BlockBuilder::default()
        .transaction(tx10.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 1, 1000).pack())
                .number(1.pack())
                .build(),
        )
        .build();
    storage.filter_block(block1.data());
    storage.update_block_number(1);

    let tx20 = TransactionBuilder::default()
        .input(CellInput::new(OutPoint::new(tx00.hash(), 1), 0))
        .input(CellInput::new(OutPoint::new(tx10.hash(), 1), 0))
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(5000).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(3000).pack())
                .lock(lock_script1.clone())
                .build(),
        )
        .output_data(Default::default())
        .output_data(Default::default())
        .build();

    let block2 = BlockBuilder::default()
        .transaction(tx20.clone())
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 2, 1000).pack())
                .number(2.pack())
                .build(),
        )
        .build();
    storage.filter_block(block2.data());
    storage.update_block_number(2);

    storage.rollback_to_block(2);

    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script2.clone().into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(100 * 100000000, capacity.value());

    let cells = rpc
        .get_cells(
            SearchKey {
                script: lock_script2.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    assert_eq!(1, cells.objects.len());

    let txs = rpc
        .get_transactions(
            SearchKey {
                script: lock_script2.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    assert_eq!(1, txs.objects.len());

    let capacity = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!((1000 + 222 + 333) * 100000000, capacity.value());

    let cells = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    assert_eq!(3, cells.objects.len());

    let txs = rpc
        .get_transactions(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();
    assert_eq!(3, txs.objects.len());
}
