use std::sync::{Arc, RwLock};

use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, BlockBuilder, Capacity, EpochNumberWithFraction, HeaderBuilder,
        ScriptHashType, TransactionBuilder,
    },
    h256,
    packed::{CellInput, CellOutputBuilder, Header, OutPoint, Script, ScriptBuilder},
    prelude::*,
    H256, U256,
};

use crate::{
    protocols::{FetchInfo, Peers},
    service::{
        BlockFilterRpc, BlockFilterRpcImpl, ChainRpc, ChainRpcImpl, FetchStatus, Order,
        ScriptStatus, ScriptType, SearchKey, SearchKeyFilter, TransactionWithHeader,
    },
    storage::{self, StorageWithChainData},
    tests::utils::new_storage,
};

#[test]
fn rpc() {
    let storage = new_storage("rpc");
    let swc = StorageWithChainData::new(
        storage.clone(),
        Arc::new(Peers::new(RwLock::new(Vec::new()))),
    );
    let rpc = BlockFilterRpcImpl { swc };

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

    let lock_script3 = ScriptBuilder::default()
        .code_hash(H256(rand::random()).pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(b"lock_script3".to_vec()).pack())
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
    storage.update_filter_scripts(vec![
        storage::ScriptStatus {
            script: lock_script1.clone(),
            script_type: storage::ScriptType::Lock,
            block_number: 0,
        },
        storage::ScriptStatus {
            script: type_script1.clone(),
            script_type: storage::ScriptType::Type,
            block_number: 0,
        },
        storage::ScriptStatus {
            script: lock_script3,
            script_type: storage::ScriptType::Lock,
            block_number: 0,
        },
    ]);

    // test get_scripts rpc
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 3);

    // test set_scripts rpc
    rpc.set_scripts(vec![
        ScriptStatus {
            script: lock_script1.clone().into(),
            script_type: ScriptType::Lock,
            block_number: 0.into(),
        },
        ScriptStatus {
            script: type_script1.clone().into(),
            script_type: ScriptType::Type,
            block_number: 0.into(),
        },
    ])
    .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(
        scripts.len(),
        2,
        "set_scripts should override the old scripts and delete the lock_script3"
    );

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
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();

    assert_eq!(
        1,
        cells_page_1.objects.len(),
        "total size should be 1 (last block live cell)"
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
                    script_len_range: Some([50.into(), 100.into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();

    assert_eq!(
        0,
        filter_cells_page_1.objects.len(),
        "script len range filter empty"
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

    let txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
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
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
                ..Default::default()
            },
            Order::Asc,
            500.into(),
            Some(txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize * 2 - 1,
        txs_page_1.objects.len() + txs_page_2.objects.len(),
        "total size should be total_block * 2 - 1 (genesis block only has one tx)"
    );

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

    // test get_cells with_data option
    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                ..Default::default()
            },
            Order::Asc,
            1.into(),
            None,
        )
        .unwrap();

    assert!(cells_page_1.objects.first().unwrap().output_data.is_some());

    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script1.clone().into(),
                with_data: Some(false),
                ..Default::default()
            },
            Order::Asc,
            1.into(),
            None,
        )
        .unwrap();

    assert!(cells_page_1.objects.first().unwrap().output_data.is_none());

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

    let txs_page_1 = rpc
        .get_transactions(
            SearchKey {
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Asc,
            300.into(),
            None,
        )
        .unwrap();
    let txs_page_2 = rpc
        .get_transactions(
            SearchKey {
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
                group_by_transaction: Some(true),
                ..Default::default()
            },
            Order::Asc,
            300.into(),
            Some(txs_page_1.last_cursor),
        )
        .unwrap();

    assert_eq!(
        total_blocks as usize,
        txs_page_1.objects.len() + txs_page_2.objects.len(),
        "total size should be total_block"
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
    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        1000 * 100000000 * (total_blocks + 1),
        cc.capacity.value(),
        "cellbases + last block live cell"
    );

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: type_script1.clone().into(),
            script_type: ScriptType::Type,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        1000 * 100000000,
        cc.capacity.value(),
        "last block live cell"
    );

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script2.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(0, cc.capacity.value(), "lock_script2 is not filtered");

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            filter: Some(SearchKeyFilter {
                script_len_range: Some([50.into(), 100.into()]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(0, cc.capacity.value(), "script len range filter empty");

    // test get_header rpc
    let extra_header = HeaderBuilder::default()
        .epoch(EpochNumberWithFraction::new(0, 500, 1000).pack())
        .number(500.pack())
        .build();
    let fetched_headers: Vec<H256> = [0xaa11, 0xaa77, 0xaa88]
        .into_iter()
        .map(|nonce| {
            let header = Header::new_builder().nonce(nonce.pack()).build();
            storage.add_fetched_header(&header);
            header.calc_header_hash().unpack()
        })
        .collect();
    let fetched_txs: Vec<H256> = [h256!("0xbb11"), h256!("0xbb77"), h256!("0xbb88")]
        .into_iter()
        .map(|header_dep| {
            let tx = TransactionBuilder::default()
                .header_dep(header_dep.pack())
                .build();
            storage.add_fetched_tx(&tx.data(), &Header::default());
            tx.hash().unpack()
        })
        .collect();
    // insert fetched headers
    let peers = Arc::new(Peers::new(RwLock::new(vec![extra_header.clone()])));
    peers.fetching_headers().insert(
        h256!("0xaa22").pack(),
        FetchInfo::new(1111, 3344, false, false),
    );
    peers.fetching_headers().insert(
        h256!("0xaa33").pack(),
        FetchInfo::new(1111, 0, false, false),
    );
    peers.fetching_headers().insert(
        h256!("0xaa404").pack(),
        FetchInfo::new(1111, 0, false, true),
    );
    peers.fetching_txs().insert(
        h256!("0xbb22").pack(),
        FetchInfo::new(1111, 5566, false, false),
    );
    peers.fetching_txs().insert(
        h256!("0xbb33").pack(),
        FetchInfo::new(1111, 0, false, false),
    );
    peers.fetching_txs().insert(
        h256!("0xbb404").pack(),
        FetchInfo::new(1111, 0, false, true),
    );

    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers));

    let rpc = ChainRpcImpl { swc };
    let header = rpc
        .get_header(pre_block.header().hash().unpack())
        .unwrap()
        .unwrap();
    assert_eq!(pre_block.header().number(), header.inner.number.value(),);
    let header = rpc
        .get_header(extra_header.hash().unpack())
        .unwrap()
        .unwrap();
    assert_eq!(extra_header.number(), header.inner.number.value(),);

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

    assert_eq!(peers.fetching_headers().len(), 3);
    assert_eq!(peers.fetching_txs().len(), 3);

    // test fetch_header rpc
    let rv = rpc.fetch_header(fetched_headers[0].clone()).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Fetched {
            data: Header::new_builder()
                .nonce(0xaa11.pack())
                .build()
                .into_view()
                .into()
        }
    );
    let rv = rpc.fetch_header(h256!("0xabcdef")).unwrap();
    assert!(matches!(rv, FetchStatus::Added { .. }));
    let rv = rpc.fetch_header(h256!("0xaa22")).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Fetching {
            first_sent: 3344.into()
        }
    );
    let rv = rpc.fetch_header(h256!("0xaa33")).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Added {
            timestamp: 1111.into()
        }
    );
    let rv = rpc.fetch_header(h256!("0xaa404")).unwrap();
    assert_eq!(rv, FetchStatus::NotFound);

    // test fetch_transaction rpc
    let rv = rpc.fetch_transaction(fetched_txs[0].clone()).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Fetched {
            data: TransactionWithHeader {
                transaction: TransactionBuilder::default()
                    .header_dep(h256!("0xbb11").pack())
                    .build()
                    .into(),
                header: Header::default().into_view().into(),
            }
        }
    );
    let rv = rpc.fetch_transaction(h256!("0xabcdef")).unwrap();
    assert!(matches!(rv, FetchStatus::Added { .. }));
    let rv = rpc.fetch_transaction(h256!("0xbb22")).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Fetching {
            first_sent: 5566.into()
        }
    );
    let rv = rpc.fetch_transaction(h256!("0xbb33")).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Added {
            timestamp: 1111.into()
        }
    );
    let rv = rpc.fetch_transaction(h256!("0xbb404")).unwrap();
    assert_eq!(rv, FetchStatus::NotFound);

    assert_eq!(peers.fetching_headers().len(), 4);
    assert_eq!(peers.fetching_txs().len(), 4);

    // test rollback_filtered_transactions
    // rollback 2 blocks
    storage.update_filter_scripts(vec![
        storage::ScriptStatus {
            script: lock_script1.clone(),
            script_type: storage::ScriptType::Lock,
            block_number: total_blocks,
        },
        storage::ScriptStatus {
            script: type_script1.clone(),
            script_type: storage::ScriptType::Type,
            block_number: total_blocks,
        },
    ]);
    storage.rollback_to_block((total_blocks - 2).into());

    let scripts = storage.get_filter_scripts();
    assert_eq!(
        total_blocks - 2,
        scripts.into_iter().map(|s| s.block_number).max().unwrap(),
        "rollback should update script filter block number"
    );

    let swc = StorageWithChainData::new(
        storage.clone(),
        Arc::new(Peers::new(RwLock::new(Vec::new()))),
    );
    let rpc = BlockFilterRpcImpl { swc };

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

    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: type_script1.clone().into(),
                script_type: ScriptType::Type,
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();

    assert_eq!(
        1,
        cells_page_1.objects.len(),
        "total size should be 1 (last block live cell)"
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
    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        1000 * 100000000 * (total_blocks - 1),
        cc.capacity.value(),
        "cellbases + last block live cell - 2 (rollbacked blocks cells)"
    );
}

#[test]
fn get_cells_capacity_bug() {
    let storage = new_storage("get_cells_capacity_bug");
    let swc = StorageWithChainData::new(
        storage.clone(),
        Arc::new(Peers::new(RwLock::new(Vec::new()))),
    );
    let rpc = BlockFilterRpcImpl { swc };

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
    storage.update_filter_scripts(vec![storage::ScriptStatus {
        script: lock_script1.clone(),
        script_type: storage::ScriptType::Lock,
        block_number: 0,
    }]);

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
    storage.update_last_state(&U256::one(), &block2.header().data());

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();

    assert_eq!((222 + 3000) * 100000000, cc.capacity.value());
    assert_eq!(block2.header().number(), cc.block_number.value());
}

#[test]
fn get_cells_after_rollback_bug() {
    let storage = new_storage("get_cells_after_rollback_bug");
    let swc = StorageWithChainData::new(
        storage.clone(),
        Arc::new(Peers::new(RwLock::new(Vec::new()))),
    );
    let rpc = BlockFilterRpcImpl { swc };

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
    storage.update_filter_scripts(vec![
        storage::ScriptStatus {
            script: lock_script1.clone(),
            script_type: storage::ScriptType::Lock,
            block_number: 0,
        },
        storage::ScriptStatus {
            script: lock_script2.clone(),
            script_type: storage::ScriptType::Lock,
            block_number: 0,
        },
    ]);

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

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script2.clone().into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(100 * 100000000, cc.capacity.value());

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

    let cc = rpc
        .get_cells_capacity(SearchKey {
            script: lock_script1.clone().into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!((1000 + 222 + 333) * 100000000, cc.capacity.value());

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

#[test]
fn test_set_scripts_clear_matched_blocks() {
    let storage = new_storage("set-scripts-clear-matched-blocks");
    let peers = Arc::new(Peers::new(RwLock::new(Vec::new())));
    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers));
    let rpc = BlockFilterRpcImpl { swc };

    storage.update_min_filtered_block_number(1234);
    storage.add_matched_blocks(2233, 200, vec![(H256(rand::random()).pack(), false)]);
    storage.add_matched_blocks(4455, 200, vec![(H256(rand::random()).pack(), false)]);
    {
        let mut matched_blocks = peers.matched_blocks().write().unwrap();
        peers.add_matched_blocks(
            &mut matched_blocks,
            vec![(H256(rand::random()).pack(), false)],
        );
    }
    let block_number_a: u64 = 3;
    let block_number_x: u64 = 4;
    rpc.set_scripts(vec![
        ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("abc").pack())
                .build()
                .into(),
            script_type: ScriptType::Lock,
            block_number: block_number_a.into(),
        },
        ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("xyz").pack())
                .build()
                .into(),
            script_type: ScriptType::Type,
            block_number: block_number_x.into(),
        },
    ])
    .unwrap();
    assert_eq!(
        storage.get_min_filtered_block_number(),
        block_number_a.min(block_number_x)
    );
    assert!(storage.get_earliest_matched_blocks().is_none());
    assert!(storage.get_latest_matched_blocks().is_none());
    assert!(peers.matched_blocks().read().unwrap().is_empty());
}
