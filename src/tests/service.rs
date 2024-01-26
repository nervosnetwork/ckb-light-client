use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_network::PeerIndex;
use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, BlockBuilder, Capacity, EpochNumberWithFraction, HeaderBuilder,
        ScriptHashType, TransactionBuilder,
    },
    h256,
    packed::{Block, CellInput, CellOutputBuilder, Header, OutPoint, Script, ScriptBuilder},
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    H256, U256,
};

use crate::{
    protocols::{FetchInfo, LastState, ProveRequest, ProveState},
    service::{
        BlockFilterRpc, BlockFilterRpcImpl, ChainRpc, ChainRpcImpl, FetchStatus, Order,
        ScriptStatus, ScriptType, SearchKey, SearchKeyFilter, SetScriptsCommand, Status,
        TransactionRpc, TransactionRpcImpl, TransactionWithStatus, TxStatus,
    },
    storage::{self, HeaderWithExtension, StorageWithChainData},
    tests::prelude::*,
    tests::utils::{create_peers, new_storage, MockChain},
};

#[test]
fn rpc() {
    let storage = new_storage("rpc");
    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
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
    storage.update_filter_scripts(
        vec![
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
        ],
        Default::default(),
    );

    // test get_scripts rpc
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 3);

    // test set_scripts rpc
    rpc.set_scripts(
        vec![
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
        ],
        None,
    )
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
            let hash = header.calc_header_hash().unpack();
            let extension = (nonce + 1).to_le_bytes().to_vec().pack();
            storage.add_fetched_header(&HeaderWithExtension {
                header: header,
                extension: Some(extension),
            });
            hash
        })
        .collect();

    // insert fetched headers
    let peers = create_peers();
    {
        let peer_index = PeerIndex::new(3);
        peers.add_peer(peer_index);
        let tip_header = VerifiableHeader::new(
            storage.get_tip_header().into_view(),
            Default::default(),
            None,
            Default::default(),
        );
        let last_state = LastState::new(tip_header);
        let request = ProveRequest::new(last_state.clone(), Default::default());
        let prove_state = ProveState::new_from_request(
            request.clone(),
            Default::default(),
            vec![extra_header.clone()],
        );
        peers.request_last_state(peer_index).unwrap();
        peers.update_last_state(peer_index, last_state).unwrap();
        peers.update_prove_request(peer_index, request).unwrap();
        peers.update_prove_state(peer_index, prove_state).unwrap();
    }
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

    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), Default::default());

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
    let rv = rpc.fetch_header(h256!("0xaa404")).unwrap();
    assert!(matches!(rv, FetchStatus::Added { .. }));

    // test rollback_filtered_transactions
    // rollback 2 blocks
    storage.update_filter_scripts(
        vec![
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
        ],
        Default::default(),
    );
    storage.rollback_to_block((total_blocks - 2).into());

    let scripts = storage.get_filter_scripts();
    assert_eq!(
        total_blocks - 2,
        scripts.into_iter().map(|s| s.block_number).max().unwrap(),
        "rollback should update script filter block number"
    );

    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
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

    // test get_transaction rpc
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

    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), Default::default());

    let rpc = TransactionRpcImpl {
        swc,
        consensus: Arc::new(Consensus::default()),
    };
    let fetched_txs: Vec<H256> = [h256!("0xbb11"), h256!("0xbb77"), h256!("0xbb88")]
        .into_iter()
        .map(|header_dep| {
            let tx = TransactionBuilder::default()
                .header_dep(header_dep.pack())
                .build();
            storage.add_fetched_tx(
                &tx.data(),
                &&HeaderWithExtension {
                    header: Header::default(),
                    extension: None,
                },
            );
            tx.hash().unpack()
        })
        .collect();

    let TransactionWithStatus {
        transaction,
        tx_status,
        cycles: _,
    } = rpc.get_transaction(pre_tx0.hash().unpack()).unwrap();
    assert_eq!(transaction.unwrap().hash, pre_tx0.hash().unpack());
    assert_eq!(
        tx_status.block_hash.unwrap(),
        pre_block.header().hash().unpack()
    );
    assert_eq!(peers.fetching_txs().len(), 3);

    // test fetch_transaction rpc
    let rv = rpc.fetch_transaction(fetched_txs[0].clone()).unwrap();
    assert_eq!(
        rv,
        FetchStatus::Fetched {
            data: TransactionWithStatus {
                transaction: Some(
                    TransactionBuilder::default()
                        .header_dep(h256!("0xbb11").pack())
                        .build()
                        .into()
                ),
                cycles: None,
                tx_status: TxStatus {
                    block_hash: Some(Header::default().into_view().hash().unpack()),
                    status: Status::Committed,
                },
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
    let rv = rpc.fetch_transaction(h256!("0xbb404")).unwrap();
    assert!(matches!(rv, FetchStatus::Added { .. }));

    assert_eq!(peers.fetching_headers().len(), 4);
    assert_eq!(peers.fetching_txs().len(), 4);
}

#[test]
fn get_cells_capacity_bug() {
    let storage = new_storage("get_cells_capacity_bug");
    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
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
    storage.update_filter_scripts(
        vec![storage::ScriptStatus {
            script: lock_script1.clone(),
            script_type: storage::ScriptType::Lock,
            block_number: 0,
        }],
        Default::default(),
    );

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
    storage.update_last_state(&U256::one(), &block2.header().data(), &[]);

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
    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
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
    storage.update_filter_scripts(
        vec![
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
        ],
        Default::default(),
    );

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
    let peers = create_peers();
    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), Default::default());
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
    rpc.set_scripts(
        vec![
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
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        storage.get_min_filtered_block_number(),
        block_number_a.min(block_number_x)
    );
    assert!(storage.get_earliest_matched_blocks().is_none());
    assert!(storage.get_latest_matched_blocks().is_none());
    assert!(peers.matched_blocks().read().unwrap().is_empty());
}

#[test]
fn test_set_scripts_command() {
    let storage = new_storage("set-scripts-command");
    let peers = create_peers();
    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), Default::default());
    let rpc = BlockFilterRpcImpl { swc };

    rpc.set_scripts(
        vec![
            ScriptStatus {
                script: Script::new_builder()
                    .args(Bytes::from("abc").pack())
                    .build()
                    .into(),
                script_type: ScriptType::Lock,
                block_number: 3u64.into(),
            },
            ScriptStatus {
                script: Script::new_builder()
                    .args(Bytes::from("xyz").pack())
                    .build()
                    .into(),
                script_type: ScriptType::Type,
                block_number: 4u64.into(),
            },
        ],
        None,
    )
    .unwrap();

    rpc.set_scripts(
        vec![ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("abc").pack())
                .build()
                .into(),
            script_type: ScriptType::Lock,
            block_number: 6u64.into(),
        }],
        Some(SetScriptsCommand::All),
    )
    .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 1);

    rpc.set_scripts(
        vec![ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("xyz").pack())
                .build()
                .into(),
            script_type: ScriptType::Lock,
            block_number: 3u64.into(),
        }],
        Some(SetScriptsCommand::Partial),
    )
    .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 2);
    assert_eq!(storage.get_min_filtered_block_number(), 3);

    rpc.set_scripts(vec![], Some(SetScriptsCommand::Partial))
        .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 2);

    rpc.set_scripts(
        vec![ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("xyz").pack())
                .build()
                .into(),
            script_type: ScriptType::Lock,
            block_number: 0u64.into(),
        }],
        Some(SetScriptsCommand::Delete),
    )
    .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 1);

    rpc.set_scripts(vec![], Some(SetScriptsCommand::Delete))
        .unwrap();
    let scripts = rpc.get_scripts().unwrap();
    assert_eq!(scripts.len(), 1);
}

#[test]
fn test_set_scripts_partial_min_filtered_block_number_bug() {
    let storage = new_storage("set_scripts_partial_min_filtered_block_number_bug");
    let peers = create_peers();
    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), Default::default());
    let rpc = BlockFilterRpcImpl { swc };

    storage.update_min_filtered_block_number(42);
    rpc.set_scripts(
        vec![
            ScriptStatus {
                script: Script::new_builder()
                    .args(Bytes::from("abc").pack())
                    .build()
                    .into(),
                script_type: ScriptType::Lock,
                block_number: 1234.into(),
            },
            ScriptStatus {
                script: Script::new_builder()
                    .args(Bytes::from("xyz").pack())
                    .build()
                    .into(),
                script_type: ScriptType::Type,
                block_number: 5678.into(),
            },
        ],
        Some(SetScriptsCommand::Partial),
    )
    .unwrap();
    // min_filtered_block_number should be minimum block_number of scripts when storage scripts is empty
    assert_eq!(storage.get_min_filtered_block_number(), 1234,);

    rpc.set_scripts(
        vec![ScriptStatus {
            script: Script::new_builder()
                .args(Bytes::from("123").pack())
                .build()
                .into(),
            script_type: ScriptType::Lock,
            block_number: 12345.into(),
        }],
        Some(SetScriptsCommand::Partial),
    )
    .unwrap();

    // min_filtered_block_number should be same as before when storage scripts is not empty
    assert_eq!(storage.get_min_filtered_block_number(), 1234,);
}

#[test]
fn test_chain_txs_in_same_block_bug() {
    let storage = new_storage("chain_txs_in_same_block_bug");
    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
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
    storage.update_filter_scripts(
        vec![
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
        ],
        Default::default(),
    );

    let tx10 = TransactionBuilder::default()
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(100).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output_data(Default::default())
        .build();

    let tx11 = TransactionBuilder::default()
        .input(CellInput::new(OutPoint::new(tx10.hash(), 0), 0))
        .output(
            CellOutputBuilder::default()
                .capacity(capacity_bytes!(100).pack())
                .lock(lock_script2.clone())
                .build(),
        )
        .output_data(Default::default())
        .build();

    let block1 = BlockBuilder::default()
        .transaction(tx10)
        .transaction(tx11)
        .header(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 1, 1000).pack())
                .number(1.pack())
                .build(),
        )
        .build();
    storage.filter_block(block1.data());
    storage.update_block_number(1);

    let cells_page_1 = rpc
        .get_cells(
            SearchKey {
                script: lock_script2.into(),
                ..Default::default()
            },
            Order::Asc,
            150.into(),
            None,
        )
        .unwrap();

    assert_eq!(1, cells_page_1.objects.len());
}

#[test]
fn test_send_chain_txs() {
    let chain = MockChain::new_with_default_pow("test_send_chain_txs");
    let storage = chain.client_storage();
    let consensus = Arc::new(chain.consensus().clone());

    let swc = StorageWithChainData::new(storage.clone(), create_peers(), Default::default());
    let rpc = TransactionRpcImpl { consensus, swc };

    // https://pudge.explorer.nervos.org/address/ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0l2z2v9305wm7rs5gqrpsf507ey8wj3tggtl4sj
    let script: Script = serde_json::from_str::<ckb_jsonrpc_types::Script>(r#"{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type": "type","args": "0xff5094c2c5f476fc38510018609a3fd921dd28ad"}"#).unwrap().into();
    let scripts = vec![storage::ScriptStatus {
        script,
        script_type: storage::ScriptType::Lock,
        block_number: 0,
    }];
    storage.update_filter_scripts(scripts, Default::default());

    // https://pudge.explorer.nervos.org/block/261
    let block: Block = serde_json::from_str::<ckb_jsonrpc_types::Block>(r#"{"header":{"compact_target":"0x1e015555","dao":"0x18f067d6835aa12e81d52889fd862300aa4aa421700c0000003ef78768fcfe06","epoch":"0x3e80105000000","extra_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x32daf82076f991d5b69674ed257385eb","number":"0x105","parent_hash":"0xe883cd26172309608574ab5e7fad5dbdb4c82d6dcbac407f3d81b4b50f46f513","proposals_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x1723baeb815","transactions_root":"0xf7250b8db808b34d96276a5b146a93b14372ff58abe4eb8927c6955446bca748","version":"0x0"},"proposals":[],"transactions":[{"cell_deps":[],"header_deps":[],"inputs":[{"previous_output":{"index":"0xffffffff","tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"since":"0x105"}],"outputs":[{"capacity":"0x2ecbd5b8aa","lock":{"args":"0xda648442dbb7347e467d1d09da13e5cd3a0ef0e1","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x"],"version":"0x0","witnesses":["0x5d0000000c00000055000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000da648442dbb7347e467d1d09da13e5cd3a0ef0e104000000deadbeef"]},{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}],"uncles":[]}"#).unwrap().into();
    storage.filter_block(block);

    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction = serde_json::from_str::<ckb_jsonrpc_types::Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap();
    assert!(rpc.send_transaction(transaction).is_ok());

    // https://pudge.explorer.nervos.org/transaction/0xbad8ef061f71775ecf74e9bf2d0e7aa8055cb4cce8bdf5512f8a80992ac058d6
    let transaction = serde_json::from_str::<ckb_jsonrpc_types::Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x0","tx_hash":"0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30"},"since":"0x0"}],"outputs":[{"capacity":"0x48c27395000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0x470958b84888f0","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x55000000100000005500000055000000410000006ee0aef4919b989c23fd37f3803c56f23fb078860d1bec16ea9c9b43e54858fc27f07f2af210f3696d4b6b00c45c3e66c968c172e461af3fc7e91731ecddd58d01"]}"#).unwrap();
    assert!(rpc.send_transaction(transaction).is_ok());

    // https://pudge.explorer.nervos.org/transaction/0x69f4606d63f22a9b3b1ec11116ba4eba11351fe1def4d30e09aa2b8280494b23
    let transaction = serde_json::from_str::<ckb_jsonrpc_types::Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x0","tx_hash":"0xbad8ef061f71775ecf74e9bf2d0e7aa8055cb4cce8bdf5512f8a80992ac058d6"},"since":"0x0"}],"outputs":[{"capacity":"0xcfcd253d00","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0x3baee7d4ef0","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x7f454c460201010000000000000000000200f30001000000a0010100000000004000000000000000e0200000000000000100000040003800010040000700060001000000050000000000000000000000000001000000000000000100000000006820000000000000682000000000000000100000000000001d710c18080886ecef10c033aa8709c5e6603e85256182802c00480002e4ef00b014aa8775f592478545e215a3010100854613063100850595c7ef10e00515ed834531000808ef10205daa8771f10818ef10006aaa874dfda2650808ef10a07daa877db7ef10400309e92266834531000808ef10a054aa8761bf930760fd49bf79717d73056722f006f426ecfd771a91410705680a97e117aa862e8442e4b305f700080801461147814793088881730000000f00f00fa2679b040500a9e06363f8061307000d639de7048277130600020c191ce013050402ef00a0062277c166fd1693578702f58f9dc313568701f18e63fff6002217219318e414e81cec05631a91a27026850274e2644561828005631a91a270c15426850274e26445618280f954f1bfd954e1bf973100009381816c02452c000146eff0bfec9308d0057300000093f735006383073e630e0620aa8719a063090620850583c6f5ff850713f73500a38fd7fe7d166df713f837003e87630c081e411122e426e07d476376c70a894683c8050098416308d8308d461304c6fe6301d82803c3150003c825001180931644008d0593843700cd06a38067002380170123810701b383d7002e83a6878328130003285300832693001b5e87010327d3009b9288009b1f88001b9f86009bd888011b5888019bd686019b1e8700336e5e00b3e8f8013368e801b3e6d60123a0c70123a2170123a40701d4c7c1074103e39777fa13071400120735161204018eb387e400ba9513770601937886001378460093762600058a6308073283c4050003c7e50003c475002380970083c4150083c3850083c29500a380970083c4250083cfa50003cfb5002381970083c4350083cec50003ced500a381970083c4450003c3f5002387e7002382970083c45500a383870023847700a382970083c46500a38457002385f70123839700a385e7012386d701a386c701c10513870701a38767006385082a83c7650083c2050083cf150003cf250083ce350003ce450003c3550083c875002303f70023005700a300f7012301e701a301d7012302c701a3026700a10593078700a3031701630d082003c7250003c3050083c8150003c835002381e70023806700a3801701910513874700a3810701638d062283c7050083c6150089052300f700a300d7009307270009c603c705002380e700226482644101828082808280bd4663f9c604b3e6f5009d8a930e06ff639c061a93b60e0293c6160093f6f60f6384061a93de4e00138e1e00ae8603b3860083b8060005082334670023301701c1064107e365c8ff13871e0012073d8aba97ba95137886009376460013772600058a630c080083a8050003a84500a10723ac17ff23ae07ffa10591c694419107910523aed7fe6304071803c7050083c6150089052380e700a380d7001387270039de83c705002300f7008280118093164400850593841700c50623801701b383d7002e83a68783283300032873008326b3001b5e87000327f3009b9288019b1f88011b9f86019bd888001b5888009bd686009b1e8701336e5e00b3e8f8013368e801b3e6d60123a0c70123a2170123a40701d4c7c1074103e39777fa1307140012073d161204018eb387e400ba9549bb1304c6fe03c81500118093164400890593842700c90623801701a3800701b383d7002e83a68783282300032863008326a3001b5e07010327e3009b9208019b1f08011b9f06019bd808011b5808019bd606019b1e0701336e5e00b3e8f8013368e801b3e6d60123a0c70123a2170123a40701d4c7c1074103e39777fa13071400120739161204018eb387e400ba9509b33e8739b5aa8735b993de4e00138f1e00120f2e9f2e87be86032e070003234700832887000328c70023a0c60123a2660023a4160123a606014107c106e31eeffca1b53e87a1bbba8779bbba87f9bb3e8741bd1c450d476371f710033805000545832808006399170f1d4609456375f60e8326480013f5360071ed637dd60c1bd326001b0ef3ff1b060e00894e194563f4ce0c99e16311e60c13f7c6ff094563ece70a93170302f983bd079b05d3ff41119183821522e492070008819189053301f1408a8e8a059307480023a0de0013864e00c295910798431106232ee6fe636fd7069b060700e397b7fe9b07e3ff8217f983f6979c4363e3f80693170e02f983f69723a0170103a74e0083a70e00930600021d45bb07f7406393d70483a68e0085473b87e640631cf70283a7ce001396060201920d47959f32986372f702032708001dc31127b307f7403335f00001c91d4531a00d458280094582800d45130104ff226441018280f1173335f000c5b71c450d47637ef71203380500054583280800639617131d4609456372f6128326480013f53600631b05106379d6101bd326001b0ef3ff1b060e00894e194563f0ce1099e1631de60e13f7c6ff094563e8e70e93170302f983bd079b05d3ff41119183821522e492070008819189053301f1408a8e8a059307480023a0de0013864e00c295910798431106232ee6fe636bd70a9b060700e397b7fe9b07e3ff8217f983f6979c4363eff80893170e02f983f69723a0170103a70e0083a74e00bb86e7408dc20d461d45637fd606021701934297184335cf1127b306d740b336d0001d45b5e203a78e00bb06f7408dc20d461d45637ad60482178193c2979c43a9cf9127b386d740b336d0001d458dee83a7ce000145999f85cb8d461d4563f5f602021701933a98032708001dcb1127b307f7403335f00001c91d4531a00d458280094582800d45130104ff226441018280f116b336d00069b7f116b336d00075b7f1173335f000c1bf39716173216e22f806fc26f461781a9113070e02930788fe0a9721638568aa862e841ae4b305f70008100146054781479388a881730000000f00f00fa2679b040500bde8636cf30613070e020a97130508ff3a95814518103ae83ecceff0dfe331e9025691476307f604925705479bd72700fd376370f704a256081089451397060201932a976384b702b257959f9dc31443a1476390f602834747001ce021631a91e27026854274a27421618280bb07d640f1bff954e5b7f554d5b7d154c5b7fd7779717d732e87938587ff856722f006f426ecc1071a9105688a97aa863284be9542e408080146814793088881730000000f00f00fa2679b040500a9e06363f8061307000d639de7048277130600020c191ce013050402eff0bf822277c166fd1693578702f58f9dc313568701f18e63fff6002217219318e414e81cec05631a91a27026850274e2644561828005631a91a270c15426850274e26445618280f954f1bfd954e1bf054869712143131e880385684ee6ae8eaa8906f622f226ee4aea52e21af808080c180146814613071e0081479388c882730000000f00f00fc27701256305051b6de56394670e37e74cfeb727b3011307772d938797d20149054a93149700139497004263b33760001b8707006318090c23a0f90013080002856842f488102c100146ca8613071e00954793881882730000000f00f00fa277012541e963970709631f090a8677bee0a677bee4c677bee8e677beec2148856842f028080c100146ca8613071e00814793881882730000000f00f00f827701252de9639807076311030a6267b30797006361f71003b70e00ba9723b0fe0063eae70e21480509856842f808080c180146ca8613071e0081479388c882730000000f00f00fc27701256303450d19e1e38e07f37955b2701274f2645269b269126a5561828083a70900e38ae7f2130580fdd5b7b2701274f2645269b269126a1305d0fb556182808c102e879c0019a0e387b7f403c607008346070085070507e308d6fe130570fd7db72c184a8576e4eff03fd13de562750c01eff08fd88547139e8703a26e29e9900193051e004a8576e4eff01fdb29e1c2668a6762672a762e75639ef602b30797006365f702b3b5a70281463385a702ef00107b2295636b8500a26e8547139e870323b0ae0019bf014591b7715581b7130540fc2dbf49551dbf1305b0fb05bf6306051459716173a167a6ec86f4a2f0cae8cee461781a91938707048a97ae862163930508fc8568aa843287be951ae088000146894793881882730000000f00f00f8267012579e56366f30c2167130707040a97130508fd3a95814598003ae83ecceff03f9b5de5064791476307f70016479b572700fd37c5eb03a6090013834900930604020347040083c7040005048504631ef706e318d4fe83470900a5eb930700046315f606e1772164138807fe938587fc930704048a9733850701930704048a97130e00028568be9572e401468146014781479388e880730000000f00f00fa26701251de56396c703930704048a97c2971386070219a0638ec70083c607000347030085070503e388e6fe130580fb11a0795521631a91a6700674e6644669a66965618280131407020190940005473694e383e7f40369810409473699e38de7f28369c104b69905bf130570fb82801571a6e5cae14efd52f956f55eed62e986eda2e95af166e56ae1eefc3ee4b2842a8aae89b68a3a89428cc68b19c223200600630409002320090063040c0023200c00496b856d13048bf1814c138d1d82130404021308000242f088080c100146e68605479547ea88730000000f00f00f8277012505c98547630ef51289476303f50c1305f0fbee604e64ae640e69ea794a7aaa7a0a7bea6b4a6caa6c0a6de67d2d618280e39f07fd614842f428182c1081479388cd82730000000f00f00fa275012589476300f5084dfde36cb8fa980893078bf103c6070083460700850705076317d606e39887fe0546e6854e85eff01fdc29e92148627e42f828080c180146e68605478147ea88730000000f00f00fc277012515e963990703e277adcf9dc063820a02984093171700ba979207052798c0d697626723bc070023b0c70198eb23a09703850c39b71305d0fb2dbf52879c0803c607008346070085070507e313d6fe9418e397d7fee1476397f50403270c0093171700ba9705272320ec0062779207de9798eb066798ef266723a09703850c98e3c1b5e30709faa266c5d60327090093171700ba97920705272320e900b69749b70145c1bd1305c0fbe9b551715af95ef562f166ed6ae96ee586f5a2f1a6edcae9cee5d2e156fdc28c328daa8b2e8b36833a8cbe8d468819c22320060063040c0023200c0063840c0023a00c00b727010083b787f3c96a056a13848af13eec814493091a8213040402930e000276f888100c180146a68609479547ce88730000000f00f00fc277012549c18547630cf5188947630af5061305f0fbae700e74ee644e69ae690e6aea7a4a7baa7b0a7cea6c4a6daa6d6d6182805e879c1003c607008346070085070507631fd6021401e397d7fee1476315f9146667a66546666317071063020c0263800d0283270c001307f00f634bf7121b87170092072320ec00ee978ce390e7850485b7e396d7f9e14e76fca8002c1881479308ca82730000000f00f00f627901258947e30ef5fc65e963e72e0f981093878af103c607008346070085070507e319d6f6e39887fea147e314f9f603479104834781040346a1048346b104d98f0347c104d18f0346d104d58f8346e104d98f0347f104d18fd58fd98f9dfbe3010df8e30f03f60946a6855a8542e81ae4eff05fb62263426825f5cae028108c000146a68609478147ce88730000000f00f00f8667012539ed639e27052277e267e3e0e7f483270d009306f00f63cbf6049b86170092072320dd009a9798e323b407008504bdbde38d0cf0e30b08f083a60c009307f00f63c6d70293971600b6979207852623a0dc00c2978ceb90ef98e3850481bd7555bdbd1305c0fba5bd014595bd055585bd39716173216e22f84af006fc26f461781a91368493060e02aa878a962e872163930588fe85683289b6951ae4be860810014681479388a881730000000f00f00fa2679b0405009de8636cf30613070e020a97130508ff3a95814518103ae83ecceff00fda11e9825691476387f60092571bd727007d3701ef930410fc21631a91e27026854274a27402792161828093950702819108100546aa956300c7022257bb07f740f1db83e705009105e39687fc22864a85efe07fffd1b7bb87f640ddb7d1546dbf75715d7322e1a6fc06e5a564caf8cef4d2f0d6ecdae8dee4e2e066fc6af81a9132849387040210082163b2975d78aa863385674093870402b2972e878568930508febe951ae8014681479388a881730000000f00f00fc2670125631f05166363f3181408138704023697330767403ae4138704023697130508ff3a95226781453ed43af0eff08fcb631b0514a267904391476303f614a2670547dc439bd72700fd37637bf71222672265894514471397060201932a97638eb7105c45959f638d07101443a1476399f610a566100893870602b297dd74138984febe9493870602b2973e9985688339470023b414ff2685ca85014681461147814793888881730000000f00f00f83b784fe1b0a0500631f0a081307000d639be708416db70a0001130f0402854ca68b138b040a7d1dfd1a25a8637d6e06233404012338c401233c64006387890723b4dbff730000000f00f00f83b78bfe01251307000d21e963e7fe04850c6394e70403bc0b01da85130600027a8523308401efe0ffe683b78b01856e2a8f13d3870213de87013373a30133f857012685ca850146e6861147814793888e81337eae01e31503f8130a40fc25631a91aa6052850a64e6744679a679067ae66a466ba66b066ce27c427d49618280bb07d640e5b5130a00fcd1bf130a10fcf9b7515ae9b75d716173216e26fc4af886e4a2e04ef461781a9113070e02930788fe0a9721638568aa842e891ae4b305f7000810014681460147814793884880730000000f00f00fa2671b04050039ec6368f30613070e020a97411833050701814518103ae83ecceff04f9d2de1025791476309f700925709479bd72700fd376362f70403a709009307000493854900631ff702130600022685efe0bfd613060002938549024a85efe0dfd521631a91a6602285e27406644279a279616182800d44edb78369c1021c10be9965bf7954f1bf75716173e177216706e522e1a6fccaf8cef4d2f0d6ec1a911408ae8e138807fe938507fc93070704b6972a833385070193070704328eb697130f00028568be957ae80146f6867287954793881882730000000f00f00fc26701250dc18947630cf512795921631a91aa604a850a64e6744679a679067ae66a49618280e393e7ffa167938707041808ba97c297814a014a61781386070283c607000347030085070503639ae60ee398c7fe216f180893070f04ba97b384070193070f04ba972163930588fc8568be9523b464fc26850146f6867287894793881882730000000f00f00f83b784fc1b090500e31c09f6e36af3f613070f041408130508fd369781453a9523b894fc23acf4fceff00f8631f9944091476384f608d8409b572700fd37b5cf13140702019005462694bb8ae6406386c70603aa8400130600023b07ea40e311c7f293190a0293d909020947a699638be7042167130707041408e1773697ba973ee4dc473b8a47418547e31bfaee83c709008de3c967938787ef1386070219a0e381c7ee8346040003c7070005048507e388e6fe130940fde9b593070002e385fafc7dbd3b8a4641c1b7397126f4b284094622f806fc2e84eff07fe415e96148856842e028008a850146a286094781479388c882730000000f00f00f8267012509ed639c0701a2674267639b970009ebe2704274a27421618280130540fdcdbf130550fdf5b759710546a2f086f42e84eff0ffdeaa8e45e5130e400213088103856872e842850c080146a2860547814793883882730000000f00f00f42639b0e0500639c0e06631ac307e27662171ae436ec866642852c0036f0a666050736f4c66636f88146730000000f00f00fa267012535e1639367040543ba8f468f42873c0803c607008346070085070507631dd602e39807ff72e442852c0001469a867e878147fa88730000000f00f00fa267012515e10503e384c7fd930ea0fba6700674768565618280a6700674930e30fd7685656182808547e311f5fecdb705473971214862178568aa8f02f042e408102c00014681460507814793881882730000000f00f00fa267012521e96394070502730548214e3a8fc68e11a8639cc703827705089a9733b767003e8305ef02f072e408102c000146c2867a878147f688730000000f00f00fa267012561d98547630df50079552161828085470143e31bf5fe21a071552161828013080002856842e808100c080146814609478d4793881882730000000f00f00fc2670125014f49e1e39107fd0148014fa14e468e930200027e871c1003c607008346070085070507631dd6029400e397d7fe02e076ec0a852c080146c28609478147f288730000000f00f00fe26701252dfde39cd7f78267fa9733b7e7013e8f2dff050816e808100c080146c28609478d47f288730000000f00f00fc267012501e5e38b57f891b78547e310f5f40145e37e6ff2130510fd15bf6971657322f226ee4aeaeae906f64ee652e2d6fddaf9def5e2f1e6edeee51d691a911418130709093697e977ba973ee4be88657493070909b697130804f72ef03e9801478147814601468145aa84eff04fc32a8d1dc11d631a91b2706a851274f2645269b269126aee7a4e7bae7b0e7cee6c4e6dae6d55618280181893070909ba97f578be9893070909ba97130844f73e98014781478146014681452685eff02fda2a8d4df9c257638c071ea267130604f81d6403e50702181893070409ba973e968545eff03f862a8d63100512c257635ef01c657a1018130704093297930c8af7ba9c370700017d1722693ae41307040993070afc3297ba97814a81493eec2af49d6793870709181883330900ba97b38447010334090103bb04f883bb84fa6388030c856823bc14f72685e685014681461147814793888881730000000f00f00f83b784f701254de11307000d639ee708c162854f2688fd12056cc68d130d000d22e80334080a033e8801833e0801233088fe0334880aa26713538e02233488fe0334080b135f8e012330d8fd233888fe0334880b33735300337efe00233c88fe2685e6850146fe8611478147ee88337f5f00630b030263796f022334c8fd2338e8fd233c68fc638ed30b233c88f7730000000f00f00f833788f7012511e56365fc00850fe38fa7f7130d00fca5b50365090262668545efe03fe97df583be04fc63846e096360db0bb33574032a76814633057403ef00a0094e95b3373501aa89b9efc257852a13090903e3cbfaec227d1d66130706091418e5773697ba973ee483a747f7635af004fd37130706098217101881933297f576ba969395170013870604be95946a9205ba956301b7021c6313070703b69733b6d700be867dd6715dd1bb4264e3906ef9228579b7b386d940b3b7d900b689e5f78277e38d37db130d50fd4dbb130df0fd75b3814951b7814863da05003305a040b337a000b305b0409d8dfd5863db06003306c040b337c000b306d04093c8f8ff9d8e32882a8e2e83639e062063f1c50c13078003b357e60093f7f70f99e3611775fbc966938606f4b357e600b69783c6070093070004998f958f8dc31b8e0700130300043b03c341b395c501335365003318c6013363b300331ec50193550802b377b30213160802019213570e023353b30282175d8fb30666029a87637cd70042979307f3ff636707016375d7009307e3ff4297158fb376b702021e135e0e023357b702821633eec6013306e6023a85637bce00429e1305f7ff63660e016374ce001305e7ff8217c98f01436da001e605483358d80213078003b357e80093f7f70f99e3611775fbc966b357e800938606f4b69783c70700ba97130700041d8f59e7b385054105431355080213160802019293560e0233d7a502b3f7a502b305e6028217dd8eba8763fcb600c2969307f7ff63e7060163f5b6009307e7ffc2968d8e33f7a602021e135e0e02b3d6a6020217336ec7013306d6023685637bce00429e1385f6ff63660e016374ce001385e6ff8217c98f3e859a85638908003305f040b337a000b30560409d8d82801b0e07003318c801812733d7f500b395c501b357f500331ec5011355080233e6b700b377a702931508028191135306023357a7028217b3e76700b386e5023a8363fcd700c2971303f7ff63e7070163f5d7001303e7ffc297b386d740b3f7a60202160192b3d6a60282173387d502b3e5c700b68763fce500c2959387f6ff63e7050163f5e5009387e6ffc2950213998d3363f300ddb563e2d5149307800333d7f6001377f70f19e3e117f5fb496833d7f600130808f4429703470700130300043e973303e340631c03008547e3eeb6f0b337c50093c717008217819331b71b0e03000127b357e600b396c601dd8e13df0602b3d7e50033f8e703939e0602b395c5013357e50093de0e023363b700135703023316c601b3d7e70302183367e800b385fe023e88637cb70036971388f7ff6367d7006375b7001388e7ff36970d8fb375e7030213135303023357e7038215b3e56500b38eee023a8363fcd501b6951303f7ff63e7d50063f5d5011303e7ffb6953387d54193170802fd55b3e76700819133f3b70013d80702f18d0192b30eb302b305b80293d60e023303c3022e939a963308c80263f5b60005460216329813d606023298636007030143e31607e37d570193f98e8216b3feee003315c501f696e37bd5e0fd1795b30143814729b5000010c653a5cf01334a9339937751ec6d4fb4549f720b3456ebc58c91a76d4d76dacc77c4deac05d68ab5b26828f0bf4565a8d73113d7bb7e92b8362b8a74e58e580080c6a47e8d0300000102020303030304040404040404040505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808081000000000000000017a5200017c01011b0d0200100000001800000002fbffff98030000000000004743433a2028474e552920382e332e30004128000000726973637600011e0000000572763634693270305f6d3270305f613270305f6332703000002e7368737472746162002e74657874002e726f64617461002e65685f6672616d65002e636f6d6d656e74002e72697363762e6174747269627574657300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b000000010000000600000000000000780001000000000078000000000000007e1e00000000000000000000000000000200000000000000000000000000000011000000010000000200000000000000f81e010000000000f81e000000000000480100000000000000000000000000000800000000000000000000000000000019000000010000000200000000000000402001000000000040200000000000002800000000000000000000000000000008000000000000000000000000000000230000000100000030000000000000000000000000000000682000000000000011000000000000000000000000000000010000000000000001000000000000002c000000030000700000000000000000000000000000000079200000000000002900000000000000000000000000000001000000000000000000000000000000010000000300000000000000000000000000000000000000a2200000000000003e00000000000000000000000000000001000000000000000000000000000000","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000da1dedf507d990897399489ac509c4754146186bb7b5e7ecabf224a6ff929dc45443f4f0374f12a21a4ab320251f527789e5604ce7b96eff0963a86aea750aea00"]}"#).unwrap();
    assert!(rpc.send_transaction(transaction).is_ok());
}
