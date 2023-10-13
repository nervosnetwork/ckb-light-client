use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

use ckb_network::{bytes::Bytes, CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_store::ChainStore as _;
use ckb_types::{
    core::{EpochNumberWithFraction, HeaderBuilder},
    packed::{self, Script},
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    H256, U256,
};

use crate::storage::SetScriptsCommand;
use crate::storage::{ScriptStatus, ScriptType};
use crate::{
    protocols::{BAD_MESSAGE_BAN_TIME, GET_BLOCK_FILTERS_TOKEN},
    tests::{
        prelude::*,
        utils::{setup, MockChain, MockNetworkContext},
    },
};

#[tokio::test]
async fn test_block_filter_malformed_message() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let peers = chain.create_peers();
    let mut protocol = chain.create_filter_protocol(peers);

    let peer_index = PeerIndex::new(3);
    let data = Bytes::from(vec![2, 3, 4, 5]);
    protocol.received(nc.context(), peer_index, data).await;

    assert_eq!(
        nc.has_banned(peer_index).map(|(duration, _)| duration),
        Some(BAD_MESSAGE_BAN_TIME)
    );
}

#[tokio::test]
async fn test_block_filter_ignore_start_number() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number((min_filtered_block_number + 1).pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);
    let content = packed::BlockFilters::new_builder()
        .start_number((min_filtered_block_number - 1).pack())
        .block_hashes(vec![H256(rand::random()).pack(), H256(rand::random()).pack()].pack())
        .filters(vec![Bytes::from("abc").pack(), Bytes::from("def").pack()].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build();

    let peer_index = PeerIndex::new(3);
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.not_banned(peer_index));
    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_empty_filters() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number((min_filtered_block_number + 1).pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);
    let content = packed::BlockFilters::new_builder()
        .start_number((min_filtered_block_number + 1).pack())
        .block_hashes(vec![].pack())
        .filters(vec![].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build();

    let peer_index = PeerIndex::new(3);
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.not_banned(peer_index));
    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_invalid_filters_count() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number((min_filtered_block_number + 1).pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);
    let content = packed::BlockFilters::new_builder()
        .start_number((min_filtered_block_number + 1).pack())
        .block_hashes(vec![H256(rand::random()).pack(), H256(rand::random()).pack()].pack())
        .filters(vec![].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build();

    let peer_index = PeerIndex::new(3);
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert_eq!(
        nc.has_banned(peer_index).map(|(duration, _)| duration),
        Some(BAD_MESSAGE_BAN_TIME)
    );
    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_start_number_greater_then_proved_number() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    let proved_number = min_filtered_block_number;
    let start_number = min_filtered_block_number + 1;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number((proved_number).pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));
    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(vec![H256(rand::random()).pack(), H256(rand::random()).pack()].pack())
        .filters(vec![Bytes::from("abc").pack(), Bytes::from("def").pack()].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build();

    peers.mock_latest_block_filter_hashes(
        peer_index,
        0,
        vec![Default::default(); proved_number as usize],
    );
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.not_banned(peer_index));
    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_filter_ok_with_blocks_not_matched() {
    setup();

    let chain = MockChain::new_with_dummy_pow("test-block-filter").start();
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 30;
    let proved_number = min_filtered_block_number + 3;
    let start_number = min_filtered_block_number + 1;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    chain.mine_to(proved_number);

    let snapshot = chain.shared().snapshot();

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header: VerifiableHeader = snapshot
            .get_verifiable_header_by_number(proved_number)
            .expect("block stored")
            .into();
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };

    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));

    let block_hashes = {
        let block_hash_1 = snapshot.get_block_hash(start_number).unwrap();
        let block_hash_2 = snapshot.get_block_hash(start_number + 1).unwrap();
        vec![block_hash_1, block_hash_2]
    };
    let filters = {
        let filter_data_1 = snapshot.get_block_filter_data(start_number).unwrap();
        let filter_data_2 = snapshot.get_block_filter_data(start_number + 1).unwrap();
        vec![filter_data_1, filter_data_2]
    };
    let filter_hashes = {
        let mut filter_hashes = snapshot
            .get_block_filter_hashes_until(proved_number)
            .unwrap();
        filter_hashes.remove(0);
        filter_hashes
    };

    let blocks_count = block_hashes.len();
    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(block_hashes.pack())
        .filters(filters.pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build();

    peers.mock_latest_block_filter_hashes(peer_index, 0, filter_hashes);
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    let filtered_block_number = start_number - 1 + blocks_count as u64;
    assert!(nc.not_banned(peer_index));
    assert_eq!(
        chain.client_storage().get_filter_scripts()[0].block_number,
        filtered_block_number
    );
    let message = {
        let content = packed::GetBlockFilters::new_builder()
            .start_number((filtered_block_number + 1).pack())
            .build();
        packed::BlockFilterMessage::new_builder()
            .set(content)
            .build()
    };
    assert_eq!(
        nc.sent_messages().borrow().clone(),
        vec![(
            SupportProtocols::Filter.protocol_id(),
            peer_index,
            message.as_bytes()
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_filter_ok_with_blocks_matched() {
    setup();

    let chain = MockChain::new_with_dummy_pow("test-block-filter").start();
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 30;
    let start_number = min_filtered_block_number + 1;
    let proved_number = start_number + 5;
    let script = Script::new_builder()
        .code_hash(H256(rand::random()).pack())
        .build();
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    chain
        .client_storage()
        .update_min_filtered_block_number(min_filtered_block_number);

    chain.mine_to(start_number - 3);

    {
        let tx = {
            let tx = chain.get_cellbase_as_input(start_number - 5);
            let output = tx.output(0).unwrap().as_builder().lock(script).build();
            tx.as_advanced_builder().set_outputs(vec![output]).build()
        };
        chain.mine_block(|block| {
            let ids = vec![tx.proposal_short_id()];
            block.as_advanced_builder().proposals(ids).build()
        });
        chain.mine_blocks(1);
        chain.mine_block(|block| block.as_advanced_builder().transaction(tx.clone()).build());
        chain.mine_blocks(1);
    }

    chain.mine_to(proved_number);

    let snapshot = chain.shared().snapshot();

    let tip_header: VerifiableHeader = snapshot
        .get_verifiable_header_by_number(proved_number)
        .expect("block stored")
        .into();
    chain
        .client_storage()
        .update_last_state(&U256::one(), &tip_header.header().data(), &[]);

    let peer_index = PeerIndex::new(3);
    let (peers, prove_state_block_hash) = {
        let prove_state_block_hash = tip_header.header().hash();
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        (peers, prove_state_block_hash)
    };

    let filter_data_1 = snapshot.get_block_filter_data(start_number).unwrap();
    let filter_data_2 = snapshot.get_block_filter_data(start_number + 1).unwrap();
    let block_hash_1 = snapshot.get_block_hash(start_number).unwrap();
    let block_hash_2 = snapshot.get_block_hash(start_number + 1).unwrap();
    let filter_hashes = {
        let mut filter_hashes = snapshot
            .get_block_filter_hashes_until(start_number + 3)
            .unwrap();
        filter_hashes.remove(0);
        filter_hashes
    };

    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(vec![block_hash_1.clone(), block_hash_2].pack())
        .filters(vec![filter_data_1, filter_data_2].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build()
        .as_bytes();

    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));
    peers.mock_latest_block_filter_hashes(peer_index, 0, filter_hashes);
    protocol.received(nc.context(), peer_index, message).await;
    assert!(nc.not_banned(peer_index));

    let get_blocks_proof_message = {
        let content = packed::GetBlocksProof::new_builder()
            .block_hashes(vec![block_hash_1].pack())
            .last_hash(prove_state_block_hash)
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
            .as_bytes()
    };
    let get_block_filters_message = {
        let blocks_count = 2;
        let new_start_number = start_number - 1 + blocks_count + 1;
        let content = packed::GetBlockFilters::new_builder()
            .start_number(new_start_number.pack())
            .build();
        packed::BlockFilterMessage::new_builder()
            .set(content)
            .build()
            .as_bytes()
    };
    assert_eq!(
        nc.sent_messages().borrow().clone(),
        vec![
            (
                SupportProtocols::LightClient.protocol_id(),
                peer_index,
                get_blocks_proof_message
            ),
            (
                SupportProtocols::Filter.protocol_id(),
                peer_index,
                get_block_filters_message
            )
        ]
    );
}

#[tokio::test]
async fn test_block_filter_notify_ask_filters() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    // for should_ask() return true
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number((min_filtered_block_number + 1).pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));

    peers.mock_latest_block_filter_hashes(
        peer_index,
        0,
        vec![Default::default(); min_filtered_block_number as usize + 1],
    );
    protocol.notify(nc.context(), GET_BLOCK_FILTERS_TOKEN).await;
    let message = {
        let start_number: u64 = min_filtered_block_number + 1;
        let content = packed::GetBlockFilters::new_builder()
            .start_number(start_number.pack())
            .build();
        packed::BlockFilterMessage::new_builder()
            .set(content)
            .build()
    };

    assert_eq!(
        nc.sent_messages().borrow().clone(),
        vec![(
            SupportProtocols::Filter.protocol_id(),
            peer_index,
            message.as_bytes()
        )]
    );
}

#[tokio::test]
async fn test_block_filter_notify_no_proved_peers() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let peer_index = PeerIndex::new(3);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);

    protocol.notify(nc.context(), GET_BLOCK_FILTERS_TOKEN).await;

    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_notify_not_reach_ask() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number(5u64.pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);
    protocol.last_ask_time = Arc::new(RwLock::new(Some(Instant::now())));

    protocol.notify(nc.context(), GET_BLOCK_FILTERS_TOKEN).await;

    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_notify_proved_number_not_big_enough() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    // for should_ask() return true
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: Script::default(),
            script_type: ScriptType::Lock,
            block_number: min_filtered_block_number,
        }],
        Default::default(),
    );

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number(min_filtered_block_number.pack())
                .build(),
            Default::default(),
            None,
            Default::default(),
        );
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let mut protocol = chain.create_filter_protocol(peers);

    protocol.notify(nc.context(), GET_BLOCK_FILTERS_TOKEN).await;

    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test]
async fn test_block_filter_notify_recover_matched_blocks() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    chain
        .client_storage()
        .update_min_filtered_block_number(min_filtered_block_number);

    let peer_index = PeerIndex::new(3);
    let tip_header = VerifiableHeader::new(
        HeaderBuilder::default()
            .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
            .number((min_filtered_block_number + 2).pack())
            .build(),
        Default::default(),
        None,
        Default::default(),
    );
    let tip_hash = tip_header.header().hash();
    chain
        .client_storage()
        .update_last_state(&U256::one(), &tip_header.header().data(), &[]);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let unproved_block_hash = H256(rand::random()).pack();
    let proved_block_hash = H256(rand::random()).pack();
    let matched_blocks = vec![
        (unproved_block_hash.clone(), false),
        (proved_block_hash.clone(), true),
    ];
    chain
        .client_storage()
        .add_matched_blocks(2, 2, matched_blocks);
    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));

    peers.mock_latest_block_filter_hashes(
        peer_index,
        0,
        vec![Default::default(); min_filtered_block_number as usize + 2],
    );
    protocol.notify(nc.context(), GET_BLOCK_FILTERS_TOKEN).await;

    let get_blocks_proof_message = {
        let content = packed::GetBlocksProof::new_builder()
            .block_hashes(vec![unproved_block_hash].pack())
            .last_hash(tip_hash.clone())
            .build();
        packed::LightClientMessage::new_builder()
            .set(content.clone())
            .build()
            .as_bytes()
    };
    let get_blocks_message = {
        let content = packed::GetBlocks::new_builder()
            .block_hashes(vec![proved_block_hash].pack())
            .build();
        packed::SyncMessage::new_builder()
            .set(content.clone())
            .build()
            .as_bytes()
    };
    let get_block_filters_message = {
        let start_number: u64 = min_filtered_block_number + 1;
        let content = packed::GetBlockFilters::new_builder()
            .start_number(start_number.pack())
            .build();
        packed::BlockFilterMessage::new_builder()
            .set(content)
            .build()
            .as_bytes()
    };
    assert_eq!(
        nc.sent_messages().borrow().clone(),
        vec![
            (
                SupportProtocols::LightClient.protocol_id(),
                peer_index,
                get_blocks_proof_message,
            ),
            (
                SupportProtocols::Sync.protocol_id(),
                peer_index,
                get_blocks_message,
            ),
            (
                SupportProtocols::Filter.protocol_id(),
                peer_index,
                get_block_filters_message,
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_filter_without_enough_hashes() {
    setup();

    let chain = MockChain::new_with_dummy_pow("test-block-filter").start();
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 30;
    let start_number = min_filtered_block_number + 1;
    let proved_number = start_number + 5;
    let script = Script::new_builder()
        .code_hash(H256(rand::random()).pack())
        .build();
    chain.client_storage().update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    chain
        .client_storage()
        .update_min_filtered_block_number(min_filtered_block_number);

    chain.mine_to(start_number - 3);

    {
        let tx = {
            let tx = chain.get_cellbase_as_input(start_number - 5);
            let output = tx.output(0).unwrap().as_builder().lock(script).build();
            tx.as_advanced_builder().set_outputs(vec![output]).build()
        };
        chain.mine_block(|block| {
            let ids = vec![tx.proposal_short_id()];
            block.as_advanced_builder().proposals(ids).build()
        });
        chain.mine_blocks(1);
        chain.mine_block(|block| block.as_advanced_builder().transaction(tx.clone()).build());
        chain.mine_blocks(1);
    }

    chain.mine_to(proved_number);

    let snapshot = chain.shared().snapshot();

    let tip_header: VerifiableHeader = snapshot
        .get_verifiable_header_by_number(proved_number)
        .expect("block stored")
        .into();
    chain
        .client_storage()
        .update_last_state(&U256::one(), &tip_header.header().data(), &[]);

    let peer_index = PeerIndex::new(3);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers.set_max_outbound_peers(3);
        peers
    };

    let filter_data_1 = snapshot.get_block_filter_data(start_number).unwrap();
    let filter_data_2 = snapshot.get_block_filter_data(start_number + 1).unwrap();
    let block_hash_1 = snapshot.get_block_hash(start_number).unwrap();
    let block_hash_2 = snapshot.get_block_hash(start_number + 1).unwrap();
    let filter_hashes = {
        let mut filter_hashes = snapshot
            .get_block_filter_hashes_until(start_number + 3)
            .unwrap();
        filter_hashes.remove(0);
        filter_hashes
    };

    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(vec![block_hash_1.clone(), block_hash_2].pack())
        .filters(vec![filter_data_1, filter_data_2].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build()
        .as_bytes();

    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));
    peers.mock_latest_block_filter_hashes(peer_index, 0, filter_hashes);
    protocol.received(nc.context(), peer_index, message).await;
    assert!(nc.not_banned(peer_index));

    assert!(nc.sent_messages().borrow().is_empty());
}
