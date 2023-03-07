use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

use golomb_coded_set::{GCSFilterWriter, SipHasher24Builder, M, P};

use ckb_network::{bytes::Bytes, CKBProtocolHandler, PeerIndex, SupportProtocols};
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
        utils::{MockChain, MockNetworkContext},
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

#[tokio::test]
async fn test_block_filter_ok_with_blocks_not_matched() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
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
    let block_hashes = vec![H256(rand::random()).pack(), H256(rand::random()).pack()];
    let blocks_count = block_hashes.len();
    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(block_hashes.pack())
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

#[tokio::test]
async fn test_block_filter_ok_with_blocks_matched() {
    let chain = MockChain::new_with_dummy_pow("test-block-filter");
    let nc = MockNetworkContext::new(SupportProtocols::Filter);

    let min_filtered_block_number = 3;
    let proved_number = min_filtered_block_number + 1;
    let start_number = min_filtered_block_number + 1;
    let script = Script::new_builder()
        .code_hash(H256(rand::random()).pack())
        .args(Bytes::from(vec![1, 2, 3]).pack())
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

    let header = HeaderBuilder::default()
        .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
        .number((proved_number).pack())
        .build();
    let tip_header =
        VerifiableHeader::new(header.clone(), Default::default(), None, Default::default());
    chain
        .client_storage()
        .update_last_state(&U256::one(), &tip_header.header().data(), &[]);

    let peer_index = PeerIndex::new(3);
    let (peers, prove_state_block_hash) = {
        let prove_state_block_hash = header.hash();
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        (peers, prove_state_block_hash)
    };

    let filter_data = {
        let mut writer = std::io::Cursor::new(Vec::new());
        let mut filter = GCSFilterWriter::new(&mut writer, SipHasher24Builder::new(0, 0), M, P);
        filter.add_element(script.calc_script_hash().as_slice());
        filter
            .finish()
            .expect("flush to memory writer should be OK");
        writer.into_inner()
    };
    let block_hash = H256(rand::random());

    let content = packed::BlockFilters::new_builder()
        .start_number(start_number.pack())
        .block_hashes(vec![block_hash.pack(), H256(rand::random()).pack()].pack())
        .filters(vec![filter_data.pack(), Bytes::from("def").pack()].pack())
        .build();
    let message = packed::BlockFilterMessage::new_builder()
        .set(content)
        .build()
        .as_bytes();

    let mut protocol = chain.create_filter_protocol(Arc::clone(&peers));
    peers.mock_latest_block_filter_hashes(
        peer_index,
        0,
        vec![Default::default(); start_number as usize + 2],
    );
    protocol.received(nc.context(), peer_index, message).await;
    assert!(nc.not_banned(peer_index));

    let get_blocks_proof_message = {
        let content = packed::GetBlocksProof::new_builder()
            .block_hashes(vec![block_hash.pack()].pack())
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
