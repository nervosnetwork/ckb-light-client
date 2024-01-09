use ckb_network::{bytes::Bytes, CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_systemtime::{faketime, unix_time_as_millis};
use ckb_types::{
    core::{BlockNumber, EpochNumberWithFraction, HeaderBuilder},
    packed,
    prelude::*,
    utilities::{merkle_mountain_range::VerifiableHeader, DIFF_TWO},
    H256, U256,
};

use crate::{
    protocols::{
        light_client::constant::{
            GET_IDLE_BLOCKS_TOKEN, REFRESH_PEERS_DURATION, REFRESH_PEERS_TOKEN,
        },
        PeerState, BAD_MESSAGE_BAN_TIME,
    },
    tests::{
        prelude::*,
        utils::{setup, MockChain, MockNetworkContext},
    },
};

mod send_blocks_proof;
mod send_last_state;
mod send_last_state_proof;
mod send_transactions_proof;

#[tokio::test]
async fn malformed_message() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peers = chain.create_peers();
    let mut protocol = chain.create_light_client_protocol(peers);

    let peer_index = PeerIndex::new(3);
    let data = Bytes::from(vec![2, 3, 4, 5]);
    protocol.received(nc.context(), peer_index, data).await;

    assert_eq!(
        nc.has_banned(peer_index).map(|(duration, _)| duration),
        Some(BAD_MESSAGE_BAN_TIME)
    );
}

#[test]
fn build_prove_request_content() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");

    let peers = chain.create_peers();
    let protocol = chain.create_light_client_protocol(peers);
    let storage = chain.client_storage();

    let peer_state = PeerState::default();
    let default_compact_target = DIFF_TWO;
    let default_block_difficulty = 2u64;
    let last_number = 50;
    let last_total_difficulty = 500u64;
    let last_n_blocks = protocol.last_n_blocks();
    let epoch_length = last_n_blocks + last_number + 100;

    // Setup the storage.
    {
        let epoch = EpochNumberWithFraction::new(0, last_number, epoch_length);
        let header = HeaderBuilder::default()
            .number(last_number.pack())
            .epoch(epoch.pack())
            .build();
        let last_total_difficulty = U256::from(last_total_difficulty);
        storage.update_last_state(&last_total_difficulty, &header.data(), &[]);
    }

    // Test different total difficulties.
    {
        let header = {
            let new_last_number = last_number + 1;
            let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
            HeaderBuilder::default()
                .number(new_last_number.pack())
                .epoch(epoch.pack())
                .compact_target(default_compact_target.pack())
                .build()
        };
        for diff in 1u64..10 {
            let new_last_total_difficulty =
                U256::from(last_total_difficulty - default_block_difficulty - diff);
            let parent_chain_root = packed::HeaderDigest::new_builder()
                .total_difficulty(new_last_total_difficulty.pack())
                .build();
            let verifiable_header =
                VerifiableHeader::new(header.clone(), Default::default(), None, parent_chain_root);
            let prove_request =
                protocol.build_prove_request_content(&peer_state, &verifiable_header);
            assert!(prove_request.is_none());
        }
        for diff in 0u64..10 {
            let new_last_total_difficulty =
                U256::from(last_total_difficulty - default_block_difficulty + diff);
            let parent_chain_root = packed::HeaderDigest::new_builder()
                .total_difficulty(new_last_total_difficulty.pack())
                .build();
            let verifiable_header =
                VerifiableHeader::new(header.clone(), Default::default(), None, parent_chain_root);
            let prove_request =
                protocol.build_prove_request_content(&peer_state, &verifiable_header);
            assert!(prove_request.is_some());
            let start_number: BlockNumber = prove_request.expect("checked").start_number().unpack();
            assert_eq!(start_number, last_number);
        }
    }

    // Test different block numbers.
    {
        let new_last_total_difficulty =
            U256::from(last_total_difficulty + default_block_difficulty);

        for new_last_number in 1..=last_number {
            let verifiable_header = {
                let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
                let header = HeaderBuilder::default()
                    .number(new_last_number.pack())
                    .epoch(epoch.pack())
                    .build();
                let parent_chain_root = packed::HeaderDigest::new_builder()
                    .total_difficulty(new_last_total_difficulty.pack())
                    .build();
                VerifiableHeader::new(header, Default::default(), None, parent_chain_root)
            };
            let prove_request =
                protocol.build_prove_request_content(&peer_state, &verifiable_header);
            assert!(prove_request.is_none());
        }

        for new_last_number in (last_number + 1)..=(last_number + last_n_blocks + 10) {
            let verifiable_header = {
                let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
                let header = HeaderBuilder::default()
                    .number(new_last_number.pack())
                    .epoch(epoch.pack())
                    .build();
                let parent_chain_root = packed::HeaderDigest::new_builder()
                    .total_difficulty(new_last_total_difficulty.pack())
                    .build();
                VerifiableHeader::new(header, Default::default(), None, parent_chain_root)
            };
            let prove_request =
                protocol.build_prove_request_content(&peer_state, &verifiable_header);
            assert!(prove_request.is_some());
            let prove_request = prove_request.expect("checked");
            let start_number: BlockNumber = prove_request.start_number().unpack();
            assert_eq!(start_number, last_number);
            let difficulty_boundary: U256 = prove_request.difficulty_boundary().unpack();
            let difficulties = prove_request.difficulties();
            let expected_difficulty_boundary = U256::from(last_total_difficulty);
            if new_last_number - last_number <= last_n_blocks {
                assert!(difficulties.is_empty());
                assert_eq!(difficulty_boundary, expected_difficulty_boundary);
            }
        }
    }
}

#[tokio::test]
async fn test_light_client_get_idle_matched_blocks() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(3);
    let tip_header = VerifiableHeader::new(
        HeaderBuilder::default()
            .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
            .number(3u64.pack())
            .build(),
        Default::default(),
        None,
        Default::default(),
    );
    chain
        .client_storage()
        .update_last_state(&U256::one(), &tip_header.header().data(), &[]);
    let tip_hash = tip_header.header().hash();
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };
    let unproved_block_hash = H256(rand::random()).pack();
    let proved_block_hash = H256(rand::random()).pack();
    let blocks = vec![
        (unproved_block_hash.clone(), false),
        (proved_block_hash.clone(), true),
    ];
    {
        let mut matched_blocks = peers.matched_blocks().write().expect("poisoned");
        peers.add_matched_blocks(&mut matched_blocks, blocks);
    }

    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.notify(nc.context(), GET_IDLE_BLOCKS_TOKEN).await;

    let content = packed::GetBlocksProof::new_builder()
        .block_hashes(vec![unproved_block_hash].pack())
        .last_hash(tip_hash.clone())
        .build();
    let get_blocks_proof_message = packed::LightClientMessage::new_builder()
        .set(content.clone())
        .build()
        .as_bytes();
    let content = packed::GetBlocks::new_builder()
        .block_hashes(vec![proved_block_hash].pack())
        .build();
    let get_blocks_message = packed::SyncMessage::new_builder()
        .set(content.clone())
        .build()
        .as_bytes();
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
            )
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_all_peers() {
    setup();

    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    let storage = chain.client_storage();

    let mut num = 20;
    chain.mine_to(num);

    // Setup the storage.
    {
        let snapshot = chain.shared().snapshot();
        let header = snapshot.get_header_by_number(num).expect("block stored");
        let last_total_difficulty = U256::from(500u64);
        storage.update_last_state(&last_total_difficulty, &header.data(), &[]);
    }

    num -= 5;

    // A node, whose tip number is small than client, connect to the client.
    {
        let snapshot = chain.shared().snapshot();
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let content = packed::SendLastState::new_builder()
                .last_header(last_header)
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
                .as_bytes()
        };

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_last_state().is_none());
        assert!(nc.sent_messages().borrow().is_empty());

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_last_state().is_some());
        assert!(nc.sent_messages().borrow().is_empty());
    }

    // Referesh all peers.
    {
        let start_ts = unix_time_as_millis();
        let timeout_ts = start_ts + REFRESH_PEERS_DURATION.as_millis() as u64 + 1;
        let faketime_guard = faketime();
        faketime_guard.set_faketime(timeout_ts);

        protocol.notify(nc.context(), REFRESH_PEERS_TOKEN).await;

        let content = packed::GetLastState::new_builder()
            .subscribe(true.pack())
            .build();
        let get_last_state_message = packed::LightClientMessage::new_builder()
            .set(content)
            .build()
            .as_bytes();
        assert_eq!(
            nc.sent_messages().borrow().clone(),
            vec![(
                SupportProtocols::LightClient.protocol_id(),
                peer_index,
                get_last_state_message
            )]
        );
    }
}
