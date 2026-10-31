use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core::BlockNumber, h256, packed, prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader, H256,
};
use std::collections::HashMap;

use crate::{
    protocols::{LastState, MatchedBlockState, ProveRequest, ProveState, StatusCode},
    storage::LightClientStorage,
    tests::{
        prelude::*,
        utils::{MockChain, MockNetworkContext},
    },
};

#[tokio::test]
async fn peer_state_is_not_found() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peers = chain.create_peers();
    let mut protocol = chain.create_light_client_protocol(peers);

    let data = {
        let content = packed::SendBlocksProof::new_builder().build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    }
    .as_bytes();

    let peer_index = PeerIndex::new(1);
    protocol.received(nc.context(), peer_index, data).await;

    assert!(nc.banned_since(peer_index, StatusCode::PeerIsNotFound));
}

#[tokio::test]
async fn no_matched_request() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);

    let data = {
        let content = packed::SendBlocksProof::new_builder().build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    }
    .as_bytes();

    protocol.received(nc.context(), peer_index, data).await;

    assert!(nc.banned_since(peer_index, StatusCode::PeerIsNotOnProcess));
}

#[tokio::test(flavor = "multi_thread")]
async fn last_state_is_changed() {
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

    let mut num = 12;
    chain.mine_to(12 + 1);

    let snapshot = chain.shared().snapshot();

    let block_numbers = vec![3, 5, 8];

    // Setup the test fixture.
    {
        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = protocol
                .build_prove_request_content(&peer_state, &last_header)
                .await
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        let prove_state = {
            let last_n_blocks_start_number = if num > protocol.last_n_blocks() + 1 {
                num - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (last_n_blocks_start_number..num)
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers, &[]);
        let expected_heights = block_numbers
            .iter()
            .map(|&n| {
                (
                    snapshot
                        .get_header_by_number(n)
                        .expect("block stored")
                        .hash()
                        .unpack(),
                    n,
                )
            })
            .collect::<HashMap<H256, BlockNumber>>();
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
        protocol
            .commit_prove_state(peer_index, prove_state)
            .await
            .unwrap();
        protocol.peers().update_blocks_proof_request(
            peer_index,
            Some(content),
            expected_heights,
            true,
        );
    }

    num += 1;

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let content = packed::SendBlocksProof::new_builder()
                .last_header(last_header.clone())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let peer = protocol.get_peer(&peer_index).expect("has peer");
        assert!(peer.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unexpected_response() {
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

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let bad_block_numbers = vec![3, 5, 7, 11, 16, 18];

    // Setup the test fixture.
    {
        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = protocol
                .build_prove_request_content(&peer_state, &last_header)
                .await
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        let prove_state = {
            let last_n_blocks_start_number = if num > protocol.last_n_blocks() + 1 {
                num - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (last_n_blocks_start_number..num)
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers, &[]);
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
        protocol
            .commit_prove_state(peer_index, prove_state)
            .await
            .unwrap();
        let expected_heights = block_numbers
            .iter()
            .map(|&n| {
                (
                    snapshot
                        .get_header_by_number(n)
                        .expect("block stored")
                        .hash()
                        .unpack(),
                    n,
                )
            })
            .collect::<HashMap<H256, BlockNumber>>();
        protocol.peers().update_blocks_proof_request(
            peer_index,
            Some(content),
            expected_heights,
            true,
        );
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let headers = bad_block_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .map(|n| {
                    snapshot
                        .get_header_by_number(n)
                        .expect("block stored")
                        .data()
                })
                .collect::<Vec<_>>();
            let last_number: BlockNumber = last_header.header().raw().number().unpack();
            let proof = chain.build_proof_by_numbers(last_number, &bad_block_numbers);
            let content = packed::SendBlocksProof::new_builder()
                .last_header(last_header)
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        assert!(nc.sent_messages().borrow().is_empty());

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::UnexpectedResponse));
        assert!(nc.sent_messages().borrow().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_blocks_with_chunks() {
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
    let chunk_size = 3;
    protocol.set_init_blocks_in_transit_per_peer(chunk_size);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let block_numbers = vec![3, 5, 8, 11, 13, 16, 18];

    // Setup the test fixture.
    {
        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = protocol
                .build_prove_request_content(&peer_state, &last_header)
                .await
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        let prove_state = {
            let last_n_blocks_start_number = if num > protocol.last_n_blocks() + 1 {
                num - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (last_n_blocks_start_number..num)
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers, &[]);
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
        protocol
            .commit_prove_state(peer_index, prove_state)
            .await
            .unwrap();
        let expected_heights = block_numbers
            .iter()
            .map(|&n| {
                (
                    snapshot
                        .get_header_by_number(n)
                        .expect("block stored")
                        .hash()
                        .unpack(),
                    n,
                )
            })
            .collect::<HashMap<H256, BlockNumber>>();
        protocol.peers().update_blocks_proof_request(
            peer_index,
            Some(content),
            expected_heights,
            true,
        );
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let headers = block_numbers
            .iter()
            .map(|n| *n as BlockNumber)
            .map(|n| snapshot.get_header_by_number(n).expect("block stored"))
            .collect::<Vec<_>>();
        let block_hashes = headers.iter().map(|h| h.hash()).collect::<Vec<_>>();
        let data = {
            let headers = headers.iter().map(|h| h.data()).collect::<Vec<_>>();
            let last_number: BlockNumber = last_header.header().raw().number().unpack();
            let proof = chain.build_proof_by_numbers(last_number, &block_numbers);
            let uncles_hashes = headers
                .iter()
                .map(|h| {
                    snapshot
                        .get_block_by_number(h.raw().number().unpack())
                        .expect("block stored")
                        .calc_uncles_hash()
                })
                .collect::<Vec<_>>();
            let extensions = headers
                .iter()
                .map(|h| {
                    packed::BytesOpt::new_builder()
                        .set(
                            snapshot
                                .get_block_by_number(h.raw().number().unpack())
                                .expect("block stored")
                                .extension(),
                        )
                        .build()
                })
                .collect::<Vec<_>>();
            let content = packed::SendBlocksProofV1::new_builder()
                .last_header(last_header)
                .proof(proof)
                .headers(headers.pack())
                .blocks_uncles_hash(uncles_hashes.pack())
                .blocks_extension(extensions)
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        assert!(nc.sent_messages().borrow().is_empty());

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let msg_count = if block_numbers.len() % chunk_size == 0 {
            0
        } else {
            1
        } + block_numbers.len() / chunk_size;
        assert_eq!(nc.sent_messages().borrow().len(), msg_count);

        let actual_block_hashes = nc
            .sent_messages()
            .borrow()
            .iter()
            .enumerate()
            .flat_map(|(idx, msg)| {
                let data = &msg.2;
                let message = packed::SyncMessageReader::new_unchecked(data);
                let hashes =
                    if let packed::SyncMessageUnionReader::GetBlocks(content) = message.to_enum() {
                        content.block_hashes().to_entity().into_iter()
                    } else {
                        panic!("unexpected message");
                    };
                if idx < msg_count - 1 {
                    assert_eq!(hashes.len(), chunk_size);
                } else {
                    assert_eq!(hashes.len(), block_numbers.len() % chunk_size);
                }
                hashes
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_block_hashes.as_slice(), block_hashes.as_slice());

        let peer = protocol.get_peer(&peer_index).expect("has peer");
        assert!(peer.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_without_any_proof_items() {
    let last_block_number = 20;
    let block_numbers = (0..last_block_number).collect::<Vec<_>>();
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_proof_since_all_blocks_are_missing() {
    let last_block_number = 20;
    let block_numbers = vec![];
    let missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        missing_block_hashes: missing_block_hashes.clone(),
        returned_missing_block_hashes: missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_proof_with_extension_block_is_rejected() {
    // Every block mined by the mock chain carries an extension, so a legacy
    // (v0) message which withholds the V1 fields must be rejected.
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        use_legacy_message: true,
        expected_status: Some(StatusCode::InvalidProof),
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_proof_with_incorrect_extension_is_rejected() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let returned_uncles_hashes = block_numbers
        .iter()
        .map(|_| packed::Byte32::zero())
        .collect::<Vec<_>>();
    // The headers commit to the real block extensions, but the message
    // carries different extension bytes, so the V1 extra-hash verification
    // must reject it.
    let incorrect_extension = packed::Bytes::new_builder().push(2u8).build();
    let returned_extensions = block_numbers
        .iter()
        .map(|_| {
            packed::BytesOpt::new_builder()
                .set(Some(incorrect_extension.clone()))
                .build()
        })
        .collect::<Vec<_>>();
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        returned_uncles_hashes: Some(returned_uncles_hashes),
        returned_extensions: Some(returned_extensions),
        expected_status: Some(StatusCode::InvalidProof),
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_v1_fields_when_all_blocks_are_missing() {
    let missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let param = TestParameter {
        last_block_number: 20,
        missing_block_hashes: missing_block_hashes.clone(),
        returned_missing_block_hashes: missing_block_hashes,
        returned_uncles_hashes: Some(vec![packed::Byte32::default()]),
        expected_status: Some(StatusCode::MalformedProtocolMessage),
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nonempty_proof_since_all_blocks_are_missing() {
    let last_block_number = 20;
    let block_numbers = vec![];
    let returned_headers = vec![9];
    let missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers,
        missing_block_hashes: missing_block_hashes.clone(),
        returned_missing_block_hashes: missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_missing_block_hashes() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        missing_block_hashes: missing_block_hashes.clone(),
        returned_missing_block_hashes: missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_insufficient_missing_block_hashes() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let returned_missing_block_hashes = vec![h256!("0x1").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        missing_block_hashes,
        returned_missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_redundant_missing_block_hashes() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let missing_block_hashes = vec![h256!("0x1").pack()];
    let returned_missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        missing_block_hashes,
        returned_missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_duplicate_missing_block_hashes() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let missing_block_hashes = vec![h256!("0x1").pack()];
    let returned_missing_block_hashes = vec![h256!("0x1").pack(), h256!("0x1").pack()];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers.clone(),
        returned_headers: block_numbers,
        missing_block_hashes,
        returned_missing_block_hashes,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_insufficient_proved_blocks() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let proved_block_numbers = vec![3, 5, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers,
        returned_headers: block_numbers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_redundant_proved_blocks() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let proved_block_numbers = vec![3, 5, 7, 8, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers,
        returned_headers: block_numbers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_insufficient_returned_headers() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let returned_headers = vec![3, 5, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers,
        returned_headers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_redundant_returned_headers() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let returned_headers = vec![3, 5, 7, 8, 11, 16, 18];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers,
        returned_headers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_with_duplicate_returned_headers() {
    let last_block_number = 20;
    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let returned_headers = vec![3, 5, 8, 11, 16, 18, 8];
    let param = TestParameter {
        last_block_number,
        block_numbers: block_numbers.clone(),
        proved_block_numbers: block_numbers,
        returned_headers,
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

#[derive(Default)]
struct TestParameter {
    last_block_number: BlockNumber,
    block_numbers: Vec<BlockNumber>,
    proved_block_numbers: Vec<BlockNumber>,
    returned_headers: Vec<BlockNumber>,
    missing_block_hashes: Vec<packed::Byte32>,
    returned_missing_block_hashes: Vec<packed::Byte32>,
    returned_uncles_hashes: Option<Vec<packed::Byte32>>,
    returned_extensions: Option<Vec<packed::BytesOpt>>,
    use_legacy_message: bool,
    expected_status: Option<StatusCode>,
    /// Heights to record as the ones `BlockFilters` matched each block at.
    ///
    /// Defaults to the blocks' real heights, which is the honest case. Setting a
    /// height different from where the block actually sits models a peer that sent
    /// correct filter data for one height and the provable hash of a block from
    /// another — the shape of the 0058 attack.
    matched_heights: Option<Vec<BlockNumber>>,
}

/// A peer sends correct filter data for heights 1000/1005/1008, but fills the
/// corresponding `block_hashes[]` entries with the hashes of blocks 3/5/8 — real,
/// provable blocks that sit at other heights.
///
/// The MMR proof for those blocks succeeds, because it only shows they are
/// somewhere in the chain; it says nothing about which height they occupy. Without
/// the height binding in `SendBlocksProofProcess` the client would download them,
/// index them as 1000/1005/1008, and advance the cursor past those heights — so the
/// real blocks there would never be scanned and any transaction touching a watched
/// script would be missed. This is the shape of sec-reports `PENDING-HIGH-0058`.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_proof_of_block_at_a_different_height_than_the_filters_matched() {
    let param = TestParameter {
        last_block_number: 20,
        block_numbers: vec![3, 5, 8],
        proved_block_numbers: vec![3, 5, 8],
        returned_headers: vec![3, 5, 8],
        // The filters claimed these blocks sit at heights with nothing to do with
        // where they actually are.
        matched_heights: Some(vec![1000, 1005, 1008]),
        expected_status: Some(StatusCode::InvalidProof),
        ..Default::default()
    };
    test_send_blocks_proof(param).await;
}

/// A block whose hash came from `BlockFilters` is reported missing by the proof
/// peer: the peer that supplied the hash is banned and the filter cursor is rolled
/// back to the height before it, so the height is re-filtered rather than skipped.
///
/// The existing `*_missing_block_hashes` tests build their request directly and
/// leave the in-memory `matched_blocks` map empty, so the handling finds nothing to
/// act on and only the `Remove` no-op path is reached. Seeding the map with a
/// `filter_source` is what exercises the `Retry` path.
///
/// This is a standalone test rather than a case of the shared harness because the
/// retry path sends its own `GetBlockFilters`, and the harness's `expected_status`
/// branch asserts that nothing was sent. The supplier is also deliberately a
/// different peer from the responder, which the harness cannot express either.
#[tokio::test(flavor = "multi_thread")]
async fn missing_block_rolls_the_filter_cursor_back_to_the_height_before_it() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let block_number: BlockNumber = 8;
    let missing_hash = h256!("0x1").pack();
    let filter_source_peer = PeerIndex::new(7);

    // Mine far enough that the probe below has a real header to anchor on.
    chain.mine_to(20);
    let snapshot = chain.shared().snapshot();

    let client_peer = PeerIndex::new(1);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(client_peer);
        peers.request_last_state(client_peer).unwrap();
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);

    let num = 20;
    {
        let peer_state = protocol
            .get_peer_state(&client_peer)
            .expect("has peer state");
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = protocol
                .build_prove_request_content(&peer_state, &last_header)
                .await
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        let prove_state = {
            let last_n_blocks_start_number = if num > protocol.last_n_blocks() + 1 {
                num - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (last_n_blocks_start_number..num)
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };

        // The block was admitted from a `BlockFilters` response, so we know which
        // peer supplied its hash.
        {
            let mut matched_blocks = protocol.peers().matched_blocks().write().await;
            matched_blocks.insert(
                missing_hash.unpack(),
                MatchedBlockState::new(block_number, false, Some(filter_source_peer)),
            );
        }

        let content =
            chain.build_blocks_proof_content(num, &[], std::slice::from_ref(&missing_hash));
        protocol
            .peers()
            .update_last_state(client_peer, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(client_peer, prove_request)
            .unwrap();
        protocol
            .commit_prove_state(client_peer, prove_state)
            .await
            .unwrap();
        protocol.peers().update_blocks_proof_request(
            client_peer,
            Some(content),
            HashMap::new(),
            true,
        );
    }

    {
        // The response must carry the same last state the request asked about,
        // otherwise it is rejected as an unexpected response before the
        // missing-block handling runs.
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let content = packed::SendBlocksProof::new_builder()
                .last_header(last_header)
                .missing_block_hashes(vec![missing_hash.clone()].pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), client_peer, data).await;
    }

    // The peer that supplied the hash is the one that gets banned, not the one that
    // reported it missing — `Status::process` bans the *responder*, which here is
    // `client_peer`.
    assert!(
        nc.banned_since(filter_source_peer, StatusCode::InvalidProof),
        "the peer that supplied the unprovable hash should have been banned"
    );

    assert_eq!(
        chain.client_storage().get_min_filtered_block_number(),
        block_number - 1,
        "the cursor should roll back to just below the height that was skipped"
    );
}
async fn test_send_blocks_proof(param: TestParameter) {
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

    let num = param.last_block_number;
    chain.mine_to(num);

    let snapshot = chain.shared().snapshot();

    // Setup the test fixture.
    {
        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = protocol
                .build_prove_request_content(&peer_state, &last_header)
                .await
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        let prove_state = {
            let last_n_blocks_start_number = if num > protocol.last_n_blocks() + 1 {
                num - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (last_n_blocks_start_number..num)
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(
            num,
            &param.block_numbers,
            &param.missing_block_hashes,
        );
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
        protocol
            .commit_prove_state(peer_index, prove_state)
            .await
            .unwrap();
        let claimed_heights = param
            .matched_heights
            .clone()
            .unwrap_or_else(|| param.block_numbers.clone());
        let expected_heights = param
            .block_numbers
            .iter()
            .zip(claimed_heights)
            .map(|(&real, claimed)| {
                (
                    snapshot
                        .get_header_by_number(real)
                        .expect("block stored")
                        .hash()
                        .unpack(),
                    claimed,
                )
            })
            .collect::<HashMap<H256, BlockNumber>>();
        protocol.peers().update_blocks_proof_request(
            peer_index,
            Some(content),
            expected_heights,
            true,
        );
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let headers = param
            .returned_headers
            .iter()
            .map(|n| snapshot.get_header_by_number(*n).expect("block stored"))
            .collect::<Vec<_>>();
        let block_hashes = headers.iter().map(|h| h.hash()).collect::<Vec<_>>().pack();
        let data = {
            let headers = headers.iter().map(|h| h.data()).collect::<Vec<_>>();
            let last_number: BlockNumber = last_header.header().raw().number().unpack();
            let proof = chain.build_proof_by_numbers(last_number, &param.proved_block_numbers);
            let all_block_numbers = (0..last_number).collect::<Vec<_>>();
            if param.proved_block_numbers == all_block_numbers {
                assert!(proof.is_empty());
            }
            let content = if param.use_legacy_message {
                // A legacy (v0) message which withholds the V1 fields. Only
                // valid for blocks committing to no uncles/extensions.
                let content = packed::SendBlocksProof::new_builder()
                    .last_header(last_header)
                    .proof(proof)
                    .headers(headers.pack())
                    .missing_block_hashes(param.returned_missing_block_hashes.clone().pack())
                    .build();
                packed::LightClientMessage::new_builder()
                    .set(content)
                    .build()
            } else if let Some(uncles_hashes) = &param.returned_uncles_hashes {
                // A V1 message with explicitly crafted uncles/extensions.
                let mut builder = packed::SendBlocksProofV1::new_builder()
                    .last_header(last_header)
                    .proof(proof)
                    .headers(headers.pack())
                    .missing_block_hashes(param.returned_missing_block_hashes.clone().pack())
                    .blocks_uncles_hash(uncles_hashes.to_owned().pack());
                if let Some(extensions) = &param.returned_extensions {
                    let extensions = packed::BytesOptVec::new_builder()
                        .set(extensions.clone())
                        .build();
                    builder = builder.blocks_extension(extensions);
                }
                let content = builder.build();
                packed::LightClientMessage::new_builder()
                    .set(content)
                    .build()
            } else {
                // A V1 message carrying the real uncles hashes and extensions
                // from the snapshot, like an honest server would send.
                let uncles_hashes = headers
                    .iter()
                    .map(|h| {
                        snapshot
                            .get_block_by_number(h.raw().number().unpack())
                            .expect("block stored")
                            .calc_uncles_hash()
                    })
                    .collect::<Vec<_>>();
                let extensions = headers
                    .iter()
                    .map(|h| {
                        packed::BytesOpt::new_builder()
                            .set(
                                snapshot
                                    .get_block_by_number(h.raw().number().unpack())
                                    .expect("block stored")
                                    .extension(),
                            )
                            .build()
                    })
                    .collect::<Vec<_>>();
                let content = packed::SendBlocksProofV1::new_builder()
                    .last_header(last_header)
                    .proof(proof)
                    .headers(headers.pack())
                    .missing_block_hashes(param.returned_missing_block_hashes.clone().pack())
                    .blocks_uncles_hash(uncles_hashes.pack())
                    .blocks_extension(extensions)
                    .build();
                packed::LightClientMessage::new_builder()
                    .set(content)
                    .build()
            };
            content
        }
        .as_bytes();

        assert!(nc.sent_messages().borrow().is_empty());

        protocol.received(nc.context(), peer_index, data).await;

        if let Some(expected_status) = param.expected_status {
            assert!(nc.banned_since(peer_index, expected_status));
            assert!(nc.sent_messages().borrow().is_empty());
        } else if param.block_numbers == param.proved_block_numbers
            && param.block_numbers == param.returned_headers
            && param.missing_block_hashes == param.returned_missing_block_hashes
        {
            assert!(nc.not_banned(peer_index));

            if param.block_numbers.is_empty() {
                assert!(nc.sent_messages().borrow().is_empty());
            } else {
                assert_eq!(nc.sent_messages().borrow().len(), 1);

                let data = &nc.sent_messages().borrow()[0].2;
                let message = packed::SyncMessageReader::new_unchecked(data);
                let content =
                    if let packed::SyncMessageUnionReader::GetBlocks(content) = message.to_enum() {
                        content
                    } else {
                        panic!("unexpected message");
                    };
                assert_eq!(content.block_hashes().as_slice(), block_hashes.as_slice());
            }

            let peer = protocol.get_peer(&peer_index).expect("has peer");
            assert!(peer.get_blocks_proof_request().is_none());
        } else {
            if param.missing_block_hashes != param.returned_missing_block_hashes
                || param.block_numbers != param.returned_headers
            {
                assert!(nc.banned_since(peer_index, StatusCode::UnexpectedResponse));
            } else if param.block_numbers != param.proved_block_numbers {
                assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
            } else {
                panic!("unhandled failed tests");
            }

            assert!(nc.sent_messages().borrow().is_empty());
        }
    }
}
