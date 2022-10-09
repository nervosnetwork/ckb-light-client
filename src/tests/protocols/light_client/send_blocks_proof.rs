use std::sync::Arc;

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core::BlockNumber, packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader,
};

use crate::{
    protocols::{LastState, Peers, ProveRequest, ProveState, StatusCode},
    tests::{
        prelude::*,
        utils::{MockChain, MockNetworkContext},
    },
};

#[tokio::test]
async fn peer_state_is_not_found() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peers = Arc::new(Peers::default());
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

    assert!(nc.banned_since(peer_index, StatusCode::PeerStateIsNotFound));
}

#[tokio::test]
async fn no_matched_request() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
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
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
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

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unexpected_response() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
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
async fn valid_proof() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let block_numbers = vec![3, 5, 8, 11, 16, 18];

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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
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
        let block_hashes = headers.iter().map(|h| h.hash()).collect::<Vec<_>>().pack();
        let data = {
            let headers = headers.iter().map(|h| h.data()).collect::<Vec<_>>();
            let last_number: BlockNumber = last_header.header().raw().number().unpack();
            let proof = chain.build_proof_by_numbers(last_number, &block_numbers);
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

        assert!(nc.not_banned(peer_index));
        assert_eq!(nc.sent_messages().borrow().len(), 1);

        let data = &nc.sent_messages().borrow()[0].2;
        let message = packed::SyncMessageReader::new_unchecked(&data);
        let content = if let packed::SyncMessageUnionReader::GetBlocks(content) = message.to_enum()
        {
            content
        } else {
            panic!("unexpected message");
        };
        assert_eq!(content.block_hashes().as_slice(), block_hashes.as_slice());

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_empty_proof() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let block_numbers = (0..num).into_iter().collect::<Vec<_>>();

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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
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
        let block_hashes = headers.iter().map(|h| h.hash()).collect::<Vec<_>>().pack();
        let data = {
            let headers = headers.iter().map(|h| h.data()).collect::<Vec<_>>();
            let last_number: BlockNumber = last_header.header().raw().number().unpack();
            let proof = chain.build_proof_by_numbers(last_number, &block_numbers);
            assert!(proof.is_empty());
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

        assert!(nc.not_banned(peer_index));
        assert_eq!(nc.sent_messages().borrow().len(), 1);

        let data = &nc.sent_messages().borrow()[0].2;
        let message = packed::SyncMessageReader::new_unchecked(&data);
        let content = if let packed::SyncMessageUnionReader::GetBlocks(content) = message.to_enum()
        {
            content
        } else {
            panic!("unexpected message");
        };
        assert_eq!(content.block_hashes().as_slice(), block_hashes.as_slice());

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_blocks_with_chunks() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
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
            .map(|(idx, msg)| {
                let data = &msg.2;
                let message = packed::SyncMessageReader::new_unchecked(&data);
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
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(actual_block_hashes.as_slice(), block_hashes.as_slice());

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");
        assert!(peer_state.get_blocks_proof_request().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let block_numbers = vec![3, 5, 8, 11, 16, 18];
    let proved_block_numbers = vec![3, 5, 7, 11, 16, 18];

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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
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
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prove_request.clone(), Vec::new(), last_n_headers)
        };
        let content = chain.build_blocks_proof_content(num, &block_numbers);
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
        protocol.commit_prove_state(peer_index, prove_state);
        protocol
            .peers()
            .update_blocks_proof_request(peer_index, Some(content));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let headers = block_numbers
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
            let proof = chain.build_proof_by_numbers(last_number, &proved_block_numbers);
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

        assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
        assert!(nc.sent_messages().borrow().is_empty());
    }
}
