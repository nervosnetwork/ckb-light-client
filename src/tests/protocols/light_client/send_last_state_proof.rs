use std::{cmp, sync::Arc};

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core::BlockNumber, packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256,
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
        let content = packed::SendLastStateProof::new_builder().build();
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
        let content = packed::SendLastStateProof::new_builder().build();
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
    assert!(peer_state.get_prove_state().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn update_last_state() {
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
    chain.mine_to(12 + 2);

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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    num += 2;

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let last_hash = last_header.header().calc_header_hash();
        let data = {
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header)
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
        let message = packed::LightClientMessageReader::new_unchecked(&data);
        let content = if let packed::LightClientMessageUnionReader::GetLastStateProof(content) =
            message.to_enum()
        {
            content
        } else {
            panic!("unexpected message");
        };
        assert_eq!(content.last_hash().as_slice(), last_hash.as_slice());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_proof() {
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
    chain.mine_to(12 + 2);

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
                .expect("build prove request content");
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    num += 2;

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let item = packed::HeaderDigest::default();
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header)
                .proof(vec![item].pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        assert!(nc.sent_messages().borrow().is_empty());

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));
        assert!(nc.sent_messages().borrow().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_should_be_sorted() {
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

    // Setup the test fixture.
    {
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = {
                let genesis_block = chain.consensus().genesis_block();
                packed::GetLastStateProof::new_builder()
                    .last_hash(last_header.header().hash())
                    .start_hash(genesis_block.hash())
                    .start_number(genesis_block.number().pack())
                    .last_n_blocks(protocol.last_n_blocks().pack())
                    .difficulty_boundary(U256::zero().pack())
                    .build()
            };
            let last_state = LastState::new(last_header);
            protocol
                .peers()
                .update_last_state(peer_index, last_state.clone());
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let item = packed::HeaderDigest::default();
            let headers = (1..num)
                .into_iter()
                .map(|mut n| {
                    if n == 1 {
                        n = num / 2;
                    } else if n == num / 2 {
                        n = 1;
                    }
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header)
                .proof(vec![item].pack())
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::MalformedProtocolMessage));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_boundary_not_in_last_n() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() - 2;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let prove_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state")
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        assert!(prove_state.is_same_as(&last_header));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_boundary_in_last_n() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let prove_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state")
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        assert!(prove_state.is_same_as(&last_header));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_prove_state() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 30;
    chain.mine_to(30);

    let snapshot = chain.shared().snapshot();

    let prev_last_number = 15;
    let prev_sampled_numbers = vec![3, 4, 7, 10];
    let sampled_numbers = vec![17, 20, 22, 25, 28];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let prev_boundary_number = prev_last_number - protocol.last_n_blocks() + 1;
        let prev_prove_request = chain.build_prove_request(
            0,
            prev_last_number,
            &prev_sampled_numbers,
            prev_boundary_number,
            protocol.last_n_blocks(),
        );
        let prove_state = {
            let prev_last_n_blocks_start_number = if prev_last_number > protocol.last_n_blocks() + 1
            {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (prev_last_n_blocks_start_number..prev_last_number)
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prev_prove_request, Vec::new(), last_n_headers)
        };
        protocol.commit_prove_state(peer_index, prove_state);
        let mut prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let prove_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state")
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        assert!(prove_state.is_same_as(&last_header));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_reorg_blocks() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 30;
    chain.mine_to(30);

    let snapshot = chain.shared().snapshot();

    let prev_last_number = 15;
    let prev_sampled_numbers = vec![3, 4, 7, 10];
    let sampled_numbers = vec![17, 20, 22, 25, 28];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let prev_boundary_number = prev_last_number - protocol.last_n_blocks() + 1;
        let prev_prove_request = chain.build_prove_request(
            0,
            prev_last_number,
            &prev_sampled_numbers,
            prev_boundary_number,
            protocol.last_n_blocks(),
        );
        let prove_state = {
            let prev_last_n_blocks_start_number = if prev_last_number > protocol.last_n_blocks() + 1
            {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (prev_last_n_blocks_start_number..prev_last_number)
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prev_prove_request, Vec::new(), last_n_headers)
        };
        protocol.commit_prove_state(peer_index, prove_state);
        let mut prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let reorg_start_number = if prev_last_number > protocol.last_n_blocks() + 1 {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = (reorg_start_number..prev_last_number)
                .chain(
                    sampled_numbers
                        .iter()
                        .map(|n| *n as BlockNumber)
                        .filter(|n| *n < first_last_n_number),
                )
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.not_banned(peer_index));

        let prove_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state")
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        assert!(prove_state.is_same_as(&last_header));
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
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .skip(1)
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_not_enough() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 30;
    chain.mine_to(30);

    let snapshot = chain.shared().snapshot();

    let prev_last_number = 15;
    let prev_sampled_numbers = vec![3, 4, 7, 10];
    let sampled_numbers = vec![17, 20, 22, 25, 28];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let prev_boundary_number = prev_last_number - protocol.last_n_blocks() + 1;
        let prev_prove_request = chain.build_prove_request(
            0,
            prev_last_number,
            &prev_sampled_numbers,
            prev_boundary_number,
            protocol.last_n_blocks(),
        );
        let prove_state = {
            let prev_last_n_blocks_start_number = if prev_last_number > protocol.last_n_blocks() + 1
            {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (prev_last_n_blocks_start_number..prev_last_number)
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prev_prove_request, Vec::new(), last_n_headers)
        };
        protocol.commit_prove_state(peer_index, prove_state);
        let mut prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let reorg_start_number = if prev_last_number > protocol.last_n_blocks() + 1 {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = (reorg_start_number..prev_last_number)
                .skip(1)
                .chain(
                    sampled_numbers
                        .iter()
                        .map(|n| *n as BlockNumber)
                        .filter(|n| *n < first_last_n_number),
                )
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidReorgHeaders));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_not_continuous_with_start() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 30;
    chain.mine_to(30);

    let snapshot = chain.shared().snapshot();

    let prev_last_number = 15;
    let prev_sampled_numbers = vec![3, 4, 7, 10];
    let sampled_numbers = vec![17, 20, 22, 25, 28];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let prev_boundary_number = prev_last_number - protocol.last_n_blocks() + 1;
        let prev_prove_request = chain.build_prove_request(
            0,
            prev_last_number,
            &prev_sampled_numbers,
            prev_boundary_number,
            protocol.last_n_blocks(),
        );
        let prove_state = {
            let prev_last_n_blocks_start_number = if prev_last_number > protocol.last_n_blocks() + 1
            {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let last_n_headers = (prev_last_n_blocks_start_number..prev_last_number)
                .into_iter()
                .map(|num| snapshot.get_header_by_number(num).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prev_prove_request, Vec::new(), last_n_headers)
        };
        protocol.commit_prove_state(peer_index, prove_state);
        let mut prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let reorg_start_number = if prev_last_number > protocol.last_n_blocks() + 1 {
                prev_last_number - protocol.last_n_blocks()
            } else {
                1
            };
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = (reorg_start_number..prev_last_number)
                .map(|n| n - 1)
                .chain(
                    sampled_numbers
                        .iter()
                        .map(|n| *n as BlockNumber)
                        .filter(|n| *n < first_last_n_number),
                )
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidReorgHeaders));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_incorrect() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let bad_sampled_numbers = vec![3, 5, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() - 2;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = bad_sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidSamples));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_redundant() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let bad_sampled_numbers = vec![3, 5, 7, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() - 2;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = bad_sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidSamples));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_not_enough_1() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let bad_sampled_numbers = vec![3, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() + 1;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = bad_sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain((first_last_n_number..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidSamples));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_not_enough_2() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 12, 13, 14, 15, 16, 17, 18];
    let boundary_number = num - protocol.last_n_blocks() - 2;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks()) - 1;
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain(((first_last_n_number + 1)..num).into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidSamples));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn last_n_headers_should_be_continuous() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 18];
    let boundary_number = num - protocol.last_n_blocks() - 2;

    // Setup the test fixture.
    {
        let mut prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        prove_request.skip_check_tau();
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol.peers().update_last_state(peer_index, last_state);
        protocol
            .peers()
            .update_prove_request(peer_index, Some(prove_request));
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());
            let headers = sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain(
                    (first_last_n_number..num)
                        .into_iter()
                        .filter(|n| *n != first_last_n_number + 1),
                )
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = headers
                    .iter()
                    .map(|header| header.header().raw().number().unpack())
                    .collect::<Vec<BlockNumber>>();
                chain.build_proof_by_numbers(last_number, &numbers)
            };
            let content = packed::SendLastStateProof::new_builder()
                .last_header(last_header.clone())
                .proof(proof)
                .headers(headers.pack())
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        }
        .as_bytes();

        protocol.received(nc.context(), peer_index, data).await;

        assert!(nc.banned_since(peer_index, StatusCode::InvalidParentHash));
    }
}
