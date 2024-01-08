use std::{cmp, sync::Arc};

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core::BlockNumber, packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader,
    H256, U256,
};
use log::debug;

use crate::{
    protocols::{light_client::prelude::*, LastState, ProveRequest, ProveState, StatusCode},
    tests::{
        prelude::*,
        utils::{setup, MockChain, MockNetworkContext},
    },
};

fn sampling_between(start_number: BlockNumber, boundary_number: BlockNumber) -> Vec<BlockNumber> {
    let mut sampled_numbers = Vec::new();
    let mut diff = 1;
    let mut sampled_number = boundary_number;
    while sampled_number >= start_number + diff {
        sampled_number -= diff;
        sampled_numbers.push(sampled_number);
        diff += 1;
    }
    let sampled_numbers = sampled_numbers.into_iter().rev().collect::<Vec<_>>();
    assert!(!sampled_numbers.is_empty());
    sampled_numbers
}

#[tokio::test]
async fn peer_state_is_not_found() {
    let chain = MockChain::new_with_dummy_pow("test-light-client");
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peers = chain.create_peers();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
                .update_last_state(peer_index, last_state.clone())
                .unwrap();
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
                .update_last_state(peer_index, last_state.clone())
                .unwrap();
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
                .update_last_state(peer_index, last_state.clone())
                .unwrap();
            ProveRequest::new(last_state, content)
        };
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
        let prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
        let prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
async fn valid_proof_with_no_matched_sample() {
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
    protocol.set_last_n_blocks(3);

    let num = 20;
    chain.mine_to(20);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11];
    let boundary_number = num - protocol.last_n_blocks() + 1;
    let first_last_n_number = cmp::min(boundary_number, num - protocol.last_n_blocks());

    // Setup the test fixture.
    {
        let prove_request = {
            let last_header: VerifiableHeader = snapshot
                .get_verifiable_header_by_number(num)
                .expect("block stored")
                .into();
            let content = {
                let start_header = snapshot.get_header_by_number(0).expect("block stored");
                let difficulties = {
                    let u256_one = &U256::from(1u64);
                    let total_diffs = (0..num)
                        .into_iter()
                        .map(|num| snapshot.get_total_difficulty_by_number(num).unwrap())
                        .collect::<Vec<_>>();
                    let mut difficulties = Vec::new();
                    for n in &sampled_numbers {
                        let n = *n as usize;
                        difficulties.push(&total_diffs[n - 1] + u256_one);
                        difficulties.push(&total_diffs[n] - u256_one);
                        difficulties.push(total_diffs[n].to_owned());
                    }
                    let last_not_sampled_number = first_last_n_number as usize - 1;
                    difficulties.push(&total_diffs[last_not_sampled_number] + u256_one);
                    difficulties.sort();
                    difficulties.dedup();
                    difficulties.into_iter().map(|diff| diff.pack())
                };
                let difficulty_boundary = snapshot
                    .get_total_difficulty_by_number(boundary_number)
                    .unwrap();
                packed::GetLastStateProof::new_builder()
                    .last_hash(last_header.header().hash())
                    .start_hash(start_header.hash())
                    .start_number(start_header.number().pack())
                    .last_n_blocks(protocol.last_n_blocks().pack())
                    .difficulty_boundary(difficulty_boundary.pack())
                    .difficulties(difficulties.pack())
                    .build()
            };
            let last_state = LastState::new(last_header);
            ProveRequest::new(last_state, content)
        };
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
        let prev_last_state = LastState::new(prev_prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, prev_last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prev_prove_request.clone())
            .unwrap();
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
        protocol
            .commit_prove_state(peer_index, prove_state)
            .unwrap();
        let prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
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
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
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
        let prev_last_state = LastState::new(prev_prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, prev_last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prev_prove_request.clone())
            .unwrap();
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
        protocol
            .commit_prove_state(peer_index, prove_state)
            .unwrap();
        let prove_request = chain.build_prove_request(
            prev_last_number,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        protocol
            .peers()
            .mock_prove_request(peer_index, prove_request)
            .unwrap();
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
        assert!(!prove_state.get_reorg_last_headers().is_empty());
        assert!(prove_state.is_same_as(&last_header));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_proof_with_the_genesis_block() {
    test_parent_chain_root_for_the_genesis_block(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_parent_chain_root_for_the_genesis_block() {
    test_parent_chain_root_for_the_genesis_block(false).await;
}

async fn test_parent_chain_root_for_the_genesis_block(should_passed: bool) {
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
    protocol.set_mmr_activated_epoch(0);
    protocol.set_last_n_blocks(3);

    let num = 10;
    chain.mine_to(num + 1);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![];
    let boundary_number = 0;

    // Setup the test fixture.
    {
        let prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let headers = (0..num)
                .into_iter()
                .map(|n| {
                    if !should_passed && n == num / 2 {
                        // Set a wrong parent chain root:
                        // - Use n's chain root as n's parent chain root
                        let parent_chain_root = snapshot
                            .chain_root_mmr(n)
                            .get_root()
                            .expect("has chain root");
                        snapshot
                            .get_verifiable_header_by_number(n)
                            .expect("block stored")
                            .as_builder()
                            .parent_chain_root(parent_chain_root)
                            .build()
                    } else {
                        snapshot
                            .get_verifiable_header_by_number(n)
                            .expect("block stored")
                    }
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

        if should_passed {
            assert!(nc.not_banned(peer_index));

            let prove_state = protocol
                .get_peer_state(&peer_index)
                .expect("has peer state")
                .get_prove_state()
                .expect("has prove state")
                .to_owned();
            let last_header: VerifiableHeader = last_header.into();
            assert!(prove_state.is_same_as(&last_header));
        } else {
            assert!(nc.banned_since(peer_index, StatusCode::InvalidChainRoot));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_parent_chain_root_for_non_genesis_blocks() {
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
    protocol.set_mmr_activated_epoch(0);
    protocol.set_last_n_blocks(3);

    let num = 2;
    chain.mine_to(num);

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![1];
    let boundary_number = 0;

    // Setup the test fixture.
    {
        let prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(num)
            .expect("block stored");
        let data = {
            let headers = (0..num)
                .into_iter()
                .map(|n| {
                    if n == 1 {
                        snapshot
                            .get_verifiable_header_by_number(n)
                            .expect("block stored")
                            .as_builder()
                            .parent_chain_root(Default::default())
                            .build()
                    } else {
                        snapshot
                            .get_verifiable_header_by_number(n)
                            .expect("block stored")
                    }
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

        assert!(nc.banned_since(peer_index, StatusCode::InvalidChainRoot));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks + 1;
    let sampled_numbers = vec![3, 7, 11];
    let update_proof_numbers_func = |mut numbers: Vec<BlockNumber>| {
        numbers.remove(0);
        numbers
    };
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        sampled_numbers_opt: Some(sampled_numbers),
        update_proof_numbers_func_opt: Some(Box::new(update_proof_numbers_func)),
        result: StatusCode::InvalidProof,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_headers() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        returned_sampled_numbers_opt: Some(Default::default()),
        returned_last_n_numbers_opt: Some(Default::default()),
        result: StatusCode::MalformedProtocolMessage,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_incorrect() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let sampled_numbers = vec![3, 7, 11];
    let returned_sampled_numbers = vec![3, 5, 11];
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        sampled_numbers_opt: Some(sampled_numbers),
        returned_sampled_numbers_opt: Some(returned_sampled_numbers),
        result: StatusCode::InvalidSamples,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_redundant() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let sampled_numbers = vec![3, 7, 11];
    let returned_sampled_numbers = vec![3, 5, 7, 11];
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        sampled_numbers_opt: Some(sampled_numbers),
        returned_sampled_numbers_opt: Some(returned_sampled_numbers),
        result: StatusCode::InvalidSamples,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_not_enough_case_1() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks + 1;
    let sampled_numbers = vec![3, 7, 11];
    let returned_sampled_numbers = vec![3, 11];
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        sampled_numbers_opt: Some(sampled_numbers),
        returned_sampled_numbers_opt: Some(returned_sampled_numbers),
        result: StatusCode::InvalidSamples,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn samples_are_not_enough_case_2() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let sampled_numbers = vec![3, 7, 11, 12, 13, 14];
    let returned_sampled_numbers = vec![3, 7, 11, 12, 13];
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        sampled_numbers_opt: Some(sampled_numbers),
        returned_sampled_numbers_opt: Some(returned_sampled_numbers),
        result: StatusCode::InvalidSamples,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn last_n_headers_is_not_continuous() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let returned_last_n_numbers = (boundary_number..last_number)
        .into_iter()
        .filter(|n| *n != boundary_number + 1)
        .collect();
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        returned_last_n_numbers_opt: Some(returned_last_n_numbers),
        result: StatusCode::InvalidParentBlock,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn last_n_headers_is_not_continuous_in_middle_when_no_samples() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let returned_last_n_numbers = (boundary_number..last_number)
        .into_iter()
        .filter(|n| *n != boundary_number + 1)
        .collect();
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        returned_last_n_numbers_opt: Some(returned_last_n_numbers),
        result: StatusCode::InvalidParentBlock,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn last_n_headers_is_not_continuous_with_start_when_no_samples() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let returned_last_n_numbers = ((boundary_number + 1)..last_number).into_iter().collect();
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        returned_sampled_numbers_opt: Some(Default::default()),
        returned_last_n_numbers_opt: Some(returned_last_n_numbers),
        result: StatusCode::MalformedProtocolMessage,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn last_n_headers_is_not_continuous_with_last_when_no_samples() {
    let last_number = 20;
    let last_n_blocks = 3;
    let boundary_number = last_number - last_n_blocks - 2;
    let returned_last_n_numbers = (boundary_number..(last_number - 1)).into_iter().collect();
    let param = TestParameter {
        last_number,
        boundary_number,
        last_n_blocks,
        returned_sampled_numbers_opt: Some(Default::default()),
        returned_last_n_numbers_opt: Some(returned_last_n_numbers),
        result: StatusCode::MalformedProtocolMessage,
        ..Default::default()
    };
    test_send_last_state_proof(param).await;
}

#[derive(Default)]
struct TestParameter {
    last_number: BlockNumber,
    boundary_number: BlockNumber,
    last_n_blocks: BlockNumber,
    sampled_numbers_opt: Option<Vec<BlockNumber>>,
    returned_sampled_numbers_opt: Option<Vec<BlockNumber>>,
    returned_last_n_numbers_opt: Option<Vec<BlockNumber>>,
    expected_last_headers_count_opt: Option<BlockNumber>,
    update_proof_numbers_func_opt: Option<Box<dyn Fn(Vec<BlockNumber>) -> Vec<BlockNumber>>>,
    result: StatusCode,
}

async fn test_send_last_state_proof(param: TestParameter) {
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

    let last_n_blocks = param.last_n_blocks;
    protocol.set_last_n_blocks(last_n_blocks);

    let last_number = param.last_number;
    chain.mine_to(last_number);

    let boundary_number = param.boundary_number;
    let sampled_numbers = param
        .sampled_numbers_opt
        .unwrap_or_else(|| sampling_between(1, boundary_number));
    let returned_sampled_numbers = param
        .returned_sampled_numbers_opt
        .unwrap_or_else(|| sampled_numbers.clone());

    let snapshot = chain.shared().snapshot();

    // Setup the test fixture.
    {
        let prove_request = chain.build_prove_request(
            0,
            last_number,
            &sampled_numbers,
            boundary_number,
            last_n_blocks,
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
    }

    // Run the test.
    {
        let last_header = snapshot
            .get_verifiable_header_by_number(last_number)
            .expect("block stored");
        let data = {
            let first_last_n_number = cmp::min(boundary_number, last_number - last_n_blocks);
            let returned_last_n_numbers = param
                .returned_last_n_numbers_opt
                .unwrap_or_else(|| (first_last_n_number..last_number).collect());
            let headers = returned_sampled_numbers
                .iter()
                .map(|n| *n as BlockNumber)
                .filter(|n| *n < first_last_n_number)
                .chain(returned_last_n_numbers.into_iter())
                .map(|n| {
                    snapshot
                        .get_verifiable_header_by_number(n)
                        .expect("block stored")
                })
                .collect::<Vec<_>>();
            let proof = {
                let last_number: BlockNumber = last_header.header().raw().number().unpack();
                let numbers = {
                    let numbers = headers
                        .iter()
                        .map(|header| header.header().raw().number().unpack())
                        .collect::<Vec<BlockNumber>>();
                    if let Some(func) = param.update_proof_numbers_func_opt {
                        func(numbers)
                    } else {
                        numbers
                    }
                };
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

        if param.result != StatusCode::OK {
            assert!(nc.banned_since(peer_index, param.result));
            return;
        }

        assert!(nc.not_banned(peer_index));

        let prove_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state")
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        assert!(prove_state.is_same_as(&last_header));
        let expected_last_headers_count = param
            .expected_last_headers_count_opt
            .unwrap_or(last_n_blocks) as usize;
        assert_eq!(
            prove_state.get_last_headers().len(),
            expected_last_headers_count
        );
        for pair in prove_state.get_last_headers().windows(2) {
            assert!(pair[0].is_parent_of(&pair[1]));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_1() {
    let param = ReorgTestParameter {
        last_number: 30,
        prev_last_number_opt: Some(5),
        rollback_blocks_count: 3,
        last_n_blocks: 10,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_2() {
    let param = ReorgTestParameter {
        last_number: 8,
        prev_last_number_opt: Some(5),
        rollback_blocks_count: 0,
        last_n_blocks: 10,
        expected_last_headers_count_opt: Some(7),
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_3() {
    let param = ReorgTestParameter {
        last_number: 8,
        prev_last_number_opt: Some(5),
        rollback_blocks_count: 3,
        last_n_blocks: 10,
        expected_last_headers_count_opt: Some(7),
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_4() {
    let param = ReorgTestParameter {
        last_number: 12,
        prev_last_number_opt: Some(8),
        rollback_blocks_count: 3,
        last_n_blocks: 10,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_5() {
    let param = ReorgTestParameter {
        last_number: 5,
        prev_last_number_opt: Some(1),
        rollback_blocks_count: 1,
        last_n_blocks: 10,
        expected_last_headers_count_opt: Some(4),
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_less_than_last_n_blocks_case_6() {
    let param = ReorgTestParameter {
        last_number: 2,
        prev_last_number_opt: Some(2),
        rollback_blocks_count: 0,
        last_n_blocks: 10,
        expected_last_headers_count_opt: Some(1),
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_not_continuous() {
    let reorg_blocks = vec![10, 11, 13, 14];
    let param = ReorgTestParameter {
        last_number: 30,
        prev_last_number_opt: Some(15),
        reorg_blocks_opt: Some(reorg_blocks),
        rollback_blocks_count: 3,
        last_n_blocks: 5,
        result: StatusCode::InvalidReorgHeaders,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_not_continuous_with_start() {
    let reorg_blocks = vec![11, 12, 13, 14, 15];
    let param = ReorgTestParameter {
        last_number: 30,
        prev_last_number_opt: Some(15),
        reorg_blocks_opt: Some(reorg_blocks),
        rollback_blocks_count: 3,
        last_n_blocks: 5,
        result: StatusCode::InvalidReorgHeaders,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_blocks_is_not_continuous_with_last() {
    let reorg_blocks = vec![9, 10, 11, 12, 13];
    let param = ReorgTestParameter {
        last_number: 30,
        prev_last_number_opt: Some(15),
        reorg_blocks_opt: Some(reorg_blocks),
        rollback_blocks_count: 3,
        last_n_blocks: 5,
        result: StatusCode::InvalidReorgHeaders,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

// No fork but reorg headers are sent.
//
// Since the light client only has a hash of the start header,
// the light client couldn't distinguish whether the reorg is required,
// so the light client just accept these reorg headers.
#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_0_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 0,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

// Only the last header is changed.
#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_1_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 1,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_2_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 2,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_3_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 3,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_4_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 4,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_5_blocks() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 5,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_rollback_after_restart_and_last_n_blocks_is_not_enough() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 3,
        last_n_blocks: 20,
        restart: true,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_detect_long_fork_turn_1() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 6,
        last_n_blocks: 5,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "long fork detected")]
async fn reorg_detect_long_fork_turn_2() {
    let param = ReorgTestParameter {
        last_number: 30,
        rollback_blocks_count: 6,
        last_n_blocks: 5,
        long_fork_detected: true,
        ..Default::default()
    };
    test_with_reorg_blocks(param).await;
}

#[derive(Default)]
struct ReorgTestParameter {
    last_number: BlockNumber,
    prev_last_number_opt: Option<BlockNumber>,
    earliest_matched_number_opt: Option<BlockNumber>,
    reorg_blocks_opt: Option<Vec<BlockNumber>>,
    rollback_blocks_count: BlockNumber,
    last_n_blocks: BlockNumber,
    long_fork_detected: bool,
    expected_last_headers_count_opt: Option<BlockNumber>,
    result: StatusCode,
    // Mock "restart" state: after restart, the first received "last state" is on a forked chain.
    restart: bool,
}

async fn test_with_reorg_blocks(param: ReorgTestParameter) {
    setup();

    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index = PeerIndex::new(1);
    let downloading_matched_block = H256(rand::random());
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index);
        peers.request_last_state(peer_index).unwrap();
        peers
            .matched_blocks()
            .write()
            .unwrap()
            .insert(downloading_matched_block.clone(), (false, None));
        peers
    };
    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));

    let last_n_blocks = param.last_n_blocks;
    protocol.set_last_n_blocks(last_n_blocks);

    let storage = chain.client_storage();

    let last_number = param.last_number;
    {
        chain.mine_to_with(last_number, |block| {
            let block_number: u64 = block.header().raw().number().unpack();
            block
                .as_advanced_builder()
                .timestamp((100 + block_number).pack())
                .build()
        });
        assert_eq!(chain.shared().snapshot().tip_number(), last_number);
    }

    let prev_last_number = param.prev_last_number_opt.unwrap_or(last_number / 2);
    assert!(prev_last_number >= 1);
    let boundary_number = if last_number > last_n_blocks + 1 {
        let boundary_number = last_number - last_n_blocks + 1;
        if boundary_number > prev_last_number {
            boundary_number
        } else {
            prev_last_number
        }
    } else {
        1
    };
    let sampled_numbers = if boundary_number == 1 || prev_last_number >= boundary_number {
        Default::default()
    } else {
        sampling_between(prev_last_number, boundary_number)
    };
    let rollback_blocks_count = param.rollback_blocks_count;
    let earliest_matched_number = param.earliest_matched_number_opt.unwrap_or_else(|| {
        if prev_last_number > rollback_blocks_count + 1 {
            prev_last_number - rollback_blocks_count
        } else {
            1
        }
    });
    assert!(prev_last_number >= earliest_matched_number);

    // Setup the client data.
    {
        let snapshot = chain.shared().snapshot();
        let prev_boundary_number = if prev_last_number > last_n_blocks + 1 {
            prev_last_number - last_n_blocks + 1
        } else {
            1
        };
        let prev_sampled_numbers = if prev_boundary_number == 1 {
            Default::default()
        } else {
            sampling_between(1, prev_boundary_number)
        };
        let prev_prove_request = chain.build_prove_request(
            0,
            prev_last_number,
            &prev_sampled_numbers,
            prev_boundary_number,
            last_n_blocks,
        );
        let prev_last_state = LastState::new(prev_prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, prev_last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prev_prove_request.clone())
            .unwrap();
        let prove_state = {
            let prev_last_n_blocks_start_number = if prev_last_number > last_n_blocks + 1 {
                prev_last_number - last_n_blocks
            } else {
                1
            };
            let last_n_headers = (prev_last_n_blocks_start_number..prev_last_number)
                .into_iter()
                .map(|n| snapshot.get_header_by_number(n).expect("block stored"))
                .collect::<Vec<_>>();
            ProveState::new_from_request(prev_prove_request, Vec::new(), last_n_headers)
        };
        protocol
            .commit_prove_state(peer_index, prove_state)
            .unwrap();
    }

    // Setup the storage data.
    {
        storage.update_min_filtered_block_number(prev_last_number);
        for matched_start_number in earliest_matched_number..=prev_last_number {
            debug!("storage add match block {}", matched_start_number);
            storage.add_matched_blocks(
                matched_start_number,
                4,
                vec![(downloading_matched_block.pack(), false)],
            );
        }

        assert_eq!(storage.get_min_filtered_block_number(), prev_last_number);
        assert_eq!(
            storage.get_earliest_matched_blocks().unwrap().0,
            earliest_matched_number
        );
        assert_eq!(
            storage.get_latest_matched_blocks().unwrap().0,
            prev_last_number
        );
    }

    // Create a fork chain.
    if rollback_blocks_count > 0 {
        let rollback_to = prev_last_number - rollback_blocks_count;
        chain.rollback_to(rollback_to, Default::default());
        assert_eq!(chain.shared().snapshot().tip_number(), rollback_to);

        chain.mine_to_with(last_number, |block| {
            let block_number: u64 = block.header().raw().number().unpack();
            block
                .as_advanced_builder()
                .timestamp((500 + block_number).pack())
                .build()
        });
        assert_eq!(chain.shared().snapshot().tip_number(), last_number);
    }

    if param.restart {
        protocol.peers().mock_initialized(peer_index);
        protocol.peers().request_last_state(peer_index).unwrap();
    }

    // Run the test.
    {
        let mut prove_request = chain.build_prove_request(
            prev_last_number,
            last_number,
            &sampled_numbers,
            boundary_number,
            last_n_blocks,
        );
        if param.long_fork_detected {
            prove_request.long_fork_detected();
        }
        let last_state = LastState::new(prove_request.get_last_header().to_owned());
        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();

        let snapshot = chain.shared().snapshot();
        let last_header = snapshot
            .get_verifiable_header_by_number(last_number)
            .expect("block stored");
        let data = {
            let reorg_blocks = if param.long_fork_detected {
                Default::default()
            } else {
                param.reorg_blocks_opt.unwrap_or_else(|| {
                    let reorg_start_number = if prev_last_number > last_n_blocks + 1 {
                        prev_last_number - last_n_blocks
                    } else {
                        1
                    };
                    (reorg_start_number..prev_last_number).collect()
                })
            };
            let first_last_n_number = if last_number > last_n_blocks {
                cmp::min(boundary_number, last_number - last_n_blocks)
            } else {
                1
            };
            let headers = reorg_blocks
                .into_iter()
                .filter(|n| *n < first_last_n_number)
                .chain(
                    sampled_numbers
                        .iter()
                        .map(|n| *n as BlockNumber)
                        .filter(|n| *n < first_last_n_number),
                )
                .chain((first_last_n_number..last_number).into_iter())
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

        if param.result != StatusCode::OK {
            assert!(nc.banned_since(peer_index, param.result));
            return;
        }

        assert!(nc.not_banned(peer_index));

        let peer_state = protocol
            .get_peer_state(&peer_index)
            .expect("has peer state");

        // long fork detected
        if rollback_blocks_count > last_n_blocks {
            let prove_request = peer_state.get_prove_request().unwrap();
            assert!(prove_request.if_long_fork_detected());
            return;
        }

        let prove_state = peer_state
            .get_prove_state()
            .expect("has prove state")
            .to_owned();
        let last_header: VerifiableHeader = last_header.into();
        if prev_last_number <= 1 {
            assert!(prove_state.get_reorg_last_headers().is_empty());
        } else {
            assert!(!prove_state.get_reorg_last_headers().is_empty());
        }
        assert!(prove_state.is_same_as(&last_header));
        let expected_last_headers_count = param
            .expected_last_headers_count_opt
            .unwrap_or(last_n_blocks) as usize;
        assert_eq!(
            prove_state.get_last_headers().len(),
            expected_last_headers_count
        );
        for pair in prove_state.get_last_headers().windows(2) {
            assert!(pair[0].is_parent_of(&pair[1]));
        }

        // If `last_number == prev_last_number`, the rollback will not be applied since total
        // difficulties are the same,

        let min_filtered_block_number = if rollback_blocks_count == 0 {
            if last_number == prev_last_number {
                prev_last_number
            } else {
                prev_last_number - 1
            }
        } else {
            prev_last_number - rollback_blocks_count
        };
        assert_eq!(
            storage.get_min_filtered_block_number(),
            min_filtered_block_number
        );

        let earliest_matched_blocks_opt = storage.get_earliest_matched_blocks();
        if earliest_matched_number > min_filtered_block_number {
            assert!(earliest_matched_blocks_opt.is_none());
        } else {
            assert!(earliest_matched_blocks_opt.is_some());
            assert_eq!(
                earliest_matched_blocks_opt.unwrap().0,
                earliest_matched_number
            );
        }
        let latest_matched_blocks_opt = storage.get_latest_matched_blocks();
        if prev_last_number <= earliest_matched_number && last_number != prev_last_number {
            assert!(
                latest_matched_blocks_opt.is_none(),
                "prev: {}, earliest: {}, latest: {}",
                prev_last_number,
                earliest_matched_number,
                latest_matched_blocks_opt.unwrap().0
            );
        } else {
            assert!(latest_matched_blocks_opt.is_some());
            assert_eq!(
                latest_matched_blocks_opt.unwrap().0,
                min_filtered_block_number
            );
        }
        assert_eq!(
            peers.matched_blocks().read().unwrap().is_empty(),
            last_number > prev_last_number
        );
    }
}

// Multi peers are in same chain but have different last states.
// And the higher one send proof to client before the lower one.
#[tokio::test(flavor = "multi_thread")]
async fn multi_peers_override_last_headers() {
    let chain = MockChain::new_with_dummy_pow("test-light-client").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);

    let peer_index_high = PeerIndex::new(1);
    let peer_index_low = PeerIndex::new(2);
    let peers = {
        let peers = chain.create_peers();
        peers.add_peer(peer_index_high);
        peers.add_peer(peer_index_low);
        peers.request_last_state(peer_index_high).unwrap();
        peers.request_last_state(peer_index_low).unwrap();
        peers
    };
    let mut protocol = chain.create_light_client_protocol(peers);
    protocol.set_last_n_blocks(5);

    let num = 30;
    chain.mine_to(num);
    let num_high = num;
    let num_low = num - 5;

    let snapshot = chain.shared().snapshot();

    let sampled_numbers = vec![3, 7, 11, 15];
    let boundary_number_high = num_high - protocol.last_n_blocks() + 1;
    let boundary_number_low = num_low - protocol.last_n_blocks() + 1;

    // Header only in the higher chain.
    let header_hash_for_test = snapshot
        .get_header_by_number((num_high + num_low) / 2)
        .expect("block stored")
        .hash();

    // Setup the test fixture.
    for (peer_index, num, boundary_number) in [
        (peer_index_high, num_high, boundary_number_high),
        (peer_index_low, num_low, boundary_number_low),
    ] {
        let prove_request = chain.build_prove_request(
            0,
            num,
            &sampled_numbers,
            boundary_number,
            protocol.last_n_blocks(),
        );
        let last_state = LastState::new(prove_request.get_last_header().to_owned());

        protocol
            .peers()
            .update_last_state(peer_index, last_state)
            .unwrap();
        protocol
            .peers()
            .update_prove_request(peer_index, prove_request)
            .unwrap();
    }

    // Received proof from higher chain.
    {
        let (peer_index, num, boundary_number) = (peer_index_high, num_high, boundary_number_high);

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

    // Run the test: check last headers which is stored in memory.
    {
        let last_headers = protocol
            .peers()
            .last_headers()
            .read()
            .expect("poisoned")
            .clone();
        assert_eq!(last_headers.len() as u64, protocol.last_n_blocks());
        assert_eq!(last_headers.last().expect("checked").number(), num_high - 1);
        assert!(protocol
            .peers()
            .find_header_in_proved_state(&header_hash_for_test)
            .is_some());
    }

    // Received proof from lower chain.
    {
        let (peer_index, num, boundary_number) = (peer_index_low, num_low, boundary_number_low);

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

    // Run the test: check last headers which is stored in memory, again.
    {
        let last_headers = protocol
            .peers()
            .last_headers()
            .read()
            .expect("poisoned")
            .clone();
        assert_eq!(last_headers.len() as u64, protocol.last_n_blocks());
        assert_eq!(last_headers.last().expect("checked").number(), num_low - 1);
        // TODO FIXME Last headers from a better chain are overrided by worse data.
        assert!(protocol
            .peers()
            .find_header_in_proved_state(&header_hash_for_test)
            .is_none());
    }
}
