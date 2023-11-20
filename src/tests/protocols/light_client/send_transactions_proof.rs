use std::sync::Arc;

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_store::ChainStore;
use ckb_types::{
    h256,
    packed::{self},
    prelude::*,
    utilities::{merkle_mountain_range::VerifiableHeader, CBMT},
};

use crate::{
    protocols::{
        light_client::constant::{FETCH_HEADER_TX_TOKEN, REFRESH_PEERS_TOKEN},
        FetchInfo, StatusCode,
    },
    tests::{
        prelude::*,
        utils::{MockChain, MockNetworkContext},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_send_txs_proof_ok() {
    let chain = MockChain::new_with_dummy_pow("test-send-txs").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);
    let peer_index = PeerIndex::new(3);

    let missing_tx_hashes = vec![h256!("0x1").pack(), h256!("0x2").pack()];

    chain.mine_to(20);
    let tx_hashes: Vec<_> = [13, 15, 17]
        .into_iter()
        .map(|prev_num| {
            let tx = chain.get_cellbase_as_input(prev_num);
            chain.mine_block(|block| {
                let ids = vec![tx.proposal_short_id()];
                block.as_advanced_builder().proposals(ids).build()
            });
            chain.mine_blocks(1);
            chain.mine_block(|block| block.as_advanced_builder().transaction(tx.clone()).build());
            chain.mine_blocks(1);
            tx.hash()
        })
        .collect();

    chain.mine_blocks(4);

    let mut block_numbers = Vec::new();
    let mut filtered_blocks = Vec::new();
    for tx_hash in &tx_hashes {
        let (tx, tx_info) = chain
            .shared()
            .snapshot()
            .get_transaction_with_info(tx_hash)
            .unwrap();
        let block = chain
            .shared()
            .snapshot()
            .get_block(&tx_info.block_hash)
            .unwrap();
        let block_number = block.number();
        let header = block.header();
        let witnesses_root = block.calc_witnesses_root();

        let merkle_proof = CBMT::build_merkle_proof(
            &block
                .transactions()
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            &vec![tx_info.index as u32],
        )
        .unwrap();
        let filtered_block = packed::FilteredBlock::new_builder()
            .header(header.data())
            .witnesses_root(witnesses_root)
            .transactions(vec![tx.data()].pack())
            .proof(
                packed::MerkleProof::new_builder()
                    .indices(merkle_proof.indices().to_owned().pack())
                    .lemmas(merkle_proof.lemmas().to_owned().pack())
                    .build(),
            )
            .build();
        block_numbers.push(block_number);
        filtered_blocks.push(filtered_block);
    }

    let last_header = chain
        .shared()
        .snapshot()
        .get_verifiable_header_by_number(block_numbers[block_numbers.len() - 1] + 1)
        .unwrap();
    let message = {
        let proof = {
            let last_number = last_header.header().raw().number().unpack();
            chain.build_proof_by_numbers(last_number, &block_numbers)
        };
        let items = packed::FilteredBlockVec::new_builder()
            .set(filtered_blocks)
            .build();
        let content = packed::SendTransactionsProof::new_builder()
            .last_header(last_header.clone())
            .proof(proof.pack())
            .filtered_blocks(items)
            .missing_tx_hashes(missing_tx_hashes.clone().pack())
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    };

    let peers = {
        let peers = chain.create_peers();
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(
                tx_hashes
                    .clone()
                    .into_iter()
                    .chain(missing_tx_hashes.clone().into_iter())
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .build();
        peers.add_peer(peer_index);
        peers
            .mock_prove_state(peer_index, last_header.into())
            .unwrap();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        for tx_hash in &missing_tx_hashes {
            peers
                .fetching_txs()
                .insert(tx_hash.clone(), FetchInfo::new(1111, 0, false, false));
        }
        peers
    };

    for tx_hash in &tx_hashes {
        peers.add_fetch_tx(tx_hash.clone(), 111)
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.not_banned(peer_index));
    assert!(nc.sent_messages().borrow().is_empty());
    for tx_hash in tx_hashes {
        assert!(chain
            .client_storage()
            .get_transaction_with_header(&tx_hash)
            .is_some());
    }
    for tx_hash in missing_tx_hashes {
        assert!(peers.fetching_txs().get(&tx_hash).unwrap().missing());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_txs_proof_invalid_mmr_proof() {
    let chain = MockChain::new_with_dummy_pow("test-send-txs").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);
    let peer_index = PeerIndex::new(3);

    chain.mine_to(20);
    let tx_hashes: Vec<_> = [13, 15, 17]
        .into_iter()
        .map(|prev_num| {
            let tx = chain.get_cellbase_as_input(prev_num);
            chain.mine_block(|block| {
                let ids = vec![tx.proposal_short_id()];
                block.as_advanced_builder().proposals(ids).build()
            });
            chain.mine_blocks(1);
            chain.mine_block(|block| block.as_advanced_builder().transaction(tx.clone()).build());
            chain.mine_blocks(1);
            tx.hash()
        })
        .collect();

    chain.mine_blocks(4);

    let mut block_numbers = Vec::new();
    let mut filtered_blocks = Vec::new();
    for tx_hash in &tx_hashes {
        let (tx, tx_info) = chain
            .shared()
            .snapshot()
            .get_transaction_with_info(tx_hash)
            .unwrap();
        let block = chain
            .shared()
            .snapshot()
            .get_block(&tx_info.block_hash)
            .unwrap();
        let block_number = block.number();
        let header = block.header();
        let witnesses_root = block.calc_witnesses_root();

        let merkle_proof = CBMT::build_merkle_proof(
            &block
                .transactions()
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            &vec![tx_info.index as u32],
        )
        .unwrap();
        let filtered_block = packed::FilteredBlock::new_builder()
            .header(header.data())
            .witnesses_root(witnesses_root)
            .transactions(vec![tx.data()].pack())
            .proof(
                packed::MerkleProof::new_builder()
                    .indices(merkle_proof.indices().to_owned().pack())
                    .lemmas(merkle_proof.lemmas().to_owned().pack())
                    .build(),
            )
            .build();
        block_numbers.push(block_number);
        filtered_blocks.push(filtered_block);
    }

    let last_header = chain
        .shared()
        .snapshot()
        .get_verifiable_header_by_number(block_numbers[block_numbers.len() - 1] + 1)
        .unwrap();
    let message = {
        let proof = {
            let last_number = last_header.header().raw().number().unpack();
            // NOTE: this is invalid mmr proof
            chain.build_proof_by_numbers(last_number, &block_numbers[0..block_numbers.len() - 1])
        };
        let items = packed::FilteredBlockVec::new_builder()
            .set(filtered_blocks)
            .build();
        let content = packed::SendTransactionsProof::new_builder()
            .last_header(last_header.clone())
            .proof(proof.pack())
            .filtered_blocks(items)
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    };

    let peers = {
        let peers = chain.create_peers();
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(tx_hashes.clone().pack())
            .build();
        peers.add_peer(peer_index);
        peers
            .mock_prove_state(peer_index, last_header.into())
            .unwrap();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    for tx_hash in &tx_hashes {
        peers.add_fetch_tx(tx_hash.clone(), 111);
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
    assert!(nc.sent_messages().borrow().is_empty());
    for tx_hash in tx_hashes {
        assert!(chain
            .client_storage()
            .get_transaction_with_header(&tx_hash)
            .is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_txs_proof_invalid_merkle_proof() {
    let chain = MockChain::new_with_dummy_pow("test-send-txs").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);
    let peer_index = PeerIndex::new(3);

    chain.mine_to(20);
    let tx_hashes: Vec<_> = [13, 15, 17]
        .into_iter()
        .map(|prev_num| {
            let tx = chain.get_cellbase_as_input(prev_num);
            chain.mine_block(|block| {
                let ids = vec![tx.proposal_short_id()];
                block.as_advanced_builder().proposals(ids).build()
            });
            chain.mine_blocks(1);
            chain.mine_block(|block| block.as_advanced_builder().transaction(tx.clone()).build());
            chain.mine_blocks(1);
            tx.hash()
        })
        .collect();

    chain.mine_blocks(4);

    let mut block_numbers = Vec::new();
    let mut filtered_blocks = Vec::new();
    for tx_hash in &tx_hashes {
        let (tx, tx_info) = chain
            .shared()
            .snapshot()
            .get_transaction_with_info(tx_hash)
            .unwrap();
        let block = chain
            .shared()
            .snapshot()
            .get_block(&tx_info.block_hash)
            .unwrap();
        let block_number = block.number();
        let header = block.header();
        let witnesses_root = block.calc_witnesses_root();

        let merkle_proof = CBMT::build_merkle_proof(
            &block
                .transactions()
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            &vec![tx_info.index as u32],
        )
        .unwrap();
        let filtered_block = packed::FilteredBlock::new_builder()
            .header(header.data())
            .witnesses_root(witnesses_root)
            .transactions(vec![tx.data()].pack())
            .proof(
                packed::MerkleProof::new_builder()
                    .indices(merkle_proof.indices().to_owned().pack())
                    // NOTE: invalid merkle proof
                    .lemmas(
                        merkle_proof
                            .lemmas()
                            .iter()
                            .skip(1)
                            .cloned()
                            .collect::<Vec<_>>()
                            .pack(),
                    )
                    .build(),
            )
            .build();
        block_numbers.push(block_number);
        filtered_blocks.push(filtered_block);
    }

    let last_header = chain
        .shared()
        .snapshot()
        .get_verifiable_header_by_number(block_numbers[block_numbers.len() - 1] + 1)
        .unwrap();
    let message = {
        let proof = {
            let last_number = last_header.header().raw().number().unpack();
            chain.build_proof_by_numbers(last_number, &block_numbers)
        };
        let items = packed::FilteredBlockVec::new_builder()
            .set(filtered_blocks)
            .build();
        let content = packed::SendTransactionsProof::new_builder()
            .last_header(last_header.clone())
            .proof(proof.pack())
            .filtered_blocks(items)
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    };

    let peers = {
        let peers = chain.create_peers();
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(tx_hashes.clone().pack())
            .build();
        peers.add_peer(peer_index);
        peers
            .mock_prove_state(peer_index, last_header.into())
            .unwrap();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    for tx_hash in &tx_hashes {
        peers.add_fetch_tx(tx_hash.clone(), 111);
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
    assert!(nc.sent_messages().borrow().is_empty());
    for tx_hash in tx_hashes {
        assert!(chain
            .client_storage()
            .get_transaction_with_header(&tx_hash)
            .is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_txs_proof_is_empty() {
    let chain = MockChain::new_with_dummy_pow("test-send-txs").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);
    let peer_index = PeerIndex::new(3);

    chain.mine_to(20);

    let last_header = chain
        .shared()
        .snapshot()
        .get_verifiable_header_by_number(20)
        .unwrap();
    let message = {
        let content = packed::SendTransactionsProof::new_builder()
            .last_header(last_header.clone())
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    };

    let peers = {
        let peers = chain.create_peers();
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .build();
        peers.add_peer(peer_index);
        peers
            .mock_prove_state(peer_index, last_header.into())
            .unwrap();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.not_banned(peer_index));
    assert!(nc.sent_messages().borrow().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_headers_txs_request() {
    let chain = MockChain::new_with_dummy_pow("test-send-headers-txs").start();
    let nc = MockNetworkContext::new(SupportProtocols::LightClient);
    let peer_index = PeerIndex::new(3);

    let peers = {
        let peers = chain.create_peers();
        peers.fetching_headers().insert(
            h256!("0xaa22").pack(),
            FetchInfo::new(111, 3344, false, false),
        );
        peers
            .fetching_headers()
            .insert(h256!("0xaa33").pack(), FetchInfo::new(111, 0, false, false));
        peers.fetching_txs().insert(
            h256!("0xbb22").pack(),
            FetchInfo::new(111, 5566, false, false),
        );
        peers
            .fetching_txs()
            .insert(h256!("0xbb33").pack(), FetchInfo::new(111, 0, false, false));

        let tip_header = VerifiableHeader::new(
            chain.client_storage().get_tip_header().into_view(),
            Default::default(),
            None,
            Default::default(),
        );
        peers.add_peer(peer_index);
        peers.mock_prove_state(peer_index, tip_header).unwrap();
        peers
    };

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));

    assert_eq!(peers.get_headers_to_fetch().len(), 1);
    assert_eq!(peers.get_txs_to_fetch().len(), 1);

    protocol.notify(nc.context(), FETCH_HEADER_TX_TOKEN).await;

    assert!(nc.not_banned(peer_index));
    assert_eq!(nc.sent_messages().borrow().len(), 2);

    assert!(
        peers
            .fetching_headers()
            .get(&h256!("0xaa33").pack())
            .unwrap()
            .first_sent()
            > 0
    );
    assert!(
        peers
            .fetching_txs()
            .get(&h256!("0xbb33").pack())
            .unwrap()
            .first_sent()
            > 0
    );
    let peer = peers.get_peer(&peer_index).unwrap();
    assert!(peer.get_blocks_proof_request().is_some());
    assert!(peer.get_txs_proof_request().is_some());

    assert_eq!(peers.get_headers_to_fetch().len(), 0);
    assert_eq!(peers.get_txs_to_fetch().len(), 0);

    protocol.disconnected(nc.context(), peer_index).await;
    protocol.notify(nc.context(), REFRESH_PEERS_TOKEN).await;

    assert_eq!(peers.get_txs_to_fetch().len(), 0);
    assert_eq!(peers.get_headers_to_fetch().len(), 0);
}
