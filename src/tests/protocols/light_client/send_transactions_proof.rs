use std::collections::HashSet;
use std::sync::Arc;

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_store::ChainStore;
use ckb_types::{
    core::TransactionBuilder,
    packed::{self},
    prelude::*,
    utilities::CBMT,
};

use crate::{
    protocols::{LastState, Peers, ProveRequest, ProveState, StatusCode},
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

    chain.mine_to(20);
    let tx_hashes: Vec<_> = [13, 15, 17]
        .into_iter()
        .map(|prev_num| {
            let prev_block = chain
                .shared()
                .snapshot()
                .get_block_by_number(prev_num)
                .unwrap();
            let input = {
                let prev_tx = prev_block.transactions().get(0).unwrap().clone();
                let previous_tx_hash = prev_tx.hash();
                packed::CellInput::new(packed::OutPoint::new(previous_tx_hash, 0), 0)
            };
            let header_dep = prev_block.hash();
            let output = packed::CellOutput::new_builder()
                .capacity(0xf4610900.pack())
                .build();
            let tx = TransactionBuilder::default()
                .cell_dep(chain.always_success_cell_dep())
                .header_dep(header_dep)
                .input(input)
                .output(output)
                .output_data(Default::default())
                .build();
            chain
                .tx_pool()
                .submit_local_tx(tx.clone())
                .unwrap()
                .unwrap();
            chain.mine_blocks(2);
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
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
    };

    let peers = {
        let last_state = LastState::new(last_header.clone().into());
        let request = ProveRequest::new(last_state, Default::default());
        let prove_state =
            ProveState::new_from_request(request, Default::default(), Default::default());
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers.commit_prove_state(peer_index, prove_state);
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(tx_hashes.clone().pack())
            .build();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    for tx_hash in &tx_hashes {
        peers.fetching_txs().insert(tx_hash.unpack(), None);
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_peers().borrow().is_empty());
    assert!(nc.sent_messages().borrow().is_empty());
    assert_eq!(
        peers
            .fetched_txs()
            .iter()
            .map(|pair| pair.key().pack())
            .collect::<HashSet<_>>(),
        tx_hashes.into_iter().collect()
    );
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
            let prev_block = chain
                .shared()
                .snapshot()
                .get_block_by_number(prev_num)
                .unwrap();
            let input = {
                let prev_tx = prev_block.transactions().get(0).unwrap().clone();
                let previous_tx_hash = prev_tx.hash();
                packed::CellInput::new(packed::OutPoint::new(previous_tx_hash, 0), 0)
            };
            let header_dep = prev_block.hash();
            let output = packed::CellOutput::new_builder()
                .capacity(0xf4610900.pack())
                .build();
            let tx = TransactionBuilder::default()
                .cell_dep(chain.always_success_cell_dep())
                .header_dep(header_dep)
                .input(input)
                .output(output)
                .output_data(Default::default())
                .build();
            chain
                .tx_pool()
                .submit_local_tx(tx.clone())
                .unwrap()
                .unwrap();
            chain.mine_blocks(2);
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
        let last_state = LastState::new(last_header.clone().into());
        let request = ProveRequest::new(last_state, Default::default());
        let prove_state =
            ProveState::new_from_request(request, Default::default(), Default::default());
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers.commit_prove_state(peer_index, prove_state);
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(tx_hashes.clone().pack())
            .build();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    for tx_hash in &tx_hashes {
        peers.fetching_txs().insert(tx_hash.unpack(), None);
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
    assert!(nc.sent_messages().borrow().is_empty());
    assert!(peers.fetched_txs().is_empty());
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
            let prev_block = chain
                .shared()
                .snapshot()
                .get_block_by_number(prev_num)
                .unwrap();
            let input = {
                let prev_tx = prev_block.transactions().get(0).unwrap().clone();
                let previous_tx_hash = prev_tx.hash();
                packed::CellInput::new(packed::OutPoint::new(previous_tx_hash, 0), 0)
            };
            let header_dep = prev_block.hash();
            let output = packed::CellOutput::new_builder()
                .capacity(0xf4610900.pack())
                .build();
            let tx = TransactionBuilder::default()
                .cell_dep(chain.always_success_cell_dep())
                .header_dep(header_dep)
                .input(input)
                .output(output)
                .output_data(Default::default())
                .build();
            chain
                .tx_pool()
                .submit_local_tx(tx.clone())
                .unwrap()
                .unwrap();
            chain.mine_blocks(2);
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
        let last_state = LastState::new(last_header.clone().into());
        let request = ProveRequest::new(last_state, Default::default());
        let prove_state =
            ProveState::new_from_request(request, Default::default(), Default::default());
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers.commit_prove_state(peer_index, prove_state);
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .tx_hashes(tx_hashes.clone().pack())
            .build();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    for tx_hash in &tx_hashes {
        peers.fetching_txs().insert(tx_hash.unpack(), None);
    }

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_since(peer_index, StatusCode::InvalidProof));
    assert!(nc.sent_messages().borrow().is_empty());
    assert!(peers.fetched_txs().is_empty());
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
        let last_state = LastState::new(last_header.clone().into());
        let request = ProveRequest::new(last_state, Default::default());
        let prove_state =
            ProveState::new_from_request(request, Default::default(), Default::default());
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers.commit_prove_state(peer_index, prove_state);
        let txs_proof_request = packed::GetTransactionsProof::new_builder()
            .last_hash(last_header.header().calc_header_hash())
            .build();
        peers.update_txs_proof_request(peer_index, Some(txs_proof_request));
        peers
    };

    let mut protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    protocol
        .received(nc.context(), peer_index, message.as_bytes())
        .await;

    assert!(nc.banned_peers().borrow().is_empty());
    assert!(nc.sent_messages().borrow().is_empty());
}
