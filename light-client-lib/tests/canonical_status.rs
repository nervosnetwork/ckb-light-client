//! Deterministic protocol tests: an explicitly trusted fixture anchor and DummyPoW
//! consensus, with real response PoW/MMR/Merkle processing. Not a real-chain reorg.
#![cfg(not(target_arch = "wasm32"))]
use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
pub use ckb_light_client_lib::protocols;
use ckb_light_client_lib::{
    protocols::{LastState, LightClientProtocol, Peers, PendingTxs, ProveRequest, ProveState},
    service::{FetchStatus, LightClientChainService},
    storage::{LightClientStorage, Storage, StorageWithChainData},
};
use ckb_merkle_mountain_range::{leaf_index_to_pos, util::MemMMR};
use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core, packed,
    prelude::*,
    utilities::merkle_mountain_range::{MergeHeaderDigest, VerifiableHeader},
    U256,
};
use std::sync::Arc;
// Reused transport has helpers for other protocol suites.
#[allow(dead_code)]
#[path = "../src/tests/utils/network_context.rs"]
mod network_context;
use network_context::MockNetworkContext;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Storage,
    service: LightClientChainService,
    protocol: LightClientProtocol,
    context: MockNetworkContext,
    peer: PeerIndex,
    hash: ckb_types::H256,
    message: packed::LightClientMessage,
    anchor: core::HeaderView,
    peers: Arc<Peers>,
    extra_block: Option<core::BlockView>,
    containing_block: core::BlockView,
}

use ckb_light_client_lib::{
    service::{LightClientService, Order, SearchKey},
    storage::{
        HeaderWithExtension, Key, ScriptStatus, ScriptType, SetScriptsCommand, StorageBackend,
    },
};
use ckb_types::core::cell::{CellProvider, CellStatus};

fn fetch_info(f: &Fixture, hash: &ckb_types::H256, header: bool) -> (u64, u64, bool) {
    let swc = StorageWithChainData::new(
        f.storage.clone(),
        f.peers.clone(),
        Arc::new(std::sync::RwLock::new(PendingTxs::new(16))),
    );
    if header {
        swc.get_header_fetch_info(hash).unwrap()
    } else {
        swc.get_tx_fetch_info(hash).unwrap()
    }
}
fn status(f: &Fixture) -> serde_json::Value {
    serde_json::to_value(f.service.get_transaction(&f.hash)).unwrap()["tx_status"].clone()
}
fn payload(f: &Fixture) -> packed::SendTransactionsProofV1 {
    packed::SendTransactionsProofV1::from_compatible_slice(f.message.to_enum().as_slice()).unwrap()
}
fn inclusion(f: &Fixture) -> HeaderWithExtension {
    HeaderWithExtension {
        header: payload(f).filtered_blocks().get(0).unwrap().header(),
        extension: None,
    }
}
fn transaction(f: &Fixture) -> packed::Transaction {
    payload(f)
        .filtered_blocks()
        .get(0)
        .unwrap()
        .transactions()
        .get(0)
        .unwrap()
}
fn register(f: &Fixture) {
    let script = transaction(f).raw().outputs().get(0).unwrap().lock();
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script,
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
}
fn watched_script() -> packed::Script {
    packed::Script::new_builder()
        .args(b"wo07".to_vec().pack())
        .build()
}
fn key() -> SearchKey {
    SearchKey {
        script: watched_script().into(),
        ..SearchKey::default()
    }
}
fn queries(f: &Fixture) -> LightClientService<Storage> {
    LightClientService::new(Arc::new(f.storage.clone()))
}
fn point(f: &Fixture) -> packed::OutPoint {
    packed::OutPoint::new(f.hash.pack(), 0)
}
fn index_fixture(f: &Fixture) {
    register(f);
    f.storage.filter_block(f.containing_block.data());
    f.storage.update_block_number(1);
}

#[tokio::test]
async fn delayed_transaction_reply_cannot_drain_a_newer_request_slot() {
    replacement_slot(false, false).await;
}
#[tokio::test]
async fn delayed_header_reply_cannot_drain_a_newer_request_slot() {
    replacement_slot(true, false).await;
}
#[tokio::test]
async fn empty_old_state_announcement_cannot_retire_an_unrelated_operation() {
    replacement_slot(false, true).await;
    replacement_slot(true, true).await;
}
async fn replacement_slot(header: bool, empty: bool) {
    for (same_anchor, negative) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut f = Fixture::new(false, false).await;
        let p = payload(&f);
        let block = inclusion(&f).header;
        let block_hash = block.calc_header_hash();
        let accepted = if same_anchor {
            f.anchor.clone()
        } else {
            f.anchor
                .clone()
                .as_advanced_builder()
                .nonce(900u128)
                .build()
        };
        let new_wire = p.last_header().as_builder().header(accepted.data()).build();
        // Active replacement dispatch context plus an authentic old wire reply.
        // This models slot replacement, not a live timer/reconnection experiment.
        f.storage
            .update_last_state(&U256::from(4u64), &accepted.data(), &[]);
        let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
        peers.add_peer(f.peer);
        let state = LastState::new(new_wire.clone().into());
        let request = ProveRequest::new(state.clone(), Default::default());
        peers.request_last_state(f.peer).unwrap();
        peers.update_last_state(f.peer, state).unwrap();
        peers.update_prove_request(f.peer, request.clone()).unwrap();
        peers
            .update_prove_state(
                f.peer,
                ProveState::new_from_request(request, vec![], vec![]),
            )
            .unwrap();
        f.service = LightClientChainService::new(
            StorageWithChainData::new(
                f.storage.clone(),
                peers.clone(),
                Arc::new(std::sync::RwLock::new(PendingTxs::new(16))),
            ),
            Arc::new(ConsensusBuilder::default().build()),
        );
        f.protocol = LightClientProtocol::new(
            f.storage.clone(),
            peers.clone(),
            ConsensusBuilder::default().build(),
        );
        f.peers = peers;
        let query_hash = if same_anchor {
            packed::Byte32::new([31; 32]).unpack()
        } else if header {
            block_hash.unpack()
        } else {
            f.hash.clone()
        };
        if header {
            f.service.fetch_header(&query_hash);
        } else {
            f.service.fetch_transaction(&query_hash);
        }
        f.protocol.notify(f.context.context(), 1).await;
        let positive_header = packed::SendBlocksProofV1::new_builder()
            .last_header(p.last_header())
            .proof(p.proof())
            .headers(vec![block].pack())
            .blocks_uncles_hash(p.blocks_uncles_hash())
            .blocks_extension(p.blocks_extension())
            .build();
        let old = if empty {
            if header {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendBlocksProofV1::new_builder()
                            .last_header(p.last_header())
                            .build(),
                    )
                    .build()
            } else {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendTransactionsProofV1::new_builder()
                            .last_header(p.last_header())
                            .build(),
                    )
                    .build()
            }
        } else if header {
            let response = if negative {
                packed::SendBlocksProofV1::new_builder()
                    .last_header(p.last_header())
                    .missing_block_hashes(vec![block_hash.clone()].pack())
                    .build()
            } else {
                positive_header.clone()
            };
            packed::LightClientMessage::new_builder()
                .set(response)
                .build()
        } else if negative {
            packed::LightClientMessage::new_builder()
                .set(
                    packed::SendTransactionsProofV1::new_builder()
                        .last_header(p.last_header())
                        .missing_tx_hashes(vec![f.hash.pack()].pack())
                        .build(),
                )
                .build()
        } else {
            f.message.clone()
        };
        f.protocol
            .received(f.context.context(), f.peer, old.as_bytes())
            .await;
        let current = if same_anchor {
            // Normal matching negative completion is a peer report, not proof of absence.
            if header {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendBlocksProofV1::new_builder()
                            .last_header(new_wire)
                            .missing_block_hashes(vec![query_hash.pack()].pack())
                            .build(),
                    )
                    .build()
            } else {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendTransactionsProofV1::new_builder()
                            .last_header(new_wire)
                            .missing_tx_hashes(vec![query_hash.pack()].pack())
                            .build(),
                    )
                    .build()
            }
        } else if header {
            packed::LightClientMessage::new_builder()
                .set(positive_header.as_builder().last_header(new_wire).build())
                .build()
        } else {
            packed::LightClientMessage::new_builder()
                .set(p.as_builder().last_header(new_wire).build())
                .build()
        };
        f.protocol
            .received(f.context.context(), f.peer, current.as_bytes())
            .await;
        if same_anchor {
            if header {
                assert!(matches!(
                    f.service.fetch_header(&query_hash),
                    FetchStatus::NotFound
                ));
            } else {
                assert!(matches!(
                    f.service.fetch_transaction(&query_hash),
                    FetchStatus::NotFound
                ));
            }
        } else if header {
            assert!(f.service.get_header(&block_hash.unpack()).is_some());
        } else {
            assert_eq!(status(&f)["status"], "committed");
        }
        // Deliver the old response again after the matching current operation completed.
        f.protocol
            .received(f.context.context(), f.peer, old.as_bytes())
            .await;
        assert!(f.context.not_banned(f.peer));
    }
}

#[tokio::test]
async fn damaged_watched_rows_are_errors_instead_of_zero_balance_or_empty_pages() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let cell = Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec();
    f.storage.put(cell.clone(), vec![0; 31]).unwrap();
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    assert!(queries(&f)
        .get_cells(key(), Order::Asc, 100u32.into(), None)
        .is_err());
    f.storage.delete(&cell).unwrap();
    f.storage
        .put(
            Key::CellLockScript(&watched_script(), 1, 0, 99).into_vec(),
            f.hash.as_bytes().to_vec(),
        )
        .unwrap();
    assert!(queries(&f).get_cells_capacity(key()).is_err());
}

#[tokio::test]
async fn raw_height_index_or_transaction_corruption_cannot_reuse_a_verified_binding() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let row_key = Key::TxHash(&f.hash.pack()).into_vec();
    let row = f.storage.get(row_key.clone()).unwrap().unwrap();
    for offset in [0usize, 8, 12] {
        let mut damaged = row.clone();
        damaged[offset] ^= 1;
        f.storage.put(row_key.clone(), damaged).unwrap();
        assert_eq!(status(&f)["status"], "unknown");
        assert!(matches!(
            f.storage.cell(&point(&f), true),
            CellStatus::Unknown
        ));
        assert!(queries(&f).get_cells_capacity(key()).is_err());
    }
    f.storage.put(row_key, row).unwrap();
    assert_eq!(status(&f)["status"], "committed");
    let header_key = Key::BlockHash(&inclusion(&f).header.calc_header_hash()).into_vec();
    let header = f.storage.get(header_key.clone()).unwrap().unwrap();
    for bytes in [vec![0], vec![0; packed::Header::TOTAL_SIZE]] {
        f.storage.put(header_key.clone(), bytes).unwrap();
        assert!(f
            .service
            .get_header(&inclusion(&f).header.calc_header_hash().unpack())
            .is_none());
        assert_eq!(status(&f)["status"], "unknown");
    }
    f.storage.put(header_key, header).unwrap();
    let state_key = Key::Meta("LAST_STATE").into_vec();
    let state = f.storage.get(state_key.clone()).unwrap().unwrap();
    f.storage.put(state_key.clone(), vec![0]).unwrap();
    assert_eq!(status(&f)["status"], "unknown");
    assert!(matches!(
        f.storage.cell(&point(&f), true),
        CellStatus::Unknown
    ));
    let mut changed = state.clone();
    *changed.last_mut().unwrap() ^= 1; // Still a structurally valid header, different hash.
    f.storage.put(state_key.clone(), changed).unwrap();
    assert_eq!(status(&f)["status"], "unknown");
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    f.storage.put(state_key, state).unwrap();
    assert_eq!(status(&f)["status"], "committed");
}

#[tokio::test]
async fn unproved_legacy_overwrite_cannot_borrow_existing_header_membership() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    f.storage.add_fetched_tx(&transaction(&f), &inclusion(&f));
    assert_eq!(status(&f)["status"], "unknown");
    assert!(matches!(
        f.storage.cell(&point(&f), true),
        CellStatus::Unknown
    ));
    assert!(matches!(
        f.service.fetch_transaction(&f.hash),
        FetchStatus::Added { .. }
    ));
}

#[tokio::test]
async fn legacy_reopen_recovers_configured_genesis_without_guessing_historical_membership() {
    let f = Fixture::new(false, false).await;
    let genesis = f.storage.get_genesis_block();
    let hash = genesis.transactions().get(0).unwrap().calc_tx_hash();
    let mut binding = Key::Meta("TX_BLOCK_V1:").into_vec();
    binding.extend_from_slice(hash.as_slice());
    let mut member = Key::Meta("CHAIN_BLOCK_V1:").into_vec();
    member.extend_from_slice(&0u64.to_be_bytes());
    f.storage.delete(&binding).unwrap();
    f.storage.delete(&member).unwrap();
    f.storage.init_genesis_block(genesis);
    assert!(f.storage.get_transaction_with_header(&hash).is_some());
    register(&f); // Must not panic while filtering configured genesis in a legacy store.
}

fn wire(header: &VerifiableHeader) -> packed::VerifiableHeader {
    packed::VerifiableHeader::new_builder()
        .header(header.header().data())
        .uncles_hash(header.uncles_hash())
        .extension(
            packed::BytesOpt::new_builder()
                .set(header.extension())
                .build(),
        )
        .parent_chain_root(header.parent_chain_root())
        .build()
}

fn chain(
    genesis: &core::HeaderView,
    old: &[(core::BlockView, VerifiableHeader)],
    common: usize,
    end: u64,
    tx: &core::TransactionView,
) -> Vec<(core::BlockView, VerifiableHeader)> {
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.digest()).unwrap();
    let mut blocks: Vec<(core::BlockView, VerifiableHeader)> = Vec::new();
    for number in 1..=end {
        let (block, verifiable) = if number as usize <= common {
            old[number as usize - 1].clone()
        } else {
            let root = mmr.get_root().unwrap();
            let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
            let builder = core::BlockBuilder::default()
                .number(number)
                .nonce(if old.is_empty() { 0u128 } else { 99u128 })
                .parent_hash(
                    blocks
                        .last()
                        .map(|(block, _)| block.hash())
                        .unwrap_or_else(|| genesis.hash()),
                )
                .compact_target(genesis.compact_target())
                .epoch(core::EpochNumberWithFraction::new(0, number, 100))
                .extension(Some(extension.clone()));
            let block = if number == 2 && old.is_empty() {
                builder.transaction(tx.clone()).build()
            } else {
                builder.build()
            };
            let verifiable = VerifiableHeader::new(
                block.header(),
                block.calc_uncles_hash(),
                Some(extension),
                root,
            );
            (block, verifiable)
        };
        mmr.push(block.header().digest()).unwrap();
        blocks.push((block, verifiable));
    }
    blocks
}

#[tokio::test]
async fn actual_last_state_proof_processor_revokes_fork_suffix() {
    accepted_fork(false).await;
}
#[tokio::test]
async fn legacy_mismatched_window_cannot_preserve_an_unproved_common_prefix() {
    accepted_fork(true).await;
}
async fn accepted_fork(unbound_window: bool) {
    accepted_fork_case(unbound_window, false).await;
}

#[tokio::test]
async fn interrupted_rollback_then_known_fork_never_retrusts_partial_index() {
    accepted_fork_case(false, true).await;
}

async fn accepted_fork_case(unbound_window: bool, interrupted: bool) {
    // Real protocol/MMR processing over a deterministic DummyPoW chain, not a live reorg.
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let consensus = ConsensusBuilder::default().build();
    storage.init_genesis_block(consensus.genesis_block().data());
    let genesis = consensus.genesis_block().header();
    let tx = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(100u64)
                .lock(watched_script())
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let old = chain(&genesis, &[], 0, 3, &tx);
    let new = chain(&genesis, &old, if unbound_window { 0 } else { 1 }, 4, &tx);
    storage.update_last_state(
        &old[2].1.total_difficulty(),
        &old[2].0.header().data(),
        &[old[0].0.header(), old[1].0.header()],
    );
    let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
    let peer = PeerIndex::new(1);
    peers.add_peer(peer);
    let state = LastState::new(old[2].1.clone());
    let request = ProveRequest::new(state.clone(), Default::default());
    peers.request_last_state(peer).unwrap();
    peers.update_last_state(peer, state).unwrap();
    peers.update_prove_request(peer, request.clone()).unwrap();
    peers
        .update_prove_state(
            peer,
            ProveState::new_from_request(
                request,
                vec![],
                vec![old[0].0.header(), old[1].0.header()],
            ),
        )
        .unwrap();
    let service = LightClientChainService::new(
        StorageWithChainData::new(
            storage.clone(),
            peers.clone(),
            Arc::new(std::sync::RwLock::new(PendingTxs::new(16))),
        ),
        Arc::new(consensus.clone()),
    );
    let hash = tx.hash().unpack();
    service.fetch_transaction(&hash);
    let mut protocol = LightClientProtocol::new(storage.clone(), peers.clone(), consensus);
    let context = MockNetworkContext::new(SupportProtocols::LightClient);
    protocol.notify(context.context(), 1).await;
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.digest()).unwrap();
    for (block, _) in &old[..2] {
        mmr.push(block.header().digest()).unwrap();
    }
    let proof = mmr
        .gen_proof(vec![leaf_index_to_pos(2)])
        .unwrap()
        .proof_items()
        .to_vec();
    let tx_response = packed::LightClientMessage::new_builder()
        .set(
            packed::SendTransactionsProofV1::new_builder()
                .last_header(wire(&old[2].1))
                .proof(proof.pack())
                .filtered_blocks(vec![packed::FilteredBlock::new_builder()
                    .header(old[1].0.header().data())
                    .witnesses_root(old[1].0.calc_witnesses_root())
                    .transactions(vec![tx.data()].pack())
                    .proof(
                        packed::MerkleProof::new_builder()
                            .indices([0u32].pack())
                            .build(),
                    )
                    .build()])
                .blocks_uncles_hash(vec![old[1].0.calc_uncles_hash()].pack())
                .blocks_extension(vec![packed::BytesOpt::new_builder()
                    .set(old[1].0.extension())
                    .build()])
                .build(),
        )
        .build();
    protocol
        .received(context.context(), peer, tx_response.as_bytes())
        .await;
    assert_eq!(
        serde_json::to_value(service.get_transaction(&hash)).unwrap()["tx_status"]["status"],
        "committed"
    );
    // Inclusion at 2, accepted tip 3: two local confirmations, not finality.
    assert_eq!(storage.get_tip_header().into_view().number() - 2 + 1, 2);
    if interrupted {
        storage.update_filter_scripts(
            vec![ScriptStatus {
                script: watched_script(),
                script_type: ScriptType::Lock,
                block_number: 0,
            }],
            SetScriptsCommand::All,
        );
        storage.filter_block(old[1].0.data());
        storage.update_block_number(2);
        // Crash fixture after part of the rollback; the next fork uses the real processor.
        storage
            .put(Key::Meta("CHAIN_TRANSITION_V1").into_vec(), vec![1])
            .unwrap();
        storage
            .delete(&Key::CellLockScript(&watched_script(), 2, 0, 0).into_vec())
            .unwrap();
    }
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.digest()).unwrap();
    for (block, _) in &new[..3] {
        mmr.push(block.header().digest()).unwrap();
    }
    let proof = mmr
        .gen_proof(vec![
            leaf_index_to_pos(1),
            leaf_index_to_pos(2),
            leaf_index_to_pos(3),
        ])
        .unwrap()
        .proof_items()
        .to_vec();
    if unbound_window {
        // Simulate the persisted old defect: accepted tip A, recent window B.
        storage.update_last_n_headers(&[new[0].0.header(), new[1].0.header()]);
        storage
            .delete(&Key::Meta("CHAIN_CONTEXT_V1").into_vec())
            .unwrap();
    }
    let state = LastState::new(new[3].1.clone());
    peers.request_last_state(peer).unwrap();
    peers.update_last_state(peer, state.clone()).unwrap();
    let content = packed::GetLastStateProof::new_builder()
        .last_hash(new[3].0.hash())
        .start_hash(old[2].0.hash())
        .start_number(3u64)
        .build();
    peers
        .update_prove_request(peer, ProveRequest::new(state, content))
        .unwrap();
    let response = packed::LightClientMessage::new_builder()
        .set(
            packed::SendLastStateProof::new_builder()
                .last_header(wire(&new[3].1))
                .proof(proof.pack())
                .headers(
                    new[..3]
                        .iter()
                        .map(|(_, header)| wire(header))
                        .collect::<Vec<_>>()
                        .pack(),
                )
                .build(),
        )
        .build();
    protocol
        .received(context.context(), peer, response.as_bytes())
        .await;
    assert_eq!(
        storage.get_tip_header().calc_header_hash(),
        new[3].0.hash(),
        "actual last-state handler must accept the fixture fork"
    );
    assert_eq!(
        serde_json::to_value(service.get_transaction(&hash)).unwrap()["tx_status"]["status"],
        "unknown"
    );
    assert!(storage.get_transaction(&tx.hash()).is_some());
    if interrupted {
        assert!(
            LightClientService::new(Arc::new(storage.clone()))
                .get_cells_capacity(key())
                .is_err(),
            "a later known fork cannot certify an interrupted index"
        );
    }
    assert!(context.not_banned(peer));
}

#[tokio::test]
async fn watched_spend_waits_for_legacy_creator_proof_then_resumes_existing_pipeline() {
    watched_spend(false).await;
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn watched_range_commit_failure_is_visible_after_reopen_and_replays_safely() {
    watched_spend(true).await;
}
async fn watched_spend(_fail_finish: bool) {
    let mut f = Fixture::chain(false, false, true).await;
    register(&f);
    let creator = transaction(&f);
    // An existing height-only database/index fixture, not manufactured proof success.
    f.storage.add_fetched_tx(&creator, &inclusion(&f));
    f.storage
        .put(
            Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec(),
            f.hash.as_bytes().to_vec(),
        )
        .unwrap();
    f.storage
        .put(
            Key::TxLockScript(
                &watched_script(),
                1,
                0,
                0,
                ckb_light_client_lib::storage::CellType::Output,
            )
            .into_vec(),
            f.hash.as_bytes().to_vec(),
        )
        .unwrap();
    f.storage.update_block_number(1);
    let block = f.extra_block.clone().unwrap();
    f.storage
        .add_matched_blocks(2, 1, vec![(block.hash(), false)]);
    f.peers
        .matched_blocks()
        .write()
        .await
        .insert(block.hash().unpack(), (false, None));
    f.protocol.notify(f.context.context(), 2).await;
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(f.storage.get_genesis_block().into_view().header().digest())
        .unwrap();
    mmr.push(inclusion(&f).header.into_view().digest()).unwrap();
    mmr.push(block.header().digest()).unwrap();
    let proof = mmr
        .gen_proof(vec![leaf_index_to_pos(2)])
        .unwrap()
        .proof_items()
        .to_vec();
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(payload(&f).last_header())
        .proof(proof.pack())
        .headers(vec![block.header().data()].pack())
        .blocks_uncles_hash(vec![block.calc_uncles_hash()].pack())
        .blocks_extension(vec![packed::BytesOpt::default()])
        .build();
    f.protocol
        .received(
            f.context.context(),
            f.peer,
            packed::LightClientMessage::new_builder()
                .set(response)
                .build()
                .as_bytes(),
        )
        .await;
    let mut sync =
        ckb_light_client_lib::protocols::SyncProtocol::new(f.storage.clone(), f.peers.clone());
    let context = MockNetworkContext::new(SupportProtocols::Sync);
    sync.received(
        context.context(),
        f.peer,
        packed::SyncMessage::new_builder()
            .set(packed::SendBlock::new_builder().block(block.data()).build())
            .build()
            .as_bytes(),
    )
    .await;
    assert_eq!(
        f.storage.get_filter_scripts()[0].block_number,
        1,
        "cursor cannot pass unresolved watched input"
    );
    assert!(f.storage.get_earliest_matched_blocks().is_some());
    assert!(
        queries(&f).get_cells_capacity(key()).is_err(),
        "ambiguous balance is an error, not zero"
    );
    // Complete the actual existing GetTransactionsProof operation, then its normal idle tick.
    f.receive().await;
    #[cfg(feature = "sqlite")]
    if _fail_finish {
        let connection = rusqlite::Connection::open(f._directory.path().join("db.sqlite")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_range BEFORE DELETE ON kv_store WHEN hex(OLD.key) LIKE 'E04D4154434845445F424C4F434B53%' BEGIN SELECT RAISE(ABORT,'injected range finalization failure'); END;").unwrap();
        f.protocol.notify(f.context.context(), 2).await;
        assert_eq!(f.storage.get_filter_scripts()[0].block_number, 1);
        assert!(f.storage.get_earliest_matched_blocks().is_some());
        let reopened = LightClientService::new(Arc::new(Storage::new(f._directory.path())));
        assert!(reopened.get_cells_capacity(key()).is_err());
        connection
            .execute_batch("DROP TRIGGER fail_range;")
            .unwrap();
    }
    f.protocol.notify(f.context.context(), 2).await;
    assert_eq!(f.storage.get_filter_scripts()[0].block_number, 2);
    assert!(f.storage.get_earliest_matched_blocks().is_none());
    assert_eq!(
        queries(&f)
            .get_cells_capacity(key())
            .unwrap()
            .capacity
            .value(),
        0
    );
    assert_eq!(
        queries(&f)
            .get_transactions(key(), Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        2
    );
    let spending_hash = block.transactions()[0].hash().unpack();
    assert_eq!(
        serde_json::to_value(f.service.get_transaction(&spending_hash)).unwrap()["tx_status"]
            ["status"],
        "committed"
    );
    assert!(f.context.not_banned(f.peer));
    assert!(context.not_banned(f.peer));
}

#[tokio::test]
async fn peer_missing_report_never_discards_a_watched_match() {
    let mut f = Fixture::new(false, false).await;
    let hash = inclusion(&f).header.calc_header_hash();
    f.storage
        .add_matched_blocks(1, 1, vec![(hash.clone(), false)]);
    f.peers
        .matched_blocks()
        .write()
        .await
        .insert(hash.unpack(), (false, None));
    f.protocol.notify(f.context.context(), 2).await;
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(payload(&f).last_header())
        .missing_block_hashes(vec![hash.clone()].pack())
        .build();
    f.protocol
        .received(
            f.context.context(),
            f.peer,
            packed::LightClientMessage::new_builder()
                .set(response)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(f
        .peers
        .matched_blocks()
        .read()
        .await
        .contains_key(&hash.unpack()));
    assert!(f.storage.get_earliest_matched_blocks().is_some());
}

#[tokio::test]
async fn concurrent_height_cache_updates_cannot_change_transaction_attribution() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let original = inclusion(&f).header.into_view();
    let writer = f.storage.clone();
    let header = original.clone();
    let thread = std::thread::spawn(move || {
        for nonce in 1..=200u128 {
            writer.add_fetched_header(&HeaderWithExtension {
                header: header
                    .clone()
                    .as_advanced_builder()
                    .nonce(nonce)
                    .build()
                    .data(),
                extension: None,
            });
        }
    });
    for _ in 0..200 {
        let result = f.service.get_transaction(&f.hash);
        assert_eq!(result.tx_status.block_hash, Some(original.hash().unpack()));
        assert!(matches!(
            f.storage.cell(&point(&f), true),
            CellStatus::Live(_)
        ));
    }
    thread.join().unwrap();
}

#[tokio::test]
async fn legacy_database_is_not_silently_migrated_and_reproof_recovers_only_supported_claims() {
    let mut f = Fixture::new(false, false).await;
    f.storage
        .delete(&Key::Meta("INDEX_ASSOCIATIONS_V1").into_vec())
        .unwrap();
    f.storage.add_fetched_tx(&transaction(&f), &inclusion(&f));
    // Existing registration/index without the new format marker is retained.
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script: watched_script(),
            script_type: ScriptType::Lock,
            block_number: 1,
        }],
        SetScriptsCommand::All,
    );
    let cell_key = Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec();
    f.storage
        .put(cell_key.clone(), f.hash.as_bytes().to_vec())
        .unwrap();
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    f.receive().await;
    assert_eq!(status(&f)["status"], "committed");
    assert!(
        queries(&f).get_cells_capacity(key()).is_err(),
        "one proof cannot certify old watched completeness"
    );
    assert!(f.storage.get(cell_key.clone()).unwrap().is_some());
    register(&f); // Registration does not silently migrate.
    assert!(f.storage.get(cell_key).unwrap().is_some());
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    // Stage a replacement database; retain the old database until independently synced.
    let mut replacement = Fixture::new(false, false).await;
    replacement.receive().await;
    index_fixture(&replacement);
    assert_eq!(
        queries(&replacement)
            .get_cells_capacity(key())
            .unwrap()
            .capacity
            .value(),
        100
    );
    assert!(queries(&f).get_cells_capacity(key()).is_err());
}

#[tokio::test]
async fn real_fixture_proof_binds_block_position_and_resolver_and_survives_reopen() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    assert_eq!(status(&f)["status"], "committed");
    assert_eq!(
        f.service.get_transaction(&f.hash).tx_status.block_hash,
        Some(inclusion(&f).header.calc_header_hash().unpack())
    );
    assert!(matches!(
        f.storage.cell(&point(&f), true),
        CellStatus::Live(_)
    ));
    let (_, index, _) = f.storage.get_transaction(&f.hash.pack()).unwrap();
    assert_eq!(
        index, 0,
        "actual Merkle position must replace legacy sentinel"
    );
    f = f.reopen();
    assert!(f
        .storage
        .get_transaction_with_header(&f.hash.pack())
        .is_some());
    assert!(matches!(
        f.service.fetch_transaction(&f.hash),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test]
async fn cached_height_mapping_cannot_relabel_verified_transaction() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let original = inclusion(&f).header;
    let replacement = original
        .clone()
        .into_view()
        .as_advanced_builder()
        .transactions_root(packed::Byte32::new([77; 32]))
        .build();
    f.storage.add_fetched_header(&HeaderWithExtension {
        header: replacement.data(),
        extension: None,
    });
    assert_eq!(
        f.service.get_transaction(&f.hash).tx_status.block_hash,
        Some(original.calc_header_hash().unpack())
    );
    assert_eq!(
        f.storage
            .get_transaction_with_header(&f.hash.pack())
            .unwrap()
            .1
            .as_slice(),
        original.as_slice()
    );
    if let CellStatus::Live(cell) = f.storage.cell(&point(&f), true) {
        assert_eq!(
            cell.transaction_info.unwrap().block_hash,
            original.calc_header_hash()
        );
    } else {
        panic!("verified creator must resolve");
    }
}

#[tokio::test]
async fn rollback_revokes_status_and_resolution_but_retains_historical_bytes_and_header() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let original = inclusion(&f).header;
    f.storage.rollback_to_block(1);
    assert_eq!(status(&f)["status"], "unknown");
    assert!(f.service.get_transaction(&f.hash).transaction.is_some());
    assert!(f
        .service
        .get_transaction(&f.hash)
        .tx_status
        .block_hash
        .is_none());
    assert!(f
        .storage
        .get_transaction_with_header(&f.hash.pack())
        .is_none());
    assert!(matches!(
        f.storage.cell(&point(&f), true),
        CellStatus::Unknown
    ));
    assert!(matches!(
        f.service.fetch_transaction(&f.hash),
        FetchStatus::Added { .. }
    ));
    assert!(f
        .service
        .get_header(&original.calc_header_hash().unpack())
        .is_some());
    f = f.reopen();
    assert!(f
        .storage
        .get_transaction_with_header(&f.hash.pack())
        .is_none());
}

#[tokio::test]
async fn legacy_height_only_record_requires_proof_before_fetch_completion_and_resolution() {
    let mut f = Fixture::new(false, false).await;
    f.storage.add_fetched_tx(&transaction(&f), &inclusion(&f));
    assert_eq!(status(&f)["status"], "unknown");
    assert!(f.service.get_transaction(&f.hash).transaction.is_some());
    assert!(!matches!(
        f.service.fetch_transaction(&f.hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        f.storage.cell(&point(&f), true),
        CellStatus::Unknown
    ));
    f.receive().await;
    assert_eq!(status(&f)["status"], "committed");
    assert_eq!(f.storage.get_transaction(&f.hash.pack()).unwrap().1, 0);
}

#[tokio::test]
async fn ordinary_verified_parent_extension_preserves_membership_without_refetch() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let before = f.context.sent_messages().borrow().len();
    let extended = f
        .anchor
        .clone()
        .as_advanced_builder()
        .number(3u64)
        .parent_hash(f.anchor.hash())
        .build();
    f.storage.update_last_state(
        &U256::from(4u64),
        &extended.data(),
        std::slice::from_ref(&f.anchor),
    );
    for _ in 0..20 {
        assert!(matches!(
            f.service.fetch_transaction(&f.hash),
            FetchStatus::Fetched { .. }
        ));
        f.protocol.notify(f.context.context(), 1).await;
    }
    assert_eq!(status(&f)["status"], "committed");
    assert_eq!(f.context.sent_messages().borrow().len(), before);
}

#[tokio::test]
async fn old_response_is_accepted_after_proved_extension_not_after_unknown_fork_or_rollback() {
    for change in 0..4 {
        let mut f = Fixture::new(false, false).await;
        let (next, recent) = if change == 0 {
            (
                f.anchor
                    .clone()
                    .as_advanced_builder()
                    .number(3u64)
                    .parent_hash(f.anchor.hash())
                    .build(),
                vec![f.anchor.clone()],
            )
        } else {
            let n = match change {
                1 => 2,
                2 => 1,
                _ => 3,
            };
            (
                f.anchor
                    .clone()
                    .as_advanced_builder()
                    .number(n)
                    .nonce(123u128)
                    .parent_hash(packed::Byte32::new([55; 32]))
                    .build(),
                vec![],
            )
        };
        f.storage
            .update_last_state(&U256::from(4u64), &next.data(), &recent);
        f.receive().await;
        assert_eq!(
            status(&f)["status"],
            if change == 0 { "committed" } else { "unknown" }
        );
        assert!(
            f.context.not_banned(f.peer),
            "old response is not a peer fault"
        );
        if change != 0 {
            assert!(!fetch_info(&f, &f.hash, false).2);
        }
    }
}

#[tokio::test]
async fn delayed_negative_transaction_response_cannot_mark_new_chain_fetch_missing() {
    let mut f = Fixture::new(false, false).await;
    f.message = packed::LightClientMessage::new_builder()
        .set(
            packed::SendTransactionsProofV1::new_builder()
                .last_header(payload(&f).last_header())
                .missing_tx_hashes(vec![f.hash.pack()].pack())
                .build(),
        )
        .build();
    let next = f
        .anchor
        .clone()
        .as_advanced_builder()
        .nonce(333u128)
        .build();
    f.storage
        .update_last_state(&U256::from(4u64), &next.data(), &[]);
    f.receive().await;
    assert!(!fetch_info(&f, &f.hash, false).2);
}

#[tokio::test]
async fn delayed_header_positive_and_negative_cannot_recreate_old_membership_or_missing_claim() {
    for missing in [false, true] {
        let mut f = Fixture::new(false, false).await;
        let p = payload(&f);
        let header = inclusion(&f).header;
        let hash = header.calc_header_hash();
        f.service.fetch_header(&hash.unpack());
        f.protocol.notify(f.context.context(), 1).await;
        let response = if missing {
            packed::SendBlocksProofV1::new_builder()
                .last_header(p.last_header())
                .missing_block_hashes(vec![hash.clone()].pack())
                .build()
        } else {
            packed::SendBlocksProofV1::new_builder()
                .last_header(p.last_header())
                .proof(p.proof())
                .headers(vec![header].pack())
                .blocks_uncles_hash(p.blocks_uncles_hash())
                .blocks_extension(p.blocks_extension())
                .build()
        };
        f.message = packed::LightClientMessage::new_builder()
            .set(response)
            .build();
        let next = f
            .anchor
            .clone()
            .as_advanced_builder()
            .nonce(333u128)
            .build();
        f.storage
            .update_last_state(&U256::from(4u64), &next.data(), &[]);
        f.receive().await;
        assert!(f.storage.get_block_hash(1).is_none());
        assert!(!fetch_info(&f, &hash.unpack(), true).2);
    }
}

#[tokio::test]
async fn invalid_mmr_and_merkle_never_create_transaction_or_membership() {
    for (mmr, merkle) in [(true, false), (false, true)] {
        let mut f = Fixture::new(mmr, merkle).await;
        f.receive().await;
        assert!(f.storage.get_transaction(&f.hash.pack()).is_none());
        assert!(
            f.context.not_banned(f.peer)
                || f.context
                    .banned_since(f.peer, protocols::StatusCode::InvalidProof)
        );
        assert!(f.storage.get_block_hash(1).is_none());
        assert_eq!(status(&f)["status"], "unknown");
    }
}

#[tokio::test]
async fn watched_queries_require_bound_history_and_rollback_removes_cells() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let q = queries(&f);
    assert_eq!(
        q.get_cells(key(), Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        1
    );
    assert_eq!(
        q.get_transactions(key(), Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        1
    );
    let mut grouped = key();
    grouped.group_by_transaction = Some(true);
    assert_eq!(
        q.get_transactions(grouped, Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        1
    );
    assert_eq!(q.get_cells_capacity(key()).unwrap().capacity.value(), 100);
    f.storage.rollback_to_block(1);
    assert!(q
        .get_cells(key(), Order::Asc, 100u32.into(), None)
        .unwrap()
        .objects
        .is_empty());
    assert_eq!(q.get_cells_capacity(key()).unwrap().capacity.value(), 0);
    assert_eq!(status(&f)["status"], "unknown");
}

#[tokio::test]
async fn unknown_continuity_revokes_old_membership_and_blocks_watched_claims_until_explicit_reindex(
) {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let next = f
        .anchor
        .clone()
        .as_advanced_builder()
        .number(3u64)
        .parent_hash(packed::Byte32::new([19; 32]))
        .build();
    f.storage
        .update_last_state(&U256::from(4u64), &next.data(), &[]);
    assert_eq!(status(&f)["status"], "unknown");
    let q = queries(&f);
    assert!(q.get_cells(key(), Order::Asc, 100u32.into(), None).is_err());
    assert!(q
        .get_transactions(key(), Order::Asc, 100u32.into(), None)
        .is_err());
    assert!(q.get_cells_capacity(key()).is_err());
    // No destructive automatic migration: raw historical bytes and index persist.
    assert!(f
        .storage
        .get(Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec())
        .unwrap()
        .is_some());
    assert!(f.storage.get_transaction(&f.hash.pack()).is_some());
    register(&f); // Ordinary registration cannot erase continuity uncertainty.
    assert!(q.get_cells_capacity(key()).is_err());
    assert!(f.storage.get_transaction(&f.hash.pack()).is_some());
}

#[tokio::test]
async fn pending_pool_is_not_promoted_to_committed_by_cached_bytes() {
    let f = Fixture::new(false, false).await;
    let tx = transaction(&f).into_view();
    let pending = Arc::new(std::sync::RwLock::new(PendingTxs::new(16)));
    pending.write().unwrap().push(tx, 12);
    f.storage.add_fetched_tx(&transaction(&f), &inclusion(&f));
    let service = LightClientChainService::new(
        StorageWithChainData::new(f.storage, f.peers, pending),
        Arc::new(ConsensusBuilder::default().build()),
    );
    assert_eq!(
        serde_json::to_value(service.get_transaction(&f.hash)).unwrap()["tx_status"]["status"],
        "pending"
    );
    assert!(matches!(
        service.fetch_transaction(&f.hash),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test]
async fn corrupted_or_missing_binding_never_produces_committed_or_a_zero_watched_balance() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let mut binding_key = Key::Meta("TX_BLOCK_V1:").into_vec();
    binding_key.extend_from_slice(f.hash.as_bytes());
    for value in [vec![], vec![1], vec![1; 41]] {
        f.storage.put(binding_key.clone(), value).unwrap();
        assert_eq!(status(&f)["status"], "unknown");
        assert!(queries(&f).get_cells_capacity(key()).is_err());
    }
    f.storage.delete(&binding_key).unwrap();
    assert_eq!(status(&f)["status"], "unknown");
    assert!(queries(&f).get_cells_capacity(key()).is_err());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn receipt_batch_failure_retains_queue_and_never_partially_persists_proved_transaction() {
    let mut f = Fixture::new(false, false).await;
    let connection = rusqlite::Connection::open(f._directory.path().join("db.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_association BEFORE INSERT ON kv_store WHEN hex(NEW.key) LIKE 'E054585F424C4F434B5F56313A%' BEGIN SELECT RAISE(ABORT,'injected binding failure'); END;").unwrap();
    f.receive().await;
    assert!(f.storage.get_transaction(&f.hash.pack()).is_none());
    assert!(f.storage.get_block_hash(1).is_none());
    assert!(f.peers.fetching_txs().get(&f.hash.pack()).is_some());
    assert!(f.context.not_banned(f.peer));
    connection
        .execute_batch("DROP TRIGGER fail_association;")
        .unwrap();
    f.protocol.notify(f.context.context(), 1).await;
    let state_key = Key::Meta("LAST_STATE").into_vec();
    let state = f.storage.get(state_key.clone()).unwrap().unwrap();
    f.storage.put(state_key.clone(), vec![0]).unwrap();
    f.receive().await; // A local anchor-read failure must retain retryable work too.
    f.storage.put(state_key, state).unwrap();
    f.protocol.notify(f.context.context(), 1).await;
    f.receive().await;
    assert_eq!(status(&f)["status"], "committed");
    assert!(f.context.not_banned(f.peer));
}

#[tokio::test]
async fn interrupted_transition_marker_survives_restart_and_fails_closed() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    f.storage
        .put(Key::Meta("CHAIN_TRANSITION_V1").into_vec(), vec![1])
        .unwrap();
    f = f.reopen();
    assert!(f
        .storage
        .get_transaction_with_header(&f.hash.pack())
        .is_none());
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    assert_eq!(status(&f)["status"], "unknown");
    let next = f
        .anchor
        .clone()
        .as_advanced_builder()
        .number(3u64)
        .parent_hash(f.anchor.hash())
        .build();
    f.storage.update_last_state(
        &U256::from(4u64),
        &next.data(),
        std::slice::from_ref(&f.anchor),
    );
    assert_eq!(
        status(&f)["status"],
        "unknown",
        "a later extension cannot erase interrupted rollback uncertainty"
    );
    assert!(queries(&f).get_cells_capacity(key()).is_err());
}

impl Fixture {
    fn reopen(self) -> Self {
        let Self {
            _directory,
            storage,
            service,
            protocol,
            context,
            peer,
            hash,
            message,
            anchor,
            peers,
            extra_block,
            containing_block,
        } = self;
        drop(protocol);
        drop(service);
        drop(storage);
        drop(peers);
        // RocksDB requires all old handles closed. Start with no peer state or pending pool.
        let storage = Storage::new(_directory.path());
        let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
        let service = LightClientChainService::new(
            StorageWithChainData::new(storage.clone(), peers.clone(), Default::default()),
            Arc::new(ConsensusBuilder::default().build()),
        );
        let protocol = LightClientProtocol::new(
            storage.clone(),
            peers.clone(),
            ConsensusBuilder::default().build(),
        );
        Self {
            _directory,
            storage,
            service,
            protocol,
            context,
            peer,
            hash,
            message,
            anchor,
            peers,
            extra_block,
            containing_block,
        }
    }
    async fn new(invalid_mmr: bool, invalid_merkle: bool) -> Self {
        Self::chain(invalid_mmr, invalid_merkle, false).await
    }
    async fn chain(invalid_mmr: bool, invalid_merkle: bool, spend: bool) -> Self {
        Self::chain_case(invalid_mmr, invalid_merkle, spend, false).await
    }
    async fn chain_case(invalid_mmr: bool, invalid_merkle: bool, spend: bool, multi: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path());
        let consensus: Consensus = ConsensusBuilder::default().build();
        storage.init_genesis_block(consensus.genesis_block().data().clone());
        let genesis = consensus.genesis_block().header();
        let tx = core::TransactionBuilder::default()
            .output(
                packed::CellOutput::new_builder()
                    .capacity(100u64)
                    .lock(watched_script())
                    .build(),
            )
            .output_data(packed::Bytes::default())
            .build();
        let mut transactions = vec![];
        if multi {
            transactions.push(
                core::TransactionBuilder::default()
                    .input(packed::CellInput::new_cellbase_input(1))
                    .witness(packed::Bytes::default())
                    .output(packed::CellOutput::default())
                    .output_data(packed::Bytes::default())
                    .build(),
            );
        }
        transactions.push(tx.clone());
        let block = core::BlockBuilder::default()
            .number(1u64)
            .parent_hash(genesis.hash())
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
            .transactions(transactions)
            .build();
        let extra_block = spend.then(|| {
            let spending = core::TransactionBuilder::default()
                .input(
                    packed::CellInput::new_builder()
                        .previous_output(packed::OutPoint::new(tx.hash(), 0))
                        .build(),
                )
                .output(packed::CellOutput::new_builder().capacity(90u64).build())
                .output_data(packed::Bytes::default())
                .build();
            core::BlockBuilder::default()
                .number(2u64)
                .parent_hash(block.hash())
                .compact_target(genesis.compact_target())
                .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
                .transaction(spending)
                .build()
        });
        let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
        mmr.push(genesis.digest()).unwrap();
        mmr.push(block.header().digest()).unwrap();
        if let Some(extra) = &extra_block {
            mmr.push(extra.header().digest()).unwrap();
        }
        let root = mmr.get_root().unwrap();
        let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
        let extra =
            core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()));
        let anchor = core::HeaderBuilder::default()
            .number(if spend { 3u64 } else { 2u64 })
            .parent_hash(
                extra_block
                    .as_ref()
                    .map(|b| b.hash())
                    .unwrap_or_else(|| block.hash()),
            )
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(
                0,
                if spend { 3 } else { 2 },
                100,
            ))
            .extra_hash(extra.extra_hash())
            .build();
        let verifiable = VerifiableHeader::new(
            anchor.clone(),
            packed::Byte32::zero(),
            Some(extension),
            root,
        );
        let mut proof = mmr
            .gen_proof(vec![leaf_index_to_pos(1)])
            .unwrap()
            .proof_items()
            .to_vec();
        if invalid_mmr {
            proof[0] = proof[0]
                .clone()
                .as_builder()
                .children_hash(packed::Byte32::new([17; 32]))
                .build();
        }
        let hashes = block
            .transactions()
            .iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let tx_proof =
            ckb_types::utilities::CBMT::build_merkle_proof(&hashes, &[u32::from(multi)]).unwrap();
        let filtered = packed::FilteredBlock::new_builder()
            .header(block.header().data())
            .witnesses_root(if invalid_merkle {
                packed::Byte32::new([18; 32])
            } else {
                block.calc_witnesses_root()
            })
            .transactions(vec![tx.data()].pack())
            .proof(
                packed::MerkleProof::new_builder()
                    .indices(tx_proof.indices().to_vec().pack())
                    .lemmas(tx_proof.lemmas().to_vec().pack())
                    .build(),
            )
            .build();
        let content = packed::SendTransactionsProofV1::new_builder()
            .last_header(
                packed::VerifiableHeader::new_builder()
                    .header(verifiable.header().data())
                    .uncles_hash(verifiable.uncles_hash())
                    .extension(
                        packed::BytesOpt::new_builder()
                            .set(verifiable.extension())
                            .build(),
                    )
                    .parent_chain_root(verifiable.parent_chain_root())
                    .build(),
            )
            .proof(proof.pack())
            .filtered_blocks(vec![filtered])
            .blocks_uncles_hash(vec![block.calc_uncles_hash()].pack())
            .blocks_extension(vec![packed::BytesOpt::default()])
            .build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        storage.update_last_state(&U256::from(3u64), &anchor.data(), &[]);
        let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
        let peer = PeerIndex::new(1);
        peers.add_peer(peer);
        let state = LastState::new(verifiable);
        let request = ProveRequest::new(state.clone(), Default::default());
        peers.request_last_state(peer).unwrap();
        peers.update_last_state(peer, state).unwrap();
        peers.update_prove_request(peer, request.clone()).unwrap();
        peers
            .update_prove_state(peer, ProveState::new_from_request(request, vec![], vec![]))
            .unwrap();
        let swc = StorageWithChainData::new(
            storage.clone(),
            peers.clone(),
            Arc::new(std::sync::RwLock::new(PendingTxs::new(16))),
        );
        let service = LightClientChainService::new(swc, Arc::new(consensus.clone()));
        let hash = tx.hash().unpack();
        assert!(matches!(
            service.fetch_transaction(&hash),
            FetchStatus::Added { .. }
        ));
        let mut protocol = LightClientProtocol::new(storage.clone(), peers.clone(), consensus);
        let context = MockNetworkContext::new(SupportProtocols::LightClient);
        // Existing public scheduler; token 1 is FETCH_HEADER_TX_TOKEN.
        protocol.notify(context.context(), 1).await;
        assert!(!context.sent_messages().borrow().is_empty());
        Self {
            _directory: directory,
            storage,
            service,
            protocol,
            context,
            peer,
            hash,
            message,
            anchor,
            peers,
            extra_block,
            containing_block: block,
        }
    }
    async fn receive(&mut self) {
        self.protocol
            .received(self.context.context(), self.peer, self.message.as_bytes())
            .await;
    }
}

#[tokio::test]
async fn public_header_lookup_retains_verified_peer_header_availability() {
    let f = Fixture::new(false, false).await;
    let header = inclusion(&f).header.into_view();
    let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
    peers.add_peer(f.peer);
    let state = LastState::new(payload(&f).last_header().into());
    let request = ProveRequest::new(state.clone(), Default::default());
    peers.request_last_state(f.peer).unwrap();
    peers.update_last_state(f.peer, state).unwrap();
    peers.update_prove_request(f.peer, request.clone()).unwrap();
    // Explicitly trusted peer-state fixture, as in the existing upstream unit tests.
    peers
        .update_prove_state(
            f.peer,
            ProveState::new_from_request(request, vec![], vec![header.clone()]),
        )
        .unwrap();
    let service = LightClientChainService::new(
        StorageWithChainData::new(f.storage.clone(), peers, Default::default()),
        Arc::new(ConsensusBuilder::default().build()),
    );
    assert!(f.storage.get_header(&header.hash()).is_none());
    assert!(service.get_header(&header.hash().unpack()).is_some());
    assert!(matches!(
        service.fetch_header(&header.hash().unpack()),
        FetchStatus::Fetched { .. }
    ));
}
#[tokio::test]
async fn normal_script_registration_never_erases_retained_legacy_indexes() {
    let f = Fixture::new(false, false).await;
    let row = Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec();
    f.storage
        .put(row.clone(), f.hash.as_bytes().to_vec())
        .unwrap();
    f.storage
        .delete(&Key::Meta("INDEX_ASSOCIATIONS_V1").into_vec())
        .unwrap();
    register(&f);
    assert!(
        f.storage.get(row).unwrap().is_some(),
        "normal registration must not silently migrate a database"
    );
    assert!(queries(&f).get_cells_capacity(key()).is_err());
}

#[tokio::test]
async fn compact_merkle_tree_index_is_not_a_transaction_ordinal() {
    let mut f = Fixture::chain_case(false, false, false, true).await;
    assert_eq!(
        Unpack::<u32>::unpack(
            &payload(&f)
                .filtered_blocks()
                .get(0)
                .unwrap()
                .proof()
                .indices()
                .get(0)
                .unwrap()
        ),
        2u32
    );
    f.receive().await;
    assert_eq!(status(&f)["status"], "committed");
    let (_, index, _) = f.storage.get_transaction(&f.hash.pack()).unwrap();
    assert_eq!(
        index,
        u32::MAX,
        "a compact proof lacks the leaf count required to recover an ordinal"
    );
}

#[tokio::test]
async fn proof_refresh_preserves_an_ordinal_established_by_verified_body_indexing() {
    let mut f = Fixture::chain_case(false, false, false, true).await;
    f.receive().await;
    index_fixture(&f);
    assert_eq!(f.storage.get_transaction(&f.hash.pack()).unwrap().1, 1);
    StorageWithChainData::new(f.storage.clone(), f.peers.clone(), Default::default())
        .add_fetch_tx(f.hash.clone(), 1);
    f.protocol.notify(f.context.context(), 1).await;
    f.receive().await;
    assert_eq!(f.storage.get_transaction(&f.hash.pack()).unwrap().1, 1);
    assert_eq!(
        queries(&f)
            .get_cells_capacity(key())
            .unwrap()
            .capacity
            .value(),
        100
    );
}
#[tokio::test]
async fn verified_reinclusion_on_a_different_branch_rebinds_without_relabeling_old_bytes() {
    let mut old = Fixture::new(false, false).await;
    old.receive().await;
    let new = Fixture::chain_case(false, false, false, true).await;
    assert_ne!(
        inclusion(&old).header.calc_header_hash(),
        inclusion(&new).header.calc_header_hash()
    );
    old.storage
        .update_last_state(&U256::from(4u64), &new.anchor.data(), &[]);
    assert_eq!(status(&old)["status"], "unknown");
    let service = LightClientChainService::new(
        StorageWithChainData::new(old.storage.clone(), new.peers.clone(), Default::default()),
        Arc::new(ConsensusBuilder::default().build()),
    );
    let mut protocol = LightClientProtocol::new(
        old.storage.clone(),
        new.peers.clone(),
        ConsensusBuilder::default().build(),
    );
    protocol
        .received(new.context.context(), new.peer, new.message.as_bytes())
        .await;
    assert_eq!(
        service.get_transaction(&new.hash).tx_status.block_hash,
        Some(inclusion(&new).header.calc_header_hash().unpack())
    );
    // Drained historical response on the old handler cannot restore the old branch.
    old.receive().await;
    assert_eq!(
        service.get_transaction(&new.hash).tx_status.block_hash,
        Some(inclusion(&new).header.calc_header_hash().unpack())
    );
    assert!(old.context.not_banned(old.peer));
}
#[tokio::test]
async fn disconnect_requeues_the_existing_fetch_for_another_peer() {
    let mut f = Fixture::new(false, false).await;
    f.protocol.disconnected(f.context.context(), f.peer).await;
    let next = PeerIndex::new(2);
    f.peers.add_peer(next);
    let state = LastState::new(payload(&f).last_header().into());
    let request = ProveRequest::new(state.clone(), Default::default());
    f.peers.request_last_state(next).unwrap();
    f.peers.update_last_state(next, state).unwrap();
    f.peers.update_prove_request(next, request.clone()).unwrap();
    f.peers
        .update_prove_state(next, ProveState::new_from_request(request, vec![], vec![]))
        .unwrap();
    let sent = f.context.sent_messages().borrow().len();
    f.protocol.notify(f.context.context(), 1).await;
    assert!(f.context.sent_messages().borrow().len() > sent);
    f.protocol
        .received(f.context.context(), next, f.message.as_bytes())
        .await;
    assert_eq!(status(&f)["status"], "committed");
    assert!(f.context.not_banned(next));
}

#[tokio::test]
async fn compact_proof_of_cellbase_does_not_bypass_cellbase_classification() {
    let mut f = Fixture::chain_case(false, false, false, true).await;
    f.receive().await;
    let cellbase = f.containing_block.transactions()[0].clone();
    assert!(cellbase
        .data()
        .raw()
        .inputs()
        .get(0)
        .unwrap()
        .previous_output()
        .is_null());
    let hashes = f
        .containing_block
        .transactions()
        .iter()
        .map(|tx| tx.hash())
        .collect::<Vec<_>>();
    let proof = ckb_types::utilities::CBMT::build_merkle_proof(&hashes, &[0]).unwrap();
    assert_eq!(proof.indices(), &[1]);
    let filtered = payload(&f)
        .filtered_blocks()
        .get(0)
        .unwrap()
        .as_builder()
        .transactions(
            vec![cellbase
                .data()
                .as_builder()
                .witnesses(packed::BytesVec::default())
                .build()]
            .pack(),
        )
        .proof(
            packed::MerkleProof::new_builder()
                .indices(proof.indices().to_vec().pack())
                .lemmas(proof.lemmas().to_vec().pack())
                .build(),
        )
        .build();
    f.message = packed::LightClientMessage::new_builder()
        .set(
            payload(&f)
                .as_builder()
                .filtered_blocks(vec![filtered])
                .build(),
        )
        .build();
    f.hash = cellbase.hash().unpack();
    StorageWithChainData::new(f.storage.clone(), f.peers.clone(), Default::default())
        .add_fetch_tx(f.hash.clone(), 1);
    f.protocol.notify(f.context.context(), 1).await;
    f.receive().await;
    match f.storage.cell(&point(&f), true) {
        CellStatus::Live(cell) => assert_eq!(cell.transaction_info.unwrap().index, 0),
        _ => panic!("included cellbase must resolve with its cellbase classification"),
    }
}

#[tokio::test]
async fn cached_header_resolver_recovers_through_the_existing_proof_queue() {
    use ckb_traits::HeaderProvider;
    let mut f = Fixture::new(false, false).await;
    let hwe = inclusion(&f);
    let hash = hwe.header.calc_header_hash();
    f.storage.add_fetched_header(&hwe);
    let swc = StorageWithChainData::new(f.storage.clone(), f.peers.clone(), Default::default());
    assert!(f.service.get_header(&hash.unpack()).is_some());
    assert!(HeaderProvider::get_header(&swc, &hash).is_none());
    assert!(swc.get_header_fetch_info(&hash.unpack()).is_some());
    f.protocol.notify(f.context.context(), 1).await;
    let p = payload(&f);
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(p.last_header())
        .proof(p.proof())
        .headers(vec![hwe.header].pack())
        .blocks_uncles_hash(p.blocks_uncles_hash())
        .blocks_extension(p.blocks_extension())
        .build();
    f.protocol
        .received(
            f.context.context(),
            f.peer,
            packed::LightClientMessage::new_builder()
                .set(response)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(HeaderProvider::get_header(&swc, &hash).is_some());
}

#[tokio::test]
async fn indexing_a_verified_accepted_tip_persists_its_membership_with_the_association() {
    let f = Fixture::new(false, false).await;
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    storage.init_genesis_block(f.storage.get_genesis_block());
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: watched_script(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    // Explicit trusted accepted-header fixture; body is the original complete fixture block.
    storage.update_last_state(&U256::one(), &f.containing_block.header().data(), &[]);
    storage.filter_block(f.containing_block.data());
    assert!(storage
        .get_transaction_with_header(&f.hash.pack())
        .is_some());
    assert_eq!(storage.get_block_hash(1), Some(f.containing_block.hash()));
}

// Actual backend snapshots, with a deterministic index revision change after a
// successful transaction snapshot. This simulates a concurrent writer boundary.
struct WatchedReadProbe {
    storage: Storage,
    hash: packed::Byte32,
    reads: std::sync::atomic::AtomicUsize,
    revise: std::sync::atomic::AtomicBool,
}
impl StorageBackend for WatchedReadProbe {
    type Batch = <Storage as StorageBackend>::Batch;
    fn get(&self, key: Vec<u8>) -> ckb_light_client_lib::error::Result<Option<Vec<u8>>> {
        self.storage.get(key)
    }
    fn get_many(
        &self,
        keys: &[Vec<u8>],
    ) -> ckb_light_client_lib::error::Result<Vec<Option<Vec<u8>>>> {
        let rows = self.storage.get_many(keys)?;
        if keys.contains(&Key::TxHash(&self.hash).into_vec()) {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.revise.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.storage.put(
                    Key::Meta("INDEX_REVISION_V1").into_vec(),
                    999u64.to_be_bytes().to_vec(),
                )?;
            }
        }
        Ok(rows)
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> ckb_light_client_lib::error::Result<()> {
        self.storage.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> ckb_light_client_lib::error::Result<()> {
        self.storage.delete(key)
    }
    fn batch(&self) -> Self::Batch {
        self.storage.batch()
    }
    fn try_collect_iterator(
        &self,
        start: ckb_light_client_lib::storage::IteratorStart,
        direction: ckb_light_client_lib::storage::IteratorDirection,
        take: ckb_light_client_lib::storage::TakeWhileFn,
        filter: ckb_light_client_lib::storage::FilterMapFn,
        limit: usize,
    ) -> ckb_light_client_lib::error::Result<Vec<ckb_light_client_lib::storage::KVPair>> {
        self.storage
            .try_collect_iterator(start, direction, take, filter, limit)
    }
    fn collect_iterator(
        &self,
        start: ckb_light_client_lib::storage::IteratorStart,
        direction: ckb_light_client_lib::storage::IteratorDirection,
        take: ckb_light_client_lib::storage::TakeWhileFn,
        filter: ckb_light_client_lib::storage::FilterMapFn,
        limit: usize,
    ) -> Vec<ckb_light_client_lib::storage::KVPair> {
        self.storage
            .collect_iterator(start, direction, take, filter, limit)
    }
}
impl LightClientStorage for WatchedReadProbe {}
#[tokio::test]
async fn watched_transaction_reuse_is_bounded_to_one_public_query() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let probe = Arc::new(WatchedReadProbe {
        storage: f.storage.clone(),
        hash: f.hash.pack(),
        reads: Default::default(),
        revise: false.into(),
    });
    let service = LightClientService::new(probe.clone());
    assert_eq!(
        service
            .get_cells(key(), Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        1
    );
    assert_eq!(
        probe.reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "filtering and rendering reuse the validated transaction"
    );
    f.storage
        .put(Key::TxHash(&f.hash.pack()).into_vec(), vec![0])
        .unwrap();
    assert!(
        service
            .get_cells(key(), Order::Asc, 100u32.into(), None)
            .is_err(),
        "the next public call must read again"
    );
}
#[tokio::test]
async fn watched_transaction_reuse_cannot_mask_a_concurrent_index_revision() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let probe = Arc::new(WatchedReadProbe {
        storage: f.storage.clone(),
        hash: f.hash.pack(),
        reads: Default::default(),
        revise: true.into(),
    });
    let service = LightClientService::new(probe.clone());
    assert!(service
        .get_cells(key(), Order::Asc, 100u32.into(), None)
        .is_err());
    assert_eq!(probe.reads.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_scan_errors_cannot_become_zero_balance_or_empty_history() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let connection = rusqlite::Connection::open(f._directory.path().join("db.sqlite")).unwrap();
    // SQLite's non-STRICT BLOB column can contain a value with the wrong SQL type.
    // The old iterator silently skipped row conversion errors before callbacks ran.
    for row in [
        Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec(),
        Key::TxLockScript(
            &watched_script(),
            1,
            0,
            0,
            ckb_light_client_lib::storage::CellType::Output,
        )
        .into_vec(),
    ] {
        connection
            .execute(
                "UPDATE kv_store SET value = 'invalid blob' WHERE key = ?",
                [&row],
            )
            .unwrap();
    }
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    assert!(queries(&f)
        .get_cells(key(), Order::Asc, 100u32.into(), None)
        .is_err());
    for grouped in [false, true] {
        let mut search = key();
        search.group_by_transaction = Some(grouped);
        assert!(queries(&f)
            .get_transactions(search, Order::Asc, 100u32.into(), None)
            .is_err());
    }
    assert_eq!(
        connection
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM kv_store WHERE typeof(value) = 'text'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
        2
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_membership_scan_failure_cannot_publish_a_new_accepted_state() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let old = f.storage.get_last_state();
    let mut member = Key::Meta("CHAIN_BLOCK_V1:").into_vec();
    member.extend_from_slice(&1u64.to_be_bytes());
    let connection = rusqlite::Connection::open(f._directory.path().join("db.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE kv_store SET value = 'invalid blob' WHERE key = ?",
            [&member],
        )
        .unwrap();
    let next = f
        .anchor
        .clone()
        .as_advanced_builder()
        .nonce(123u128)
        .build();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.storage
            .update_last_state(&U256::from(4u64), &next.data(), &[]);
    }))
    .is_err());
    assert_eq!(f.storage.get_last_state().0, old.0);
    assert_eq!(f.storage.get_tip_header().as_slice(), old.1.as_slice());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn legacy_infallible_status_fails_closed_on_storage_error_without_erasing_data() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    let connection = rusqlite::Connection::open(f._directory.path().join("db.sqlite")).unwrap();
    connection
        .execute_batch("ALTER TABLE kv_store RENAME TO unavailable_store")
        .unwrap();
    assert_eq!(status(&f)["status"], "unknown");
    assert!(matches!(
        f.service.fetch_transaction(&f.hash),
        FetchStatus::Added { .. }
    ));
    connection
        .execute_batch("ALTER TABLE unavailable_store RENAME TO kv_store")
        .unwrap();
    assert_eq!(status(&f)["status"], "committed");
}

#[tokio::test]
async fn legacy_watched_error_has_a_recognizable_recovery_prefix() {
    let f = Fixture::new(false, false).await;
    f.storage
        .delete(&Key::Meta("INDEX_ASSOCIATIONS_V1").into_vec())
        .unwrap();
    let message = queries(&f)
        .get_cells_capacity(key())
        .err()
        .expect("legacy watched query must fail")
        .to_string();
    assert!(message.starts_with("runtime error: canonical_state:rebuild_required:"));
    assert!(message.contains("separate database"));
    assert!(!message.contains("all-scripts"));
}

#[tokio::test]
async fn registration_after_interrupted_rollback_preserves_data_and_returns_recovery_errors() {
    let mut f = Fixture::new(false, false).await;
    f.receive().await;
    index_fixture(&f);
    let row = Key::CellLockScript(&watched_script(), 1, 0, 0).into_vec();
    f.storage
        .put(Key::Meta("CHAIN_TRANSITION_V1").into_vec(), vec![1])
        .unwrap();
    f = f.reopen();
    // Normal startup registration must not panic while trying to filter genesis
    // through a rollback fence. It must not clear that fence or erase old rows.
    register(&f);
    assert!(f.storage.get(row).unwrap().is_some());
    assert!(f.storage.get_transaction(&f.hash.pack()).is_some());
    assert!(queries(&f).get_cells_capacity(key()).is_err());
    assert!(f
        .storage
        .get(Key::Meta("CHAIN_TRANSITION_V1").into_vec())
        .unwrap()
        .is_some());
}
