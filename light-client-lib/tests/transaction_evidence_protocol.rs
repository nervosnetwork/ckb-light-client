//! Deterministic protocol tests: an explicitly trusted fixture anchor and DummyPoW
//! consensus, with real response PoW/MMR/Merkle processing. Not a real-chain reorg.
#![cfg(not(target_arch = "wasm32"))]
use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
pub use ckb_light_client_lib::protocols;
use ckb_light_client_lib::{
    protocols::{LastState, LightClientProtocol, Peers, PendingTxs, ProveRequest, ProveState},
    service::{FetchStatus, LightClientChainService, TransactionEvidenceState},
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
}

impl Fixture {
    async fn new(invalid_mmr: bool, invalid_merkle: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path());
        let consensus: Consensus = ConsensusBuilder::default().build();
        storage.init_genesis_block(consensus.genesis_block().data().clone());
        let genesis = consensus.genesis_block().header();
        let tx = core::TransactionBuilder::default()
            .output(packed::CellOutput::new_builder().capacity(100u64).build())
            .output_data(packed::Bytes::default())
            .build();
        let block = core::BlockBuilder::default()
            .number(1u64)
            .parent_hash(genesis.hash())
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
            .transaction(tx.clone())
            .build();
        let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
        mmr.push(genesis.digest()).unwrap();
        mmr.push(block.header().digest()).unwrap();
        let root = mmr.get_root().unwrap();
        let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
        let extra =
            core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()));
        let anchor = core::HeaderBuilder::default()
            .number(2u64)
            .parent_hash(block.hash())
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
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
                    .indices([0u32].pack())
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
            service.fetch_transaction_evidence(&hash).unwrap(),
            FetchStatus::Added { .. }
        ));
        let mut protocol = LightClientProtocol::new(storage.clone(), peers, consensus);
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
        }
    }
    async fn receive(&mut self) {
        self.protocol
            .received(self.context.context(), self.peer, self.message.as_bytes())
            .await;
    }
}

#[tokio::test]
async fn successful_protocol_response_creates_bound_receipt_and_legacy_status() {
    let mut fixture = Fixture::new(false, false).await;
    fixture.receive().await;
    assert!(fixture.context.not_banned(fixture.peer));
    let evidence = fixture
        .service
        .get_transaction_evidence(&fixture.hash)
        .unwrap();
    assert_eq!(evidence.state, TransactionEvidenceState::VerifiedCurrent);
    assert_eq!(
        evidence.proof_anchor_hash,
        Some(fixture.anchor.hash().unpack())
    );
    assert_eq!(evidence.block_number.unwrap().value(), 1);
    assert!(matches!(
        fixture
            .service
            .fetch_transaction_evidence(&fixture.hash)
            .unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture
        .service
        .get_transaction(&fixture.hash)
        .transaction
        .is_some());
    assert_eq!(
        serde_json::to_value(fixture.service.get_transaction(&fixture.hash)).unwrap()["tx_status"]
            ["status"],
        "committed"
    );
    let before = fixture.context.sent_messages().borrow().len();
    for _ in 0..30 {
        assert!(matches!(
            fixture
                .service
                .fetch_transaction_evidence(&fixture.hash)
                .unwrap(),
            FetchStatus::Fetched { .. }
        ));
        fixture.protocol.notify(fixture.context.context(), 1).await;
    }
    assert_eq!(
        fixture.context.sent_messages().borrow().len(),
        before,
        "unchanged anchor must not refetch"
    );
}

#[tokio::test]
async fn local_pending_is_not_proof_or_fetch_completion() {
    let fixture = Fixture::new(false, false).await;
    let peers = Arc::new(Peers::new(2, 2000, (0, packed::Byte32::zero()), 10));
    let pending = Arc::new(std::sync::RwLock::new(PendingTxs::new(16)));
    let tx = core::TransactionBuilder::default().version(99u32).build();
    pending.write().unwrap().push(tx.clone(), 0);
    let swc = StorageWithChainData::new(fixture.storage, peers, pending);
    let service = LightClientChainService::new(swc, Arc::new(ConsensusBuilder::default().build()));
    let hash = tx.hash().unpack();
    let observation = service.get_transaction_evidence(&hash).unwrap();
    assert_eq!(observation.state, TransactionEvidenceState::LocalPending);
    assert!(matches!(
        service.fetch_transaction_evidence(&hash).unwrap(),
        FetchStatus::Added { .. }
    ));
    assert_eq!(
        serde_json::to_value(service.get_transaction(&hash)).unwrap()["tx_status"]["status"],
        "pending"
    );
}

#[tokio::test]
async fn invalid_mmr_and_merkle_responses_never_create_receipts() {
    for (mmr, merkle) in [(true, false), (false, true)] {
        let mut fixture = Fixture::new(mmr, merkle).await;
        fixture.receive().await;
        if fixture.context.has_banned(fixture.peer).is_some() {
            assert!(fixture
                .context
                .banned_since(fixture.peer, protocols::StatusCode::InvalidProof));
        }
        assert_eq!(
            fixture
                .service
                .get_transaction_evidence(&fixture.hash)
                .unwrap()
                .state,
            TransactionEvidenceState::Unknown
        );
        assert!(fixture
            .storage
            .get_transaction(&fixture.hash.pack())
            .is_none());
    }
}

#[tokio::test]
async fn wrong_transaction_hash_and_inclusion_height_cannot_create_receipts() {
    for wrong_hash in [true, false] {
        let mut fixture = Fixture::new(false, false).await;
        let payload = packed::SendTransactionsProofV1::from_compatible_slice(
            fixture.message.to_enum().as_slice(),
        )
        .unwrap();
        let block = payload.filtered_blocks().get(0).unwrap();
        let changed = if wrong_hash {
            let tx = block
                .transactions()
                .get(0)
                .unwrap()
                .into_view()
                .as_advanced_builder()
                .version(77u32)
                .build();
            block
                .as_builder()
                .transactions(vec![tx.data()].pack())
                .build()
        } else {
            let header = block
                .header()
                .into_view()
                .as_advanced_builder()
                .number(99u64)
                .build();
            block.as_builder().header(header.data()).build()
        };
        fixture.message = packed::LightClientMessage::new_builder()
            .set(payload.as_builder().filtered_blocks(vec![changed]).build())
            .build();
        fixture.receive().await;
        assert_eq!(
            fixture
                .service
                .get_transaction_evidence(&fixture.hash)
                .unwrap()
                .state,
            TransactionEvidenceState::Unknown
        );
    }
}

#[tokio::test]
async fn late_valid_response_for_old_anchor_is_stale_at_new_accepted_anchor() {
    let mut fixture = Fixture::new(false, false).await;
    let replacement = fixture
        .anchor
        .clone()
        .as_advanced_builder()
        .nonce(123u128)
        .build();
    fixture
        .storage
        .update_last_state(&U256::from(4u64), &replacement.data(), &[]);
    fixture.receive().await;
    let evidence = fixture
        .service
        .get_transaction_evidence(&fixture.hash)
        .unwrap();
    assert_eq!(
        evidence.state,
        TransactionEvidenceState::VerifiedOtherAnchor
    );
    assert_ne!(
        evidence.proof_anchor_hash,
        Some(replacement.hash().unpack())
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn failed_receipt_commit_does_not_panic_or_complete_fetch_and_can_retry() {
    let mut fixture = Fixture::new(false, false).await;
    let connection =
        rusqlite::Connection::open(fixture._directory.path().join("db.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON kv_store WHEN hex(NEW.key) LIKE 'E054585F50524F4F465F56313A%' BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;").unwrap();
    fixture.receive().await;
    assert_eq!(
        fixture
            .service
            .get_transaction_evidence(&fixture.hash)
            .unwrap()
            .state,
        TransactionEvidenceState::Unknown
    );
    assert!(
        fixture.context.not_banned(fixture.peer),
        "local storage errors must not blame the peer"
    );
    connection
        .execute_batch("DROP TRIGGER fail_receipt;")
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .fetch_transaction_evidence(&fixture.hash)
            .unwrap(),
        FetchStatus::Added { .. }
    ));
    fixture.protocol.notify(fixture.context.context(), 1).await;
    fixture.receive().await;
    assert_eq!(
        fixture
            .service
            .get_transaction_evidence(&fixture.hash)
            .unwrap()
            .state,
        TransactionEvidenceState::VerifiedCurrent
    );
}
