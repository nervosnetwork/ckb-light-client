use crate::{
    protocols::{FilterProtocol, SyncProtocol},
    storage::{LightClientStorage, Storage, StorageWithChainData},
    tests::utils::MockNetworkContext,
};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_network::{CKBProtocolHandler, PeerIndex};
use ckb_systemtime::faketime;
use ckb_types::{packed, prelude::*};
use std::sync::Arc;

// A scan error must not be confused with an empty script/range set.
struct FailedScan(Storage);
impl crate::storage::StorageBackend for FailedScan {
    type Batch = <Storage as crate::storage::StorageBackend>::Batch;
    fn get(&self, key: Vec<u8>) -> crate::error::Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> crate::error::Result<()> {
        self.0.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> crate::error::Result<()> {
        self.0.delete(key)
    }
    fn batch(&self) -> Self::Batch {
        self.0.batch()
    }
    fn collect_iterator(
        &self,
        start: crate::storage::IteratorStart,
        direction: crate::storage::IteratorDirection,
        take: crate::storage::TakeWhileFn,
        filter: crate::storage::FilterMapFn,
        limit: usize,
    ) -> Vec<crate::storage::KVPair> {
        self.0
            .collect_iterator(start, direction, take, filter, limit)
    }
    fn try_collect_iterator(
        &self,
        _: crate::storage::IteratorStart,
        _: crate::storage::IteratorDirection,
        _: crate::storage::TakeWhileFn,
        _: crate::storage::FilterMapFn,
        _: usize,
    ) -> crate::error::Result<Vec<crate::storage::KVPair>> {
        Err(crate::error::Error::runtime("injected scan failure"))
    }
}
impl LightClientStorage for FailedScan {}

#[test]
fn failed_scan_cannot_publish_range_completion_or_empty_recovery() {
    use crate::storage::{ScriptStatus, ScriptType, SetScriptsCommand};
    let f = Fixture::new();
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script: packed::Script::default(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    f.storage
        .add_positioned_matched_blocks(1, 1, vec![(1, f.block.hash())]);
    let fault = FailedScan(f.storage.clone());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::storage::canonical::finish_index(&fault, 1, 1).unwrap()
    }))
    .is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || fault.get_earliest_matched_blocks()
    ))
    .is_err());
    assert_eq!(f.storage.get_filter_scripts()[0].block_number, 0);
    assert!(f.storage.get_earliest_matched_blocks().is_some());
}

#[allow(dead_code)]
#[path = "../../../../tests/support/request_fixture.rs"]
mod request_fixture;
use request_fixture::{Fixture, Kind};

async fn recover(f: &mut Fixture) {
    let mut filter = FilterProtocol::new(f.storage.clone(), f.peers.clone());
    filter.notify(f.context.context(), 0).await;
}

async fn prepare() -> Fixture {
    let mut f = Fixture::new();
    f.storage
        .add_positioned_matched_blocks(1, 1, vec![(1, f.block.hash())]);
    f.storage.update_min_filtered_block_number(1);
    recover(&mut f).await;
    assert!(f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .unwrap()
        .should_get_blocks());
    f
}

#[tokio::test]
async fn peer_miss_retains_pending_coverage_and_retry_completes() {
    let clock = faketime();
    clock.set_faketime(100_000);
    let mut f = prepare().await;
    let miss = f.negative(Kind::Header, f.wire.clone(), vec![f.block.hash()]);
    f.receive(miss).await;
    assert!(
        f.peers
            .matched_blocks()
            .read()
            .await
            .contains_key(&f.block.hash().unpack()),
        "peer miss erased pending watched coverage"
    );
    assert!(f.storage.get_earliest_matched_blocks().is_some());
    let mut sync = SyncProtocol::new(f.storage.clone(), f.peers.clone());
    let body = packed::SyncMessage::new_builder()
        .set(
            packed::SendBlock::new_builder()
                .block(f.block.data())
                .build(),
        )
        .build();
    sync.received(f.context.context(), f.peer, body.as_bytes())
        .await;
    assert!(
        f.storage.get_earliest_matched_blocks().is_some(),
        "unproved body completed a range"
    );
    // A different proved peer can retry immediately; a peer miss isn't global.
    let survivor = PeerIndex::new(2);
    f.peers.add_peer(survivor);
    f.peers
        .mock_prove_state(survivor, f.wire.clone().into())
        .unwrap();
    f.protocol.notify(f.context.context(), 2).await;
    assert!(
        f.peers
            .get_peer(&survivor)
            .unwrap()
            .get_blocks_proof_request()
            .is_some(),
        "surviving peer was prevented from retrying"
    );
    let proof = f.positive(Kind::Header, f.wire.clone(), false);
    f.protocol
        .received(f.context.context(), survivor, proof.as_bytes())
        .await;
    sync.received(f.context.context(), survivor, body.as_bytes())
        .await;
    assert!(f.storage.get_earliest_matched_blocks().is_none());
}

#[tokio::test]
async fn all_missing_filter_recovery_and_old_cache_absence_retain_ranges() {
    let mut f = Fixture::new();
    f.storage
        .add_positioned_matched_blocks(1, 1, vec![(1, f.block.hash())]);
    f.peers.mark_fetching_headers_missing(&[f.block.hash()]);
    recover(&mut f).await;
    assert!(
        f.storage.get_earliest_matched_blocks().is_some(),
        "all-missing filter recovery deleted durable work"
    );
    assert!(f
        .peers
        .matched_blocks()
        .read()
        .await
        .contains_key(&f.block.hash().unpack()));
    // Header-cache absence after a long downtime is not fork evidence.
    let tip = f
        .wire
        .header()
        .into_view()
        .as_advanced_builder()
        .number(2000u64)
        .build();
    f.storage
        .update_last_state(&ckb_types::U256::from(2001u64), &tip.data(), &[]);
    f.storage.cleanup_invalid_matched_blocks();
    assert!(
        f.storage.get_earliest_matched_blocks().is_some(),
        "age/cache cleanup erased pending coverage"
    );
}

#[tokio::test]
async fn missing_range_reopens_and_retry_backoff_expires() {
    let clock = faketime();
    clock.set_faketime(100_000);
    let mut f = prepare().await;
    f.receive(f.negative(Kind::Header, f.wire.clone(), vec![f.block.hash()]))
        .await;
    f.protocol.notify(f.context.context(), 2).await;
    assert!(
        f.peers
            .get_peer(&f.peer)
            .unwrap()
            .get_blocks_proof_request()
            .is_none(),
        "missing peer was retried without backoff"
    );
    clock.set_faketime(160_001);
    f.protocol.notify(f.context.context(), 2).await;
    assert!(
        f.peers
            .get_peer(&f.peer)
            .unwrap()
            .get_blocks_proof_request()
            .is_some(),
        "missing peer never became retryable"
    );
    let verified = f.positive(Kind::Header, f.wire.clone(), false);
    f.receive(verified).await;
    // Committed block indexing with its completion batch not yet run models
    // interruption at that durable boundary. The range must still be replayable.
    f.storage.filter_block(f.block.data());
    assert!(f.storage.get_earliest_matched_blocks().is_some());
    let Fixture {
        _directory,
        storage,
        service,
        protocol,
        peers,
        context,
        peer,
        block,
        wire,
        proof,
    } = f;
    drop((storage, service, protocol, peers, context));
    let mut reopened = Fixture::new();
    let storage = Storage::new(_directory.path());
    let consensus = ConsensusBuilder::default().build();
    storage.init_genesis_block(consensus.genesis_block().data());
    reopened.protocol = crate::protocols::LightClientProtocol::new(
        storage.clone(),
        reopened.peers.clone(),
        consensus.clone(),
    );
    reopened.service = crate::service::LightClientChainService::new(
        StorageWithChainData::new(storage.clone(), reopened.peers.clone(), Default::default()),
        Arc::new(consensus),
    );
    reopened.storage = storage;
    reopened.peer = peer;
    reopened.block = block;
    reopened.wire = wire;
    reopened.proof = proof;
    recover(&mut reopened).await;
    assert!(reopened.storage.get_earliest_matched_blocks().is_some());
    let restored_peer = reopened.peers.get_peer(&peer).unwrap();
    assert!(
        restored_peer.get_blocks_proof_request().is_some()
            || restored_peer.get_blocks_request().is_some(),
        "reopened range must schedule proof or a body backed by retained current membership"
    );
    let proof = reopened.positive(Kind::Header, reopened.wire.clone(), false);
    reopened.receive(proof).await;
    let mut sync = SyncProtocol::new(reopened.storage.clone(), reopened.peers.clone());
    let body = packed::SyncMessage::new_builder()
        .set(
            packed::SendBlock::new_builder()
                .block(reopened.block.data())
                .build(),
        )
        .build();
    sync.received(reopened.context.context(), peer, body.as_bytes())
        .await;
    assert!(
        reopened.storage.get_earliest_matched_blocks().is_none(),
        "replayed range did not finish"
    );
}

#[tokio::test]
async fn stale_and_malformed_misses_do_not_remove_range() {
    let mut f = prepare().await;
    let before = f
        .storage
        .get_earliest_matched_blocks()
        .unwrap()
        .blocks
        .len();
    for hashes in [
        vec![packed::Byte32::new([9; 32])],
        vec![f.block.hash(), f.block.hash()],
    ] {
        f.receive(f.negative(Kind::Header, f.wire.clone(), hashes))
            .await;
        assert_eq!(
            f.storage
                .get_earliest_matched_blocks()
                .unwrap()
                .blocks
                .len(),
            before
        );
        assert!(f
            .peers
            .matched_blocks()
            .read()
            .await
            .contains_key(&f.block.hash().unpack()));
    }
}

#[tokio::test]
async fn nonexistent_filter_hash_rechecks_and_recovers_after_reopen() {
    use crate::service::{LightClientService, SearchKey};
    use crate::storage::{ScriptStatus, ScriptType, SetScriptsCommand};
    use ckb_types::utilities::{build_filter_data, calc_filter_hash, FilterDataProvider};
    struct NoInputs;
    impl FilterDataProvider for NoInputs {
        fn cell(&self, _: &packed::OutPoint) -> Option<packed::CellOutput> {
            None
        }
    }
    let mut f = Fixture::new();
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script: packed::Script::default(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let search = || SearchKey {
        script: packed::Script::default().into(),
        ..Default::default()
    };
    let capacity = |storage: &Storage| {
        LightClientService::new(Arc::new(storage.clone())).get_cells_capacity(search())
    };
    assert_eq!(
        capacity(&f.storage).unwrap().capacity.value(),
        4_100_000_000
    );
    let (data, missing) = build_filter_data(NoInputs, &f.block.transactions());
    assert!(missing.is_empty());
    let data: packed::Bytes = data.pack();
    let filter_hash: packed::Byte32 =
        calc_filter_hash(&f.storage.get_last_check_point().1, &data).pack();
    f.peers
        .mock_latest_block_filter_hashes(f.peer, 0, vec![filter_hash.clone()]);
    let bogus = packed::Byte32::new([42; 32]);
    let honest = packed::BlockFilters::new_builder()
        .start_number(1u64)
        .block_hashes(vec![f.block.hash()].pack())
        .filters(vec![data].pack())
        .build();
    let bad = honest
        .clone()
        .as_builder()
        .block_hashes(vec![bogus.clone()].pack())
        .build();
    let context = MockNetworkContext::new(ckb_network::SupportProtocols::Filter);
    let mut filter = FilterProtocol::new(f.storage.clone(), f.peers.clone());
    filter
        .received(
            context.context(),
            f.peer,
            packed::BlockFilterMessage::new_builder()
                .set(bad)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(capacity(&f.storage).is_err());
    f.protocol.disconnected(f.context.context(), f.peer).await;
    f.peer = PeerIndex::new(2);
    f.peers.add_peer(f.peer);
    f.peers
        .mock_prove_state(f.peer, f.wire.clone().into())
        .unwrap();
    f.peers
        .mock_latest_block_filter_hashes(f.peer, 0, vec![filter_hash.clone()]);
    f.protocol.notify(f.context.context(), 2).await;
    assert_eq!(
        f.peers
            .get_peer(&f.peer)
            .unwrap()
            .get_blocks_proof_request()
            .unwrap()
            .block_hashes(),
        vec![Unpack::<ckb_types::H256>::unpack(&bogus)]
    );
    f.receive(f.negative(Kind::Header, f.wire.clone(), vec![bogus]))
        .await;
    assert!(f.storage.get_earliest_matched_blocks().is_some());
    assert!(capacity(&f.storage).is_err());
    // Exercise the normal filter retry tick without waiting for its 15s clock.
    *crate::write_lock!(filter.last_ask_time) = None;
    filter.notify(context.context(), 0).await;
    assert_eq!(f.storage.get_min_filtered_block_number(), 0,
        "all available proved peers missing an unproved match must trigger positional refilter, not an endless hash retry");
    assert!(f.storage.get_earliest_matched_blocks().is_some());
    assert!(capacity(&f.storage).is_err());
    drop((filter, context));
    let Fixture {
        _directory,
        storage,
        service,
        protocol,
        peers,
        context,
        peer,
        block,
        wire,
        proof,
    } = f;
    drop((storage, service, protocol, peers, context));
    let mut f = Fixture::new();
    let storage = Storage::new(_directory.path());
    let consensus = ConsensusBuilder::default().build();
    storage.init_genesis_block(consensus.genesis_block().data());
    f.protocol = crate::protocols::LightClientProtocol::new(
        storage.clone(),
        f.peers.clone(),
        consensus.clone(),
    );
    f.service = crate::service::LightClientChainService::new(
        StorageWithChainData::new(storage.clone(), f.peers.clone(), Default::default()),
        Arc::new(consensus),
    );
    f.storage = storage;
    f.peers.remove_peer(f.peer).await;
    f.peer = peer;
    f.block = block;
    f.wire = wire;
    f.proof = proof;
    f.peers.add_peer(peer);
    f.peers
        .mock_prove_state(peer, f.wire.clone().into())
        .unwrap();
    f.peers
        .mock_latest_block_filter_hashes(peer, 0, vec![filter_hash]);
    assert!(capacity(&f.storage).is_err());
    let context = MockNetworkContext::new(ckb_network::SupportProtocols::Filter);
    let mut filter = FilterProtocol::new(f.storage.clone(), f.peers.clone());
    filter.notify(context.context(), 0).await;
    assert!(context.sent_messages().borrow().iter().any(|(_, _, bytes)| {
        packed::BlockFilterMessage::from_slice(bytes).ok().is_some_and(|msg| matches!(msg.to_enum(), packed::BlockFilterMessageUnion::GetBlockFilters(req) if Unpack::<u64>::unpack(&req.start_number()) == 1))
    }));
    filter
        .received(
            context.context(),
            peer,
            packed::BlockFilterMessage::new_builder()
                .set(honest)
                .build()
                .as_bytes(),
        )
        .await;
    assert_eq!(
        f.storage
            .get_earliest_matched_blocks()
            .unwrap()
            .blocks
            .iter()
            .map(|b| b.hash.clone())
            .collect::<Vec<_>>(),
        vec![f.block.hash()],
        "honest refilter must replace the nonexistent expectation"
    );
    assert!(
        f.peers
            .get_peer(&peer)
            .unwrap()
            .get_blocks_proof_request()
            .is_some(),
        "honest refilter must schedule proof"
    );
    assert!(capacity(&f.storage).is_err());
    f.receive(f.positive(Kind::Header, f.wire.clone(), false))
        .await;
    assert!(
        f.peers
            .matched_blocks()
            .read()
            .await
            .get(&f.block.hash().unpack())
            .unwrap()
            .0,
        "honest proof must authenticate expected position"
    );
    assert!(capacity(&f.storage).is_err());
    let mut sync = SyncProtocol::new(f.storage.clone(), f.peers.clone());
    sync.received(
        f.context.context(),
        peer,
        packed::SyncMessage::new_builder()
            .set(
                packed::SendBlock::new_builder()
                    .block(f.block.data())
                    .build(),
            )
            .build()
            .as_bytes(),
    )
    .await;
    assert!(f.storage.get_earliest_matched_blocks().is_none());
    assert_eq!(
        capacity(&f.storage).unwrap().capacity.value(),
        4_100_000_100
    );
    eprintln!("nonexistent filter hash recovered after physical reopen: capacity=4100000100");
}

/// A valid filter commits to script data, not the accompanying block hash.
/// Both supplied hashes are canonical and inside [1,2], but their positions are
/// swapped. The watched creator belongs to height 1; height 2 is unrelated.
#[tokio::test]
async fn completed_filter_range_must_bind_each_match_to_its_actual_height() {
    use crate::service::{LightClientService, SearchKey};
    use crate::storage::{ScriptStatus, ScriptType, SetScriptsCommand};
    use ckb_merkle_mountain_range::{leaf_index_to_pos, util::MemMMR};
    use ckb_types::{
        core,
        utilities::{
            build_filter_data, calc_filter_hash, merkle_mountain_range::MergeHeaderDigest,
            FilterDataProvider,
        },
        U256,
    };
    struct NoInputs;
    impl FilterDataProvider for NoInputs {
        fn cell(&self, _: &packed::OutPoint) -> Option<packed::CellOutput> {
            None
        }
    }
    let mut f = Fixture::new();
    let consensus = ConsensusBuilder::default().build();
    let genesis = consensus.genesis_block();
    let other_script = packed::Script::new_builder()
        .args(b"unwatched-range-control".as_slice().pack())
        .build();
    let other_tx = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(77u64)
                .lock(other_script)
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let two = core::BlockBuilder::default()
        .number(2u64)
        .parent_hash(f.block.hash())
        .compact_target(genesis.compact_target())
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .transaction(other_tx)
        .build();
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.header().digest()).unwrap();
    mmr.push(f.block.header().digest()).unwrap();
    mmr.push(two.header().digest()).unwrap();
    let root = mmr.get_root().unwrap();
    let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
    let extra =
        core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()));
    let anchor = core::HeaderBuilder::default()
        .number(3u64)
        .parent_hash(two.hash())
        .compact_target(genesis.compact_target())
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .extra_hash(extra.extra_hash())
        .build();
    f.wire = packed::VerifiableHeader::new_builder()
        .header(anchor.data())
        .uncles_hash(packed::Byte32::zero())
        .extension(packed::BytesOpt::new_builder().set(Some(extension)).build())
        .parent_chain_root(root)
        .build();
    // Explicit trusted checkpoint setup; actual response MMR/body checks below.
    f.storage
        .update_last_state(&U256::from(4u64), &anchor.data(), &[]);
    f.storage.init_genesis_block(genesis.data());
    f.peers
        .mock_prove_state(f.peer, f.wire.clone().into())
        .unwrap();
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script: packed::Script::default(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let service = LightClientService::new(Arc::new(f.storage.clone()));
    let search = || SearchKey {
        script: packed::Script::default().into(),
        ..Default::default()
    };
    let before = service
        .get_cells_capacity(search())
        .unwrap()
        .capacity
        .value();
    let (data_one, missing) = build_filter_data(NoInputs, &f.block.transactions());
    assert!(missing.is_empty());
    let (data_two, missing) = build_filter_data(NoInputs, &two.transactions());
    assert!(missing.is_empty());
    let data_one: packed::Bytes = data_one.pack();
    let data_two: packed::Bytes = data_two.pack();
    let first: packed::Byte32 =
        calc_filter_hash(&f.storage.get_last_check_point().1, &data_one).pack();
    let second: packed::Byte32 = calc_filter_hash(&first, &data_two).pack();
    let expected_filter_hashes = vec![first, second];
    f.peers
        .mock_latest_block_filter_hashes(f.peer, 0, expected_filter_hashes.clone());
    let mut filter = FilterProtocol::new(f.storage.clone(), f.peers.clone());
    let honest = packed::BlockFilters::new_builder()
        .start_number(1u64)
        .block_hashes(vec![f.block.hash(), two.hash()].pack())
        .filters(vec![data_one.clone(), data_two.clone()].pack())
        .build();
    let matches = filter.check_filters_data(honest.clone(), 2).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0],
        f.block.hash(),
        "only the watched creator at height 1 matches"
    );
    let malicious = packed::BlockFilters::new_builder()
        .start_number(1u64)
        .block_hashes(vec![two.hash(), f.block.hash()].pack())
        .filters(vec![data_one, data_two].pack())
        .build();
    let filter_context = MockNetworkContext::new(ckb_network::SupportProtocols::Filter);
    let duplicate = malicious
        .clone()
        .as_builder()
        .block_hashes(vec![two.hash(), two.hash()].pack())
        .build();
    filter
        .received(
            filter_context.context(),
            f.peer,
            packed::BlockFilterMessage::new_builder()
                .set(duplicate)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(
        f.storage.get_earliest_matched_blocks().is_none(),
        "duplicate filter hashes must not create coverage"
    );
    assert_eq!(f.storage.get_min_filtered_block_number(), 0);
    filter
        .received(
            filter_context.context(),
            f.peer,
            packed::BlockFilterMessage::new_builder()
                .set(malicious)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(
        service.get_cells_capacity(search()).is_err(),
        "pending positional evidence must fence watched queries"
    );
    let owner = f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .unwrap()
        .clone();
    let unrelated_proof = mmr
        .gen_proof(vec![leaf_index_to_pos(1)])
        .unwrap()
        .proof_items()
        .to_vec();
    let wrong_hash = packed::SendBlocksProofV1::new_builder()
        .last_header(f.wire.clone())
        .proof(unrelated_proof.pack())
        .headers(vec![f.block.header().data()].pack())
        .blocks_uncles_hash(vec![f.block.calc_uncles_hash()].pack())
        .blocks_extension(vec![packed::BytesOpt::default()])
        .build();
    f.receive(
        packed::LightClientMessage::new_builder()
            .set(wrong_hash)
            .build(),
    )
    .await;
    let retained = f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .unwrap()
        .clone();
    assert!(
        Arc::ptr_eq(&owner.owner, &retained.owner),
        "unrequested hash must not retire a positional request"
    );
    assert!(
        !crate::storage::canonical::anchor_current(&f.storage, &f.block.header().data()).unwrap()
    );
    // Honest proof/body for the requested canonical hash: its actual height is 2.
    let proof = mmr
        .gen_proof(vec![leaf_index_to_pos(2)])
        .unwrap()
        .proof_items()
        .to_vec();
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(f.wire.clone())
        .proof(proof.pack())
        .headers(vec![two.header().data()].pack())
        .blocks_uncles_hash(vec![two.calc_uncles_hash()].pack())
        .blocks_extension(vec![packed::BytesOpt::default()])
        .build();
    f.receive(
        packed::LightClientMessage::new_builder()
            .set(response)
            .build(),
    )
    .await;
    assert!(
        !crate::storage::canonical::anchor_current(&f.storage, &two.header().data()).unwrap(),
        "wrong-position proof must not install membership"
    );
    assert!(service.get_cells_capacity(search()).is_err());
    let sync_context = MockNetworkContext::new(ckb_network::SupportProtocols::Sync);
    let mut sync = SyncProtocol::new(f.storage.clone(), f.peers.clone());
    sync.received(
        sync_context.context(),
        f.peer,
        packed::SyncMessage::new_builder()
            .set(packed::SendBlock::new_builder().block(two.data()).build())
            .build()
            .as_bytes(),
    )
    .await;
    assert!(
        sync_context.not_banned(f.peer),
        "the supplied canonical block body is authentic"
    );
    let cursor = f.storage.get_filter_scripts()[0].block_number;
    if cursor >= 2 {
        assert_eq!(service.get_cells_capacity(search()).unwrap().capacity.value(),before+100,
            "completed [1,2] coverage omitted the watched creator: a proved in-range header was substituted at the wrong filter position");
    } else {
        assert!(
            f.storage.get_earliest_matched_blocks().is_some()
                || f.storage.get_min_filtered_block_number() < 2,
            "rejected positional evidence must keep the range pending or refilterable"
        );
    }
    // Rejection alone is insufficient: a subsequent honest filter/proof/body
    // must discharge the saved obligation, with no successful partial balance.
    assert_eq!(f.storage.get_min_filtered_block_number(), 0);
    let old_peer = f.peer;
    f.protocol.disconnected(f.context.context(), old_peer).await;
    f.peer = PeerIndex::new(2);
    f.peers.add_peer(f.peer);
    f.peers
        .mock_prove_state(f.peer, f.wire.clone().into())
        .unwrap();
    f.peers
        .mock_latest_block_filter_hashes(f.peer, 0, expected_filter_hashes);
    filter
        .received(
            filter_context.context(),
            f.peer,
            packed::BlockFilterMessage::new_builder()
                .set(honest)
                .build()
                .as_bytes(),
        )
        .await;
    assert!(service.get_cells_capacity(search()).is_err());
    let proof_one = mmr
        .gen_proof(vec![leaf_index_to_pos(1)])
        .unwrap()
        .proof_items()
        .to_vec();
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(f.wire.clone())
        .proof(proof_one.pack())
        .headers(vec![f.block.header().data()].pack())
        .blocks_uncles_hash(vec![f.block.calc_uncles_hash()].pack())
        .blocks_extension(vec![packed::BytesOpt::default()])
        .build();
    f.receive(
        packed::LightClientMessage::new_builder()
            .set(response)
            .build(),
    )
    .await;
    assert!(service.get_cells_capacity(search()).is_err());
    sync.received(
        sync_context.context(),
        f.peer,
        packed::SyncMessage::new_builder()
            .set(
                packed::SendBlock::new_builder()
                    .block(f.block.data())
                    .build(),
            )
            .build()
            .as_bytes(),
    )
    .await;
    assert!(f.storage.get_earliest_matched_blocks().is_none());
    assert_eq!(f.storage.get_filter_scripts()[0].block_number, 2);
    let capacity = service
        .get_cells_capacity(search())
        .unwrap()
        .capacity
        .value();
    assert_eq!(capacity, before + 100);
    assert_eq!(capacity, 4_100_000_100);
    eprintln!("wrong-position proof rejected without membership; honest filter/proof/body recovered capacity={capacity}");
    f.proof = mmr
        .gen_proof(vec![leaf_index_to_pos(1)])
        .unwrap()
        .proof_items()
        .to_vec()
        .pack();
    pending_positional_fork_recovers_through_filter_proof_and_sync(
        &mut f,
        &mut filter,
        &mut sync,
        &two,
        before,
    )
    .await;
}

/// Preserve a verified prefix, replace height 2 while its range is pending,
/// then reject a stale proof and complete through a new peer's actual GCS,
/// MMR and Sync paths. Accepted fixture anchors are explicitly trusted; the
/// separate real last-state processor fork controls run in the full suite.
async fn pending_positional_fork_recovers_through_filter_proof_and_sync(
    f: &mut Fixture,
    filter: &mut FilterProtocol,
    sync: &mut SyncProtocol,
    old_two: &ckb_types::core::BlockView,
    baseline: u64,
) {
    use crate::service::{LightClientService, SearchKey};
    use crate::storage::{ScriptStatus, ScriptType, SetScriptsCommand};
    use ckb_merkle_mountain_range::{leaf_index_to_pos, util::MemMMR};
    use ckb_types::{
        core,
        utilities::{
            build_filter_data, calc_filter_hash, merkle_mountain_range::MergeHeaderDigest,
            FilterDataProvider,
        },
        U256,
    };
    struct Cells(packed::Transaction);
    impl FilterDataProvider for Cells {
        fn cell(&self, point: &packed::OutPoint) -> Option<packed::CellOutput> {
            (point.tx_hash() == self.0.calc_tx_hash())
                .then(|| {
                    self.0
                        .raw()
                        .outputs()
                        .get(Unpack::<u32>::unpack(&point.index()) as usize)
                })
                .flatten()
        }
    }
    let genesis = f.storage.get_genesis_block().into_view();
    let creator = f.block.transactions()[0].clone();
    let creator_bytes = f
        .storage
        .get(crate::storage::Key::TxHash(&creator.hash()).into_vec())
        .unwrap();
    f.storage.update_filter_scripts(
        vec![ScriptStatus {
            script: packed::Script::default(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    let (one_data, missing) = build_filter_data(Cells(creator.data()), &f.block.transactions());
    assert!(missing.is_empty());
    let one_data: packed::Bytes = one_data.pack();
    // Seed the pending range with exact known positions; the real filter
    // admission path was exercised above, and is exercised again after the fork.
    f.storage
        .add_positioned_matched_blocks(1, 2, vec![(1, f.block.hash())]);
    filter.notify(f.context.context(), 0).await;
    // A retained current membership can go straight to body download. Arm an
    // explicit valid old-anchor proof request to exercise its delayed response.
    f.peers.update_blocks_proof_request(
        f.peer,
        Some(
            packed::GetBlocksProof::new_builder()
                .last_hash(f.wire.header().calc_header_hash())
                .block_hashes(vec![f.block.hash()].pack())
                .build(),
        ),
        true,
    );
    let old_owner = f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .cloned();
    assert!(old_owner.is_some());
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .output(
            packed::CellOutput::new_builder()
                .capacity(100u64)
                .lock(
                    packed::Script::new_builder()
                        .args(b"fork-spend-unwatched".as_slice().pack())
                        .build(),
                )
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let replacement = core::BlockBuilder::default()
        .number(2u64)
        .parent_hash(f.block.hash())
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .compact_target(genesis.compact_target())
        .transaction(spend)
        .nonce(222u128)
        .build();
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.header().digest()).unwrap();
    mmr.push(f.block.header().digest()).unwrap();
    mmr.push(replacement.header().digest()).unwrap();
    let root = mmr.get_root().unwrap();
    let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
    let tip = core::HeaderBuilder::default()
        .number(3u64)
        .parent_hash(replacement.hash())
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .compact_target(genesis.compact_target())
        .extra_hash(
            core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()))
                .extra_hash(),
        )
        .nonce(333u128)
        .build();
    let new_wire = packed::VerifiableHeader::new_builder()
        .header(tip.data())
        .uncles_hash(packed::Byte32::zero())
        .extension(packed::BytesOpt::new_builder().set(Some(extension)).build())
        .parent_chain_root(root)
        .build();
    {
        let mut active = f.peers.matched_blocks().write().await;
        crate::storage::canonical::accept_with_rollback(
            &f.storage,
            &U256::from(5u64),
            &tip.data(),
            &[genesis.header(), f.block.header(), replacement.header()],
            1,
        )
        .unwrap();
        f.peers.clear_matched_blocks(&mut active);
    }
    assert_eq!(f.storage.get_min_filtered_block_number(), 0);
    let service = LightClientService::new(Arc::new(f.storage.clone()));
    let search = || SearchKey {
        script: packed::Script::default().into(),
        ..Default::default()
    };
    assert!(service.get_cells_capacity(search()).is_err());
    // A delayed proof with the old anchor must not finish the replacement work.
    let old = f.positive(Kind::Header, f.wire.clone(), false);
    f.receive(old).await;
    assert!(service.get_cells_capacity(search()).is_err());
    assert!(f
        .storage
        .get(crate::storage::Key::Meta("INDEX_REPAIR_V2").into_vec())
        .unwrap()
        .is_some());
    let previous_peer = f.peer;
    f.protocol
        .disconnected(f.context.context(), previous_peer)
        .await;
    f.peer = PeerIndex::new(3);
    f.wire = new_wire;
    f.peers.add_peer(f.peer);
    f.peers
        .mock_prove_state(f.peer, f.wire.clone().into())
        .unwrap();
    let (two_data, missing) = build_filter_data(Cells(creator.data()), &replacement.transactions());
    assert!(missing.is_empty());
    let two_data: packed::Bytes = two_data.pack();
    let first: packed::Byte32 =
        calc_filter_hash(&f.storage.get_last_check_point().1, &one_data).pack();
    let second: packed::Byte32 = calc_filter_hash(&first, &two_data).pack();
    f.peers
        .mock_latest_block_filter_hashes(f.peer, 0, vec![first, second]);
    let context = MockNetworkContext::new(ckb_network::SupportProtocols::Filter);
    let filters = packed::BlockFilters::new_builder()
        .start_number(1u64)
        .block_hashes(vec![f.block.hash(), replacement.hash()].pack())
        .filters(vec![one_data, two_data].pack())
        .build();
    filter
        .received(
            context.context(),
            f.peer,
            packed::BlockFilterMessage::new_builder()
                .set(filters)
                .build()
                .as_bytes(),
        )
        .await;
    let request = f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .cloned()
        .unwrap();
    assert_eq!(
        request.block_hashes(),
        vec![replacement.hash().unpack()],
        "verified prefix header can be reused"
    );
    let proof = mmr
        .gen_proof(vec![leaf_index_to_pos(2)])
        .unwrap()
        .proof_items()
        .to_vec();
    let response = packed::SendBlocksProofV1::new_builder()
        .last_header(f.wire.clone())
        .proof(proof.pack())
        .headers(vec![replacement.header().data()].pack())
        .blocks_uncles_hash(vec![replacement.calc_uncles_hash()].pack())
        .blocks_extension(vec![packed::BytesOpt::default()])
        .build();
    f.receive(
        packed::LightClientMessage::new_builder()
            .set(response)
            .build(),
    )
    .await;
    let sync_context = MockNetworkContext::new(ckb_network::SupportProtocols::Sync);
    for block in [old_two.data(), replacement.data(), f.block.data()] {
        sync.received(
            sync_context.context(),
            f.peer,
            packed::SyncMessage::new_builder()
                .set(packed::SendBlock::new_builder().block(block).build())
                .build()
                .as_bytes(),
        )
        .await;
        if f.storage.get_earliest_matched_blocks().is_some() {
            assert!(service.get_cells_capacity(search()).is_err());
        }
    }
    assert!(f.storage.get_earliest_matched_blocks().is_none());
    assert_eq!(f.storage.get_filter_scripts()[0].block_number, 2);
    assert_eq!(
        service
            .get_cells_capacity(search())
            .unwrap()
            .capacity
            .value(),
        baseline
    );
    assert_eq!(
        f.storage
            .get(crate::storage::Key::TxHash(&creator.hash()).into_vec())
            .unwrap(),
        creator_bytes
    );
    assert!(sync_context.not_banned(f.peer));
    eprintln!("pending fork: stale anchor/body rejected; honest GCS/MMR/Sync restored spent capacity={baseline}");
}
