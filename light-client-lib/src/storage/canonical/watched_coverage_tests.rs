use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_types::{
    core, packed,
    prelude::{IntoHeaderView, Unpack},
    U256,
};

use super::super::super::{meta, update_state, INDEX_FORMAT, LAST_STATE_KEY, RECOVERY_FORMAT};
use super::{
    positional_capacity, positional_fixture, positional_fixture_at, query_context,
    replay_target_page, snapshot_target_rows, Fault,
};
use crate::error::{Error, Result};
use crate::storage::canonical::coverage;
use crate::storage::{
    FilterMapFn, IteratorDirection, IteratorStart, KVPair, Key, LightClientStorage, Storage,
    StorageBackend, TakeWhileFn,
};

#[test]
fn ambiguous_tail_behind_current_forward_range_stays_fenced() {
    let (_directory, storage, blocks) = positional_fixture();
    replay_target_page(&storage, 1, 1, &blocks[..1]);
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 2, 1, vec![(2, blocks[1].hash())], revision).unwrap();
    assert_eq!(positional_capacity(&storage).unwrap(), 100);
    storage.add_matched_blocks(3, 1, vec![(blocks[2].hash(), false)]);
    assert!(
        query_context(&storage).is_err(),
        "an ambiguous tail is not certified forward work"
    );
    assert!(positional_capacity(&storage).is_err());
}

#[test]
fn pending_anchor_carry_and_acceptance_are_one_atomic_commit() {
    for after in [false, true] {
        let (directory, storage, blocks) = positional_fixture();
        let revision = coverage::scripts_revision(&storage).unwrap();
        coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
        let old = storage.get_tip_header().into_view();
        let next = old
            .clone()
            .as_advanced_builder()
            .number(7u64)
            .parent_hash(old.hash())
            .epoch(core::EpochNumberWithFraction::new(0, 7, 1000))
            .build();
        let fault = Fault {
            storage: storage.clone(),
            prefix: meta(LAST_STATE_KEY),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(update_state(
            &fault,
            &U256::from(8u64),
            &next.data(),
            &[old.clone()],
            None
        )
        .is_err());
        assert!(fault.fired.load(Ordering::SeqCst));
        drop(fault);
        drop(storage);
        let storage = Storage::new(directory.path());
        assert_eq!(
            storage.get_tip_header().calc_header_hash(),
            if after { next.hash() } else { old.hash() }
        );
        let range = storage.get_earliest_matched_blocks().unwrap();
        assert!(coverage::cached_matches(&storage, &range)
            .unwrap()
            .is_some());
        assert!(!coverage::prepare(&storage).unwrap());
    }
}

#[test]
fn rechecked_inflight_headers_are_local_staleness_not_bad_proof() {
    let (_directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
    assert!(coverage::check_headers(&storage, &[blocks[0].header()]).unwrap());
    coverage::recheck(&storage, 1).unwrap();
    let before = snapshot_target_rows(&storage);
    for _ in 0..3 {
        assert!(!coverage::check_headers(&storage, &[blocks[0].header()]).unwrap());
        coverage::prepare(&storage).unwrap();
        assert_eq!(
            snapshot_target_rows(&storage),
            before,
            "stale response/timer rewound twice"
        );
    }
}

#[test]
fn current_position_mismatch_still_rejects_and_refilters() {
    let (_directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
    assert!(coverage::check_headers(&storage, &[blocks[1].header()]).is_err());
    assert!(
        !coverage::cached_matches(&storage, &storage.get_earliest_matched_blocks().unwrap())
            .unwrap()
            .is_some()
    );
}

#[test]
fn pending_anchor_survives_150_linear_acceptances_reopen_but_not_fork() {
    let (directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
    let original_size = storage.get(coverage::key(1)).unwrap().unwrap().len();
    let mut tip = storage.get_tip_header().into_view();
    let mut window = Vec::new();
    for number in 7..=156 {
        window.push(tip.clone());
        if window.len() > 100 {
            window.remove(0);
        }
        tip = core::HeaderBuilder::default()
            .number(number)
            .parent_hash(tip.hash())
            .epoch(core::EpochNumberWithFraction::new(0, number, 1000))
            .build();
        update_state(
            &storage,
            &U256::from(number + 1),
            &tip.data(),
            &window,
            None,
        )
        .unwrap();
    }
    assert_eq!(
        storage.get(coverage::key(1)).unwrap().unwrap().len(),
        original_size
    );
    drop(storage);
    let storage = Storage::new(directory.path());
    let range = storage.get_earliest_matched_blocks().unwrap();
    assert!(coverage::cached_matches(&storage, &range)
        .unwrap()
        .is_some());
    assert!(!coverage::prepare(&storage).unwrap());
    let bridged = tip
        .clone()
        .as_advanced_builder()
        .number(350u64)
        .epoch(core::EpochNumberWithFraction::new(0, 350, 1000))
        .build();
    // Storage-boundary trusted fixture: production proves the exact old tip
    // under the new MMR root before supplying this retained prefix.
    update_state(
        &storage,
        &U256::from(400u64),
        &bridged.data(),
        &[],
        Some(tip.number()),
    )
    .unwrap();
    assert!(coverage::cached_matches(&storage, &range)
        .unwrap()
        .is_some());
    let competing = bridged.as_advanced_builder().nonce(1234u128).build();
    update_state(
        &storage,
        &U256::from(1000u64),
        &competing.data(),
        &[],
        Some(0),
    )
    .unwrap();
    assert!(coverage::cached_matches(&storage, &range)
        .unwrap()
        .is_none());
}

#[test]
fn forward_pending_work_preserves_certified_prefix_but_recheck_fences_it() {
    let (_directory, storage, blocks) = positional_fixture();
    replay_target_page(&storage, 1, 1, &blocks[..1]);
    assert_eq!(positional_capacity(&storage).unwrap(), 100);
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 2, 1, vec![(2, blocks[1].hash())], revision).unwrap();
    assert_eq!(positional_capacity(&storage).unwrap(), 100);
    let response = crate::service::LightClientService::new(Arc::new(storage.clone()))
        .get_cells_capacity(crate::service::SearchKey {
            script: storage.get_filter_scripts().remove(0).script.into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(response.block_number.value(), 1);
    assert_eq!(
        response.block_hash,
        Unpack::<ckb_types::H256>::unpack(&blocks[0].hash())
    );
    let mapping_key = Key::BlockNumber(1).into_vec();
    let mapping = storage.get(mapping_key.clone()).unwrap().unwrap();
    storage.delete(&mapping_key).unwrap();
    assert!(
        positional_capacity(&storage).is_err(),
        "missing indexed header must not label an old balance with the accepted tip"
    );
    storage.put(mapping_key, mapping).unwrap();
    coverage::recheck(&storage, 2).unwrap();
    assert!(positional_capacity(&storage).is_err());
}

#[test]
fn legacy_cursor_is_not_a_birth_or_complete_membership_certificate() {
    let (directory, storage, blocks) = positional_fixture();
    replay_target_page(&storage, 1, 1, &blocks[..1]);
    let primary = storage
        .get(Key::TxHash(&blocks[0].transactions()[0].hash()).into_vec())
        .unwrap();
    storage.delete(&meta(RECOVERY_FORMAT)).unwrap();
    storage.delete(&meta(INDEX_FORMAT)).unwrap();
    drop(storage);
    let storage = Storage::new(directory.path());
    storage.init_genesis_block(ConsensusBuilder::default().build().genesis_block().data());
    assert_eq!(storage.get_filter_scripts()[0].block_number, 0);
    assert_eq!(
        storage
            .get(Key::TxHash(&blocks[0].transactions()[0].hash()).into_vec())
            .unwrap(),
        primary
    );
    assert!(
        positional_capacity(&storage).is_err(),
        "a legacy cursor must not certify unproved history"
    );
}

#[derive(Clone)]
struct Reads {
    storage: Storage,
    reads: Arc<std::sync::atomic::AtomicUsize>,
    fail_scan: bool,
}
impl StorageBackend for Reads {
    type Batch = <Storage as StorageBackend>::Batch;
    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.storage.get(key)
    }
    fn get_many(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.reads.fetch_add(keys.len(), Ordering::Relaxed);
        self.storage.get_many(keys)
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.storage.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.storage.delete(key)
    }
    fn batch(&self) -> Self::Batch {
        self.storage.batch()
    }
    fn collect_iterator(
        &self,
        start: IteratorStart,
        direction: IteratorDirection,
        take: TakeWhileFn,
        filter: FilterMapFn,
        limit: usize,
    ) -> Vec<KVPair> {
        self.storage
            .collect_iterator(start, direction, take, filter, limit)
    }
    fn try_collect_iterator(
        &self,
        start: IteratorStart,
        direction: IteratorDirection,
        take: TakeWhileFn,
        filter: FilterMapFn,
        limit: usize,
    ) -> Result<Vec<KVPair>> {
        if self.fail_scan {
            return Err(Error::runtime("WO44 injected pending-range scan failure"));
        }
        self.storage
            .try_collect_iterator(start, direction, take, filter, limit)
    }
}
impl LightClientStorage for Reads {}

#[test]
fn history_page_does_not_validate_2000_irrelevant_tail_transactions() {
    use crate::service::{LightClientService, Order, SearchKey};
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), true);
    replay_target_page(&storage, 1, 2, &blocks[..2]);
    let script = storage.get_filter_scripts().remove(0).script;
    for transaction_index in 2..2002 {
        storage
            .put(
                Key::TxLockScript(
                    &script,
                    2,
                    transaction_index,
                    0,
                    crate::storage::CellType::Output,
                )
                .into_vec(),
                vec![0; 32],
            )
            .unwrap();
    }
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = LightClientService::new(Arc::new(Reads {
        storage,
        reads: reads.clone(),
        fail_scan: false,
    }));
    let key = || SearchKey {
        script: script.clone().into(),
        ..Default::default()
    };
    for grouped in [false, true] {
        reads.store(0, Ordering::Relaxed);
        let mut search = key();
        search.group_by_transaction = Some(grouped);
        let result = service.get_transactions(search, Order::Asc, 1u32.into(), None);
        eprintln!(
            "WO44 history grouped={grouped}: key reads={}",
            reads.load(Ordering::Relaxed)
        );
        assert_eq!(result.unwrap().objects.len(), 1);
        assert!(
            reads.load(Ordering::Relaxed) < 80,
            "small page validated the tail"
        );
        assert!(
            service
                .get_transactions(key(), Order::Desc, 1u32.into(), None)
                .is_err(),
            "invalid returned row must still fail"
        );
    }
}

#[test]
fn history_filters_and_page_continuation_preserve_canonical_results() {
    use crate::service::{LightClientService, Order, SearchKey, SearchKeyFilter};
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), true);
    replay_target_page(&storage, 1, 2, &blocks[..2]);
    let script = storage.get_filter_scripts().remove(0).script;
    let service = LightClientService::new(Arc::new(storage));
    let key = |grouped| SearchKey {
        script: script.clone().into(),
        group_by_transaction: Some(grouped),
        ..Default::default()
    };
    let first_hash = Unpack::<ckb_types::H256>::unpack(&blocks[0].transactions()[0].hash());
    let second_hash = Unpack::<ckb_types::H256>::unpack(&blocks[1].transactions()[0].hash());
    for grouped in [false, true] {
        let first = service
            .get_transactions(key(grouped), Order::Asc, 1u32.into(), None)
            .unwrap();
        assert_eq!(first.objects.len(), 1);
        assert_eq!(first.objects[0].tx_hash(), first_hash);
        let second = service
            .get_transactions(
                key(grouped),
                Order::Asc,
                1u32.into(),
                Some(first.last_cursor),
            )
            .unwrap();
        assert_eq!(second.objects.len(), 1);
        assert_eq!(second.objects[0].tx_hash(), second_hash);
        let reverse = service
            .get_transactions(key(grouped), Order::Desc, 1u32.into(), None)
            .unwrap();
        assert_eq!(reverse.objects[0].tx_hash(), second_hash);
        let mut range = key(grouped);
        range.filter = Some(SearchKeyFilter {
            block_range: Some([2u64.into(), 3u64.into()]),
            ..Default::default()
        });
        let filtered = service
            .get_transactions(range, Order::Asc, 10u32.into(), None)
            .unwrap();
        assert_eq!(filtered.objects.len(), 1);
        assert_eq!(filtered.objects[0].tx_hash(), second_hash);
        let mut secondary = key(grouped);
        secondary.filter = Some(SearchKeyFilter {
            script: Some(packed::Script::default().into()),
            ..Default::default()
        });
        assert!(service
            .get_transactions(secondary, Order::Asc, 10u32.into(), None)
            .unwrap()
            .objects
            .is_empty());
    }
}

#[test]
fn pending_range_scan_failure_propagates_without_panicking() {
    let (_directory, storage, _) = positional_fixture();
    let before = snapshot_target_rows(&storage);
    let fault = Reads {
        storage: storage.clone(),
        reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        fail_scan: true,
    };
    assert!(coverage::prepare(&fault).is_err());
    assert_eq!(snapshot_target_rows(&storage), before);
}
