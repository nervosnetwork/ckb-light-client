//! Failure boundaries use real backend batches and reopen the preserved database.
use super::*;
use crate::storage::{FilterMapFn, KVPair, Storage, TakeWhileFn};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_types::core;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct Fault {
    storage: Storage,
    prefix: Vec<u8>,
    after: bool,
    fired: Arc<AtomicBool>,
}
struct FaultBatch {
    batch: <Storage as StorageBackend>::Batch,
    prefix: Vec<u8>,
    after: bool,
    matches: bool,
    fired: Arc<AtomicBool>,
}
impl BatchWriter for FaultBatch {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.matches |= key.starts_with(&self.prefix);
        self.batch.put(key, value);
    }
    fn delete(&mut self, key: &[u8]) {
        self.matches |= key.starts_with(&self.prefix);
        self.batch.delete(key);
    }
    fn commit(self) -> Result<()> {
        let fail = self.matches && !self.fired.swap(true, Ordering::SeqCst);
        if fail && !self.after {
            return Err(Error::runtime("injected before atomic batch"));
        }
        self.batch.commit()?;
        if fail {
            return Err(Error::runtime("injected after atomic batch"));
        }
        Ok(())
    }
}
impl StorageBackend for Fault {
    type Batch = FaultBatch;
    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.storage.get(key)
    }
    fn get_many(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.storage.get_many(keys)
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let fail = key.starts_with(&self.prefix) && !self.fired.swap(true, Ordering::SeqCst);
        if fail && !self.after {
            return Err(Error::runtime("injected before atomic put"));
        }
        self.storage.put(key, value)?;
        if fail {
            return Err(Error::runtime("injected after atomic put"));
        }
        Ok(())
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.storage.delete(key)
    }
    fn batch(&self) -> Self::Batch {
        FaultBatch {
            batch: self.storage.batch(),
            prefix: self.prefix.clone(),
            after: self.after,
            matches: false,
            fired: self.fired.clone(),
        }
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
        self.storage
            .try_collect_iterator(start, direction, take, filter, limit)
    }
}
impl LightClientStorage for Fault {}

/// A shorter candidate's target must not take effect before its intent is durable.
/// Trusted DummyPoW checkpoint setup isolates the storage crash boundary; all
/// replayed block identities below really belong to the unchanged accepted chain.
#[test]
fn preflight_shorter_rollback_before_intent_must_preserve_old_spend_coverage() {
    use crate::service::{LightClientService, SearchKey};
    let directory = if let Ok(root) = std::env::var("WO29_PREFLIGHT_REPRO_DIR") {
        std::fs::create_dir_all(&root).unwrap();
        tempfile::tempdir_in(root).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
    .into_path();
    eprintln!(
        "retained preflight rollback database: {}",
        directory.display()
    );
    let storage = Storage::new(&directory);
    let consensus = ConsensusBuilder::default().build();
    let genesis = consensus.genesis_block();
    storage.init_genesis_block(genesis.data());
    let script = packed::Script::new_builder()
        .args(b"preflight-shorter-rollback".as_slice().pack())
        .build();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: super::super::super::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let creator = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(100u64)
                .lock(script.clone())
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let one = core::BlockBuilder::default()
        .number(1u64)
        .parent_hash(genesis.hash())
        .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
        .transaction(creator.clone())
        .build();
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build();
    let two = core::BlockBuilder::default()
        .number(2u64)
        .parent_hash(one.hash())
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .transaction(spend.clone())
        .build();
    storage.update_last_state(
        &U256::from(2u64),
        &two.header().data(),
        &[genesis.header(), one.header()],
    );
    let mut batch = storage.batch();
    member(&mut batch, &one.header().data());
    member(&mut batch, &two.header().data());
    batch.commit().unwrap();
    storage.filter_block(one.data());
    storage.filter_block(two.data());
    storage.update_min_filtered_block_number(2);
    storage.update_block_number(2);
    let search = || SearchKey {
        script: script.clone().into(),
        ..Default::default()
    };
    let capacity =
        |s: &Storage| LightClientService::new(Arc::new(s.clone())).get_cells_capacity(search());
    assert_eq!(capacity(&storage).unwrap().capacity.value(), 0);
    let creator_bytes = storage
        .get(Key::TxHash(&creator.hash()).into_vec())
        .unwrap()
        .unwrap();
    let spend_bytes = storage
        .get(Key::TxHash(&spend.hash()).into_vec())
        .unwrap()
        .unwrap();
    let alternative = one.header().as_advanced_builder().nonce(912u128).build();
    let fault = Fault {
        storage: storage.clone(),
        prefix: meta(ACCEPT),
        after: false,
        fired: Arc::new(AtomicBool::new(false)),
    };
    assert!(accept_with_rollback(
        &fault,
        &U256::from(3u64),
        &alternative.data(),
        &[genesis.header()],
        0
    )
    .is_err());
    assert!(fault.fired.load(Ordering::SeqCst));
    assert!(storage.get(meta(ACCEPT)).unwrap().is_none());
    assert_eq!(
        storage.get_tip_header().as_slice(),
        two.header().data().as_slice()
    );
    let repair: Repair = decode(&storage.get(meta(REPAIR)).unwrap().unwrap()).unwrap();
    eprintln!("before restart: accepted height=2; candidate height=1 never journaled; repair targets={:?}",repair.targets.iter().map(|(_,n)|*n).collect::<Vec<_>>());
    drop(fault);
    drop(storage);
    let storage = Storage::new(&directory);
    storage.init_genesis_block(genesis.data());
    assert_eq!(
        storage.get_tip_header().as_slice(),
        two.header().data().as_slice()
    );
    assert!(query_context(&storage).is_err());
    // The honest retry restores height 1, exactly the currently saved target.
    // Height 2's genuine spend must still be an outstanding coverage obligation.
    let revision = super::super::coverage::scripts_revision(&storage).unwrap();
    super::super::coverage::save_filters(&storage, 1, 1, vec![(1, one.hash())], revision).unwrap();
    let mut batch = storage.batch();
    member(&mut batch, &one.header().data());
    batch.commit().unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(one.data());
    finish_index(&storage, 1, 1).unwrap();
    recover(&storage).unwrap();
    assert_eq!(
        storage.get_tip_header().as_slice(),
        two.header().data().as_slice()
    );
    assert_eq!(
        storage
            .get(Key::TxHash(&creator.hash()).into_vec())
            .unwrap()
            .unwrap(),
        creator_bytes
    );
    assert_eq!(
        storage
            .get(Key::TxHash(&spend.hash()).into_vec())
            .unwrap()
            .unwrap(),
        spend_bytes
    );
    match capacity(&storage) {
        Ok(value)=>assert_eq!(value.capacity.value(),0,
            "pre-intent target shrink certified incomplete old-chain coverage and resurrected an output spent at accepted height 2"),
        Err(_)=>assert!(storage.get(meta(REPAIR)).unwrap().is_some(),"unfinished coverage must retain its durable repair target"),
    }
}

/// Browser fixture generation uses the real journal encoder and write path.
/// This is a trusted DummyPoW checkpoint, not a network-consensus certification.
#[test]
#[ignore = "explicit browser checkpoint generator; set WO29_BROWSER_CHECKPOINT"]
fn export_browser_accepted_rollback_checkpoint() {
    use ckb_chain_spec::ChainSpec;
    use ckb_resource::Resource;
    let path = std::env::var("WO29_BROWSER_CHECKPOINT").unwrap();
    assert!(
        !std::path::Path::new(&path).exists(),
        "preserve existing fixtures"
    );
    let spec = String::from_utf8(
        Resource::bundled("specs/testnet.toml".into())
            .get()
            .unwrap()
            .to_vec(),
    )
    .unwrap()
    .replace("func = \"EaglesongBlake2b\"", "func = \"Dummy\"");
    assert!(spec.contains("func = \"Dummy\""));
    let consensus = ChainSpec::load_from(&Resource::raw(spec.clone()))
        .unwrap()
        .build_consensus()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let genesis = consensus.genesis_block();
    storage.init_genesis_block(genesis.data());
    let script = packed::Script::new_builder()
        .args(b"wo29-browser-rollback".as_slice().pack())
        .build();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: super::super::super::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let creator = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(100u64)
                .lock(script.clone())
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let cellbase = core::TransactionBuilder::default()
        .input(packed::CellInput::new_cellbase_input(1))
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build();
    let unrelated = core::TransactionBuilder::default()
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build();
    let one = core::BlockBuilder::default()
        .number(1u64)
        .parent_hash(genesis.hash())
        .compact_target(genesis.compact_target())
        .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
        .transaction(cellbase)
        .transaction(creator.clone())
        .transaction(unrelated)
        .build();
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build();
    let two = core::BlockBuilder::default()
        .number(2u64)
        .parent_hash(one.hash())
        .compact_target(genesis.compact_target())
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .transaction(spend)
        .build();
    let old_work = genesis.difficulty() + one.difficulty() + two.difficulty();
    storage.update_last_state(
        &old_work,
        &two.header().data(),
        &[genesis.header(), one.header()],
    );
    let mut batch = storage.batch();
    member(&mut batch, &one.header().data());
    batch.commit().unwrap();
    storage.filter_block(one.data());
    storage.filter_block(two.data());
    storage.update_block_number(2);
    storage.update_min_filtered_block_number(2);
    storage
        .put(
            meta("wallet-browser-checkpoint-data"),
            b"preserve me".to_vec(),
        )
        .unwrap();
    let positional_snapshot = || {
        storage
            .try_collect_iterator(
                IteratorStart::From(vec![]),
                IteratorDirection::Forward,
                Box::new(|_| true),
                Box::new(|_, v| Some(v.to_vec())),
                usize::MAX,
            )
            .unwrap()
            .into_iter()
            .map(|r| serde_json::json!({"key":r.key,"value":r.value}))
            .collect::<Vec<_>>()
    };
    storage.add_matched_blocks(1, 2, vec![(two.hash(), true)]);
    let positional_legacy_rows = positional_snapshot();
    super::super::coverage::prepare(&storage).unwrap();
    let script_revision = super::super::coverage::scripts_revision(&storage).unwrap();
    super::super::coverage::save_filters(&storage, 1, 1, vec![(1, one.hash())], script_revision)
        .unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(one.data());
    let positional_partial_rows = positional_snapshot();
    assert!(query_context(&storage).is_err());
    finish_index(&storage, 1, 1).unwrap();
    super::super::coverage::prepare(&storage).unwrap();
    super::super::coverage::save_filters(&storage, 2, 1, vec![(2, two.hash())], script_revision)
        .unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(two.data());
    finish_index(&storage, 2, 2).unwrap();
    let positional_final_rows = positional_snapshot();
    assert!(query_context(&storage).is_ok());
    let mut target_fix = Vec::new();
    for after in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let current = Storage::new(directory.path());
        let mut batch = current.batch();
        for row in &positional_final_rows {
            let key: Vec<u8> = serde_json::from_value(row["key"].clone()).unwrap();
            let value: Vec<u8> = serde_json::from_value(row["value"].clone()).unwrap();
            batch.put(&key, &value);
        }
        batch.commit().unwrap();
        let shorter = one.as_advanced_builder().nonce(9876u128).build();
        let fault = Fault {
            storage: current.clone(),
            prefix: meta(ACCEPT),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(accept_with_rollback(
            &fault,
            &(&old_work + one.difficulty()),
            &shorter.header().data(),
            &[genesis.header()],
            0
        )
        .is_err());
        drop(fault);
        assert_eq!(rollback_target(&current), if after { 1 } else { 2 });
        assert_eq!(current.get(meta(ACCEPT)).unwrap().is_some(), after);
        let checkpoint = snapshot_target_rows(&current);
        drop(current);
        let current = Storage::new(directory.path());
        current.init_genesis_block(genesis.data());
        assert!(positional_capacity(&current).is_err());
        let first = if after { shorter.clone() } else { one.clone() };
        replay_target_page(&current, 1, 1, &[first]);
        let prefix = snapshot_target_rows(&current);
        if after {
            assert_eq!(positional_capacity(&current).unwrap(), 100);
        } else {
            assert!(positional_capacity(&current).is_err());
            replay_target_page(&current, 2, 1, std::slice::from_ref(&two));
            assert_eq!(positional_capacity(&current).unwrap(), 0);
        }
        target_fix.push(serde_json::json!({"committed":after,"rows":checkpoint,
            "prefix_rows":prefix,"complete_rows":snapshot_target_rows(&current),
            "expected_tip":if after {shorter.header().data().as_slice().to_vec()} else {two.header().data().as_slice().to_vec()},
            "expected_capacity":if after {100} else {0}}));
    }
    let mut intent_delta = Vec::new();
    for row in target_fix[1]["rows"].as_array().unwrap() {
        if !target_fix[0]["rows"].as_array().unwrap().contains(row) {
            intent_delta.push(row.clone());
        }
    }
    assert_eq!(
        intent_delta.len(),
        3,
        "target, intent and transition are one changed key set"
    );
    let alternate_one = one.header().as_advanced_builder().nonce(9001u128).build();
    let alternate_two = two
        .header()
        .as_advanced_builder()
        .parent_hash(alternate_one.hash())
        .nonce(9002u128)
        .build();
    let tip = alternate_two
        .clone()
        .as_advanced_builder()
        .parent_hash(alternate_two.hash())
        .number(3u64)
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .nonce(9003u128)
        .build();
    let work = &old_work + tip.difficulty();
    let fault = Fault {
        storage: storage.clone(),
        prefix: meta(LAST_STATE_KEY),
        after: false,
        fired: Arc::new(AtomicBool::new(false)),
    };
    assert!(accept_with_rollback(
        &fault,
        &work,
        &tip.data(),
        &[genesis.header(), alternate_one, alternate_two],
        0
    )
    .is_err());
    assert!(fault.fired.load(Ordering::SeqCst));
    assert!(storage.get(meta(ACCEPT)).unwrap().is_some());
    assert!(storage.get(meta(TRANSITION)).unwrap().is_some());
    let rows = storage
        .try_collect_iterator(
            IteratorStart::From(vec![]),
            IteratorDirection::Forward,
            Box::new(|_| true),
            Box::new(|_, v| Some(v.to_vec())),
            usize::MAX,
        )
        .unwrap()
        .into_iter()
        .map(|row| serde_json::json!({"key":row.key,"value":row.value}))
        .collect::<Vec<_>>();
    let hex = |bytes: &[u8]| {
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    let fixture = serde_json::json!({"target_fix":target_fix,"intent_delta":intent_delta,"positional_legacy_rows":positional_legacy_rows,"positional_partial_rows":positional_partial_rows,"positional_final_rows":positional_final_rows,"kind":"trusted DummyPoW durable rollback checkpoint; proof verification tested separately","spec":spec,"script":{"codeHash":hex(script.code_hash().as_slice()),"hashType":"data","args":hex(&script.args().raw_data())},"rows":rows,"candidate_tip":tip.data().as_slice(),"creator_key":Key::TxHash(&creator.hash()).into_vec(),"creator_bytes":storage.get(Key::TxHash(&creator.hash()).into_vec()).unwrap().unwrap()});
    std::fs::write(path, serde_json::to_vec(&fixture).unwrap()).unwrap();
}

#[test]
fn repair_restart_after_derived_clear_replays_genesis_before_ready() {
    use crate::service::{LightClientService, Order, SearchKey};
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let script = packed::Script::new_builder()
        .args(b"repair-genesis".as_slice().pack())
        .build();
    let creator = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(100u64)
                .lock(script.clone())
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build();
    let genesis = core::BlockBuilder::default()
        .transaction(creator)
        .transaction(spend)
        .build();
    storage.init_genesis_block(genesis.data());
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: super::super::super::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let before_repair = query_context(&storage).unwrap();
    for number in 0..2049u64 {
        let mut key = vec![32];
        key.extend(number.to_be_bytes());
        storage.put(key, vec![7; 32]).unwrap();
    }
    storage.delete(&meta(INDEX_FORMAT)).unwrap();
    let fault = Fault {
        storage: storage.clone(),
        prefix: vec![32],
        after: true,
        fired: Arc::new(AtomicBool::new(false)),
    };
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| recover(&fault).unwrap()))
            .is_err()
    );
    assert!(fault.fired.load(Ordering::SeqCst));
    assert_eq!(
        scan(&storage, vec![32]).unwrap().len(),
        2049 - 1024,
        "first deletion page committed; remaining work is durable"
    );
    assert!(query_context(&storage).is_err());
    drop(fault);
    drop(storage);
    let storage = Storage::new(directory.path());
    storage.init_genesis_block(genesis.data());
    recover(&storage).unwrap();
    recover(&storage).unwrap();
    assert!(
        check_query_context(&storage, &before_repair).is_err(),
        "completed repair must invalidate pre-repair query snapshots"
    );
    let service = LightClientService::new(Arc::new(storage));
    let key = || SearchKey {
        script: script.clone().into(),
        ..Default::default()
    };
    assert_eq!(
        service.get_cells_capacity(key()).unwrap().capacity.value(),
        0
    );
    assert_eq!(
        service
            .get_transactions(key(), Order::Asc, 100u32.into(), None)
            .unwrap()
            .objects
            .len(),
        2
    );
}

#[test]
fn accepted_rollback_journal_replays_before_and_after_atomic_boundaries() {
    for stage in [
        ACCEPT,
        super::super::super::FILTER_SCRIPTS_KEY,
        super::super::super::MATCHED_FILTER_BLOCKS_KEY,
        LAST_STATE_KEY,
    ] {
        for after in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let storage = Storage::new(directory.path());
            let consensus = ConsensusBuilder::default().build();
            storage.init_genesis_block(consensus.genesis_block().data());
            let script = packed::Script::new_builder()
                .args(b"durable-rollback".as_slice().pack())
                .build();
            storage.update_filter_scripts(
                vec![ScriptStatus {
                    script: script.clone(),
                    script_type: super::super::super::ScriptType::Lock,
                    block_number: 0,
                }],
                SetScriptsCommand::All,
            );
            let creator = core::TransactionBuilder::default()
                .output(
                    packed::CellOutput::new_builder()
                        .capacity(100u64)
                        .lock(script.clone())
                        .build(),
                )
                .output_data(packed::Bytes::default())
                .build();
            let one = core::BlockBuilder::default()
                .number(1u64)
                .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
                .parent_hash(consensus.genesis_block().hash())
                .transaction(creator.clone())
                .build();
            let spend = core::TransactionBuilder::default()
                .input(
                    packed::CellInput::new_builder()
                        .previous_output(packed::OutPoint::new(creator.hash(), 0))
                        .build(),
                )
                .output(packed::CellOutput::default())
                .output_data(packed::Bytes::default())
                .build();
            let two = core::BlockBuilder::default()
                .number(2u64)
                .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
                .parent_hash(one.hash())
                .transaction(spend)
                .build();
            storage.update_last_state(
                &U256::from(2u64),
                &two.header().data(),
                &[consensus.genesis_block().header(), one.header()],
            );
            let mut batch = storage.batch();
            member(&mut batch, &one.header().data());
            member(&mut batch, &two.header().data());
            batch.commit().unwrap();
            storage.filter_block(one.data());
            storage.filter_block(two.data());
            storage.update_block_number(2);
            storage.add_matched_blocks(2, 1, vec![(two.hash(), true)]);
            let primary = storage
                .get(Key::TxHash(&creator.hash()).into_vec())
                .unwrap()
                .unwrap();
            let alternative = one.header().as_advanced_builder().nonce(567u128).build();
            let tip = two
                .header()
                .as_advanced_builder()
                .parent_hash(alternative.hash())
                .nonce(568u128)
                .build();
            let fault = Fault {
                storage: storage.clone(),
                prefix: meta(stage),
                after,
                fired: Arc::new(AtomicBool::new(false)),
            };
            let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                accept_with_rollback(
                    &fault,
                    &U256::from(3u64),
                    &tip.data(),
                    &[consensus.genesis_block().header(), alternative.clone()],
                    0,
                )
            }));
            assert!(fault.fired.load(Ordering::SeqCst), "boundary {stage}");
            assert!(interrupted.is_err() || interrupted.unwrap().is_err());
            drop(fault);
            drop(storage);
            let storage = Storage::new(directory.path());
            storage.init_genesis_block(consensus.genesis_block().data());
            // Before the first journal commit there is no accepted intent.
            if stage == ACCEPT && !after {
                assert_eq!(
                    storage.get_tip_header().as_slice(),
                    two.header().data().as_slice()
                );
                assert!(storage.get(meta(REPAIR)).unwrap().is_some());
                assert!(query_context(&storage).is_err());
            } else {
                assert_eq!(storage.get_tip_header().as_slice(), tip.data().as_slice());
                assert!(transaction(&storage, &creator.hash()).unwrap().is_none());
                assert!(storage.get_earliest_matched_blocks().is_none());
                assert_eq!(storage.get_filter_scripts()[0].block_number, 0);
                assert!(
                    storage
                        .get(Key::CellLockScript(&script, 1, 0, 0).into_vec())
                        .unwrap()
                        .is_none(),
                    "undo must not resurrect the removed creator"
                );
            }
            assert_eq!(
                storage
                    .get(Key::TxHash(&creator.hash()).into_vec())
                    .unwrap()
                    .unwrap(),
                primary
            );
            assert!(storage.get(meta(ACCEPT)).unwrap().is_none());
            assert!(storage.get(meta(TRANSITION)).unwrap().is_none());
            let snapshot = storage.get_last_state();
            recover(&storage).unwrap();
            recover(&storage).unwrap();
            assert_eq!(storage.get_last_state().0, snapshot.0);
            assert_eq!(storage.get_last_state().1.as_slice(), snapshot.1.as_slice());
        }
    }
}

// Positional storage boundaries use explicit trusted headers/filter pages.
// Real GCS/MMR/Sync admission and honest retry run in peers::missing_tests.
fn positional_fixture() -> (tempfile::TempDir, Storage, Vec<core::BlockView>) {
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), false);
    (directory, storage, blocks)
}
fn positional_fixture_at(
    path: &std::path::Path,
    at_spend_tip: bool,
) -> (Storage, Vec<core::BlockView>) {
    let storage = Storage::new(path);
    let genesis = ConsensusBuilder::default().build().genesis_block().clone();
    storage.init_genesis_block(genesis.data());
    let script = packed::Script::new_builder()
        .args(b"position-pages".as_slice().pack())
        .build();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: crate::storage::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    let creator = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .lock(script)
                .capacity(100u64)
                .build(),
        )
        .output_data(packed::Bytes::default())
        .build();
    let one = core::BlockBuilder::default()
        .number(1u64)
        .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
        .parent_hash(genesis.hash())
        .transaction(creator.clone())
        .build();
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .build();
    let two = core::BlockBuilder::default()
        .number(2u64)
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .parent_hash(one.hash())
        .transaction(spend)
        .build();
    let three = core::BlockBuilder::default()
        .number(3u64)
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .parent_hash(two.hash())
        .build();
    let tip = if at_spend_tip {
        two.header()
    } else {
        core::HeaderBuilder::default()
            .number(6u64)
            .epoch(core::EpochNumberWithFraction::new(0, 6, 100))
            .parent_hash(three.hash())
            .build()
    };
    storage.update_last_state(&U256::from(7u64), &tip.data(), &[]);
    for block in [&one, &two, &three] {
        if block.number() > tip.number() {
            continue;
        }
        store_proved_header(
            &storage,
            &crate::storage::HeaderWithExtension {
                header: block.header().data(),
                extension: None,
            },
            &tip.data(),
        )
        .unwrap();
    }
    (storage, vec![one, two, three])
}
fn positional_capacity(storage: &Storage) -> crate::error::Result<u64> {
    let script = storage.get_filter_scripts().remove(0).script;
    crate::service::LightClientService::new(Arc::new(storage.clone()))
        .get_cells_capacity(crate::service::SearchKey {
            script: script.into(),
            ..Default::default()
        })
        .map(|v| v.capacity.value())
}

fn rollback_target_case() -> (
    std::path::PathBuf,
    Storage,
    Vec<core::BlockView>,
    core::BlockView,
) {
    let directory = if let Ok(root) = std::env::var("WO29_TARGET_FIX_EVIDENCE") {
        std::fs::create_dir_all(&root).unwrap();
        tempfile::tempdir_in(root).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
    .into_path();
    eprintln!("retained target-boundary database: {}", directory.display());
    let (storage, blocks) = positional_fixture_at(&directory, true);
    storage.filter_block(blocks[0].data());
    storage.filter_block(blocks[1].data());
    storage.update_min_filtered_block_number(2);
    storage.update_block_number(2);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
    let replacement = blocks[0].as_advanced_builder().nonce(8080u128).build();
    (directory, storage, blocks, replacement)
}
fn rollback_target(storage: &Storage) -> u64 {
    let repair: Repair = decode(&storage.get(meta(REPAIR)).unwrap().unwrap()).unwrap();
    assert_eq!(repair.targets.len(), 1);
    repair.targets[0].1
}
fn snapshot_target_rows(storage: &Storage) -> Vec<serde_json::Value> {
    storage
        .try_collect_iterator(
            IteratorStart::From(vec![]),
            IteratorDirection::Forward,
            Box::new(|_| true),
            Box::new(|_, v| Some(v.to_vec())),
            usize::MAX,
        )
        .unwrap()
        .into_iter()
        .map(|r| serde_json::json!({"key":r.key,"value":r.value}))
        .collect()
}
fn reopen_target(storage: Storage, path: &std::path::Path, recover_now: bool) -> Storage {
    drop(storage);
    let storage = Storage::new(path);
    if recover_now {
        let genesis = ConsensusBuilder::default().build().genesis_block().data();
        storage.init_genesis_block(genesis);
    }
    storage
}
fn replay_target_page(storage: &Storage, start: u64, count: u64, blocks: &[core::BlockView]) {
    let revision = super::super::coverage::scripts_revision(storage).unwrap();
    super::super::coverage::save_filters(
        storage,
        start,
        count,
        blocks.iter().map(|b| (b.number(), b.hash())).collect(),
        revision,
    )
    .unwrap();
    let anchor = storage.get_tip_header();
    for block in blocks {
        store_proved_header(
            storage,
            &crate::storage::HeaderWithExtension {
                header: block.header().data(),
                extension: None,
            },
            &anchor,
        )
        .unwrap();
    }
    begin_index(storage).unwrap();
    for block in blocks {
        storage.filter_block(block.data());
    }
    finish_index(storage, start, start + count - 1).unwrap();
}
fn primary_target_rows(storage: &Storage, blocks: &[core::BlockView]) -> Vec<Vec<u8>> {
    blocks[..2]
        .iter()
        .flat_map(|b| b.transactions())
        .map(|tx| {
            storage
                .get(Key::TxHash(&tx.hash()).into_vec())
                .unwrap()
                .unwrap()
        })
        .collect()
}

#[test]
fn rollback_target_intent_and_prepare_failures_preserve_atomic_old_or_candidate_goals() {
    for stage in [REPAIR, ACCEPT] {
        for after in [false, true] {
            let (directory, storage, blocks, replacement) = rollback_target_case();
            let old_tip = storage.get_tip_header();
            let primary = primary_target_rows(&storage, &blocks);
            let fault = Fault {
                storage: storage.clone(),
                prefix: meta(stage),
                after,
                fired: Arc::new(AtomicBool::new(false)),
            };
            assert!(accept_with_rollback(
                &fault,
                &U256::from(8u64),
                &replacement.header().data(),
                &[storage.get_genesis_block().into_view().header()],
                0
            )
            .is_err());
            assert!(fault.fired.load(Ordering::SeqCst));
            let committed = stage == ACCEPT && after;
            assert_eq!(storage.get(meta(ACCEPT)).unwrap().is_some(), committed);
            assert_eq!(storage.get(meta(TRANSITION)).unwrap().is_some(), committed);
            if storage.get(meta(REPAIR)).unwrap().is_some() {
                assert_eq!(rollback_target(&storage), if committed { 1 } else { 2 });
                assert!(positional_capacity(&storage).is_err());
            } else {
                assert_eq!(positional_capacity(&storage).unwrap(), 0);
            }
            assert_eq!(storage.get_tip_header().as_slice(), old_tip.as_slice());
            drop(fault);
            let storage = reopen_target(storage, &directory, true);
            if stage == REPAIR && !after {
                // Nothing changed: the old, fully indexed store is still valid.
                assert_eq!(positional_capacity(&storage).unwrap(), 0);
                assert_eq!(primary_target_rows(&storage, &blocks), primary);
                let storage = reopen_target(storage, &directory, true);
                assert_eq!(positional_capacity(&storage).unwrap(), 0);
                continue;
            }
            assert!(positional_capacity(&storage).is_err());
            if committed {
                assert_eq!(
                    storage.get_tip_header().as_slice(),
                    replacement.header().data().as_slice()
                );
                replay_target_page(&storage, 1, 1, &[replacement]);
                assert_eq!(positional_capacity(&storage).unwrap(), 100);
            } else {
                assert_eq!(storage.get_tip_header().as_slice(), old_tip.as_slice());
                replay_target_page(&storage, 1, 1, &blocks[..1]);
                assert_eq!(rollback_target(&storage), 2);
                assert!(
                    positional_capacity(&storage).is_err(),
                    "old spend still requires coverage"
                );
                replay_target_page(&storage, 2, 1, &blocks[1..2]);
                assert_eq!(positional_capacity(&storage).unwrap(), 0);
            }
            assert_eq!(primary_target_rows(&storage, &blocks), primary);
            let expected = positional_capacity(&storage).unwrap();
            let storage = reopen_target(storage, &directory, true);
            recover(&storage).unwrap();
            recover(&storage).unwrap();
            assert_eq!(positional_capacity(&storage).unwrap(), expected);
            assert_eq!(primary_target_rows(&storage, &blocks), primary);
            eprintln!("target intent stage={stage} after={after}: old/candidate goals atomic; completed capacity={expected}");
        }
    }
}

#[test]
fn rollback_target_replay_survives_repeated_failures_and_physical_reopen() {
    for stage in [
        super::super::super::FILTER_SCRIPTS_KEY,
        super::super::super::MIN_FILTERED_BLOCK_NUMBER,
        LAST_STATE_KEY,
    ] {
        for after in [false, true] {
            let (directory, mut storage, blocks, replacement) = rollback_target_case();
            let primary = primary_target_rows(&storage, &blocks);
            let fault = Fault {
                storage: storage.clone(),
                prefix: meta(ACCEPT),
                after: true,
                fired: Arc::new(AtomicBool::new(false)),
            };
            assert!(accept_with_rollback(
                &fault,
                &U256::from(8u64),
                &replacement.header().data(),
                &[storage.get_genesis_block().into_view().header()],
                0
            )
            .is_err());
            drop(fault);
            assert_eq!(rollback_target(&storage), 1);
            for _ in 0..2 {
                storage = reopen_target(storage, &directory, false);
                if storage.get(meta(ACCEPT)).unwrap().is_none() {
                    break;
                }
                let fault = Fault {
                    storage: storage.clone(),
                    prefix: meta(stage),
                    after,
                    fired: Arc::new(AtomicBool::new(false)),
                };
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| recover(&fault)));
                assert!(
                    fault.fired.load(Ordering::SeqCst),
                    "replay boundary {stage}"
                );
                assert!(result.is_err() || result.unwrap().is_err());
                drop(fault);
                assert_eq!(rollback_target(&storage), 1);
                assert!(positional_capacity(&storage).is_err());
                assert_eq!(primary_target_rows(&storage, &blocks), primary);
            }
            storage = reopen_target(storage, &directory, true);
            assert_eq!(
                storage.get_tip_header().as_slice(),
                replacement.header().data().as_slice()
            );
            assert!(positional_capacity(&storage).is_err());
            replay_target_page(&storage, 1, 1, &[replacement]);
            assert_eq!(positional_capacity(&storage).unwrap(), 100);
            storage = reopen_target(storage, &directory, true);
            assert_eq!(positional_capacity(&storage).unwrap(), 100);
            assert_eq!(primary_target_rows(&storage, &blocks), primary);
            eprintln!("target repeated replay stage={stage} after={after}: durable candidate completed after reopen");
        }
    }
}

#[test]
fn rollback_target_independent_goals_and_partial_index_require_real_future_coverage() {
    for independent in [false, true] {
        for partial in [false, true] {
            let (directory, storage, blocks, replacement) = rollback_target_case();
            let primary = primary_target_rows(&storage, &blocks);
            if independent {
                start_repair(&storage, true).unwrap();
            }
            if partial {
                begin_index(&storage).unwrap();
                let scripts =
                    scan(&storage, meta(super::super::super::FILTER_SCRIPTS_KEY)).unwrap();
                assert_eq!(scripts.len(), 1);
                let mut batch = storage.batch();
                batch.put(&scripts[0].key, &0u64.to_be_bytes());
                batch.commit().unwrap();
                storage.add_positioned_matched_blocks(
                    1,
                    2,
                    vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
                );
                storage.filter_block(blocks[0].data());
                let script = storage.get_filter_scripts()[0].script.clone();
                assert!(
                    storage
                        .get(Key::CellLockScript(&script, 1, 0, 0).into_vec())
                        .unwrap()
                        .is_some(),
                    "creator row must really be present in the interrupted range"
                );
                assert!(positional_capacity(&storage).is_err());
            }
            accept_with_rollback(
                &storage,
                &U256::from(8u64),
                &replacement.header().data(),
                &[storage.get_genesis_block().into_view().header()],
                0,
            )
            .unwrap();
            assert_eq!(rollback_target(&storage), if independent { 2 } else { 1 });
            let storage = reopen_target(storage, &directory, true);
            replay_target_page(&storage, 1, 1, std::slice::from_ref(&replacement));
            if independent {
                assert!(positional_capacity(&storage).is_err());
                assert_eq!(rollback_target(&storage), 2);
                let extension = blocks[1]
                    .as_advanced_builder()
                    .parent_hash(replacement.hash())
                    .nonce(8081u128)
                    .build();
                update_state(
                    &storage,
                    &U256::from(9u64),
                    &extension.header().data(),
                    &[
                        storage.get_genesis_block().into_view().header(),
                        replacement.header(),
                    ],
                    None,
                )
                .unwrap();
                replay_target_page(&storage, 2, 1, &[extension]);
                assert_eq!(positional_capacity(&storage).unwrap(), 0);
            } else {
                assert_eq!(positional_capacity(&storage).unwrap(), 100);
            }
            let expected = positional_capacity(&storage).unwrap();
            let storage = reopen_target(storage, &directory, true);
            assert_eq!(positional_capacity(&storage).unwrap(), expected);
            assert_eq!(primary_target_rows(&storage, &blocks), primary);
            eprintln!(
                "target independent={independent} partial={partial}: completed capacity={expected}"
            );
        }
    }
}

#[test]
fn rollback_target_equal_height_deep_fork_completes_without_losing_primary_history() {
    let (directory, storage, blocks, replacement) = rollback_target_case();
    let primary = primary_target_rows(&storage, &blocks);
    let old_tip = storage.get_tip_header().into_view();
    let spend = blocks[1]
        .as_advanced_builder()
        .parent_hash(replacement.hash())
        .nonce(8082u128)
        .build();
    let mut tip = spend.header();
    let mut recent = vec![
        storage.get_genesis_block().into_view().header(),
        replacement.header(),
    ];
    if old_tip.number() > 2 {
        recent.push(tip.clone());
    }
    for number in 3..=old_tip.number() {
        tip = core::HeaderBuilder::default()
            .number(number)
            .parent_hash(tip.hash())
            .epoch(core::EpochNumberWithFraction::new(0, number, 100))
            .nonce(9000u128 + number as u128)
            .build();
        if number < old_tip.number() {
            recent.push(tip.clone());
        }
    }
    accept_with_rollback(&storage, &U256::from(8u64), &tip.data(), &recent, 0).unwrap();
    assert_eq!(
        storage.get_tip_header().into_view().number(),
        old_tip.number()
    );
    assert!(positional_capacity(&storage).is_err());
    replay_target_page(&storage, 1, tip.number(), &[replacement, spend]);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
    let storage = reopen_target(storage, &directory, true);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
    assert_eq!(primary_target_rows(&storage, &blocks), primary);
}

#[cfg(feature = "sqlite")]
#[test]
fn rollback_target_sqlite_engine_abort_rolls_back_target_and_intent_together() {
    let (directory, storage, blocks, replacement) = rollback_target_case();
    let key = meta(ACCEPT)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    storage.conn.lock().unwrap().execute_batch(&format!(
        "CREATE TEMP TRIGGER abort_accept BEFORE INSERT ON kv_store WHEN NEW.key=X'{key}' BEGIN SELECT RAISE(ABORT,'injected acceptance transaction failure'); END;"
    )).unwrap();
    let error = accept_with_rollback(
        &storage,
        &U256::from(8u64),
        &replacement.header().data(),
        &[storage.get_genesis_block().into_view().header()],
        0,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("injected acceptance transaction failure"));
    assert_eq!(
        rollback_target(&storage),
        2,
        "earlier target write in failed engine transaction must roll back"
    );
    assert!(storage.get(meta(ACCEPT)).unwrap().is_none());
    assert!(storage.get(meta(TRANSITION)).unwrap().is_none());
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER abort_accept")
        .unwrap();
    let storage = reopen_target(storage, &directory, true);
    replay_target_page(&storage, 1, 1, &blocks[..1]);
    assert!(positional_capacity(&storage).is_err());
    replay_target_page(&storage, 2, 1, &blocks[1..2]);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
}

#[test]
fn positional_recheck_pages_are_atomic_resumable_and_preserve_saved_targets() {
    use super::super::coverage;
    for after in [false, true] {
        let (directory, storage, blocks) = positional_fixture();
        let genesis = storage.get_genesis_block();
        let primary = storage
            .get(
                crate::storage::Key::TxHash(&genesis.transactions().get(0).unwrap().calc_tx_hash())
                    .into_vec(),
            )
            .unwrap();
        storage.add_matched_blocks(1, 3, vec![(blocks[1].hash(), true)]);
        storage.update_min_filtered_block_number(5);
        assert!(
            query_context(&storage).is_err(),
            "ambiguous ranges must fence queries even without [1]"
        );
        assert!(finish_index(&storage, 1, 3).is_err());
        let fault = Fault {
            storage: storage.clone(),
            prefix: coverage::key(1),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(coverage::recheck(&fault, 1).is_err());
        assert!(fault.fired.load(Ordering::SeqCst));
        assert!(repair_pending(&storage).unwrap());
        drop(fault);
        drop(storage);
        let storage = Storage::new(directory.path());
        storage.init_genesis_block(genesis.clone());
        assert!(query_context(&storage).is_err());
        assert!(coverage::prepare(&storage).unwrap());
        assert_eq!(storage.get_min_filtered_block_number(), 0);
        let revision = coverage::scripts_revision(&storage).unwrap();
        let fault = Fault {
            storage: storage.clone(),
            prefix: coverage::key(1),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(
            coverage::save_filters(&fault, 1, 1, vec![(1, blocks[0].hash())], revision).is_err()
        );
        assert_eq!(storage.get_min_filtered_block_number(), u64::from(after));
        assert!(query_context(&storage).is_err());
        drop(fault);
        drop(storage);
        let storage = Storage::new(directory.path());
        storage.init_genesis_block(genesis.clone());
        if !after {
            coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
        }
        assert_eq!(
            storage.get_latest_matched_blocks().unwrap().start_number,
            2,
            "unprocessed tail must be saved in the same atomic batch"
        );
        assert!(
            finish_index(&storage, 1, 1).is_err(),
            "a saved position is not an indexed body"
        );
        begin_index(&storage).unwrap();
        storage.filter_block(blocks[0].data());
        finish_index(&storage, 1, 1).unwrap();
        assert!(query_context(&storage).is_err());
        coverage::prepare(&storage).unwrap();
        coverage::save_filters(&storage, 2, 1, vec![(2, blocks[1].hash())], revision).unwrap();
        begin_index(&storage).unwrap();
        storage.filter_block(blocks[1].data());
        finish_index(&storage, 2, 2).unwrap();
        coverage::prepare(&storage).unwrap();
        coverage::save_filters(&storage, 3, 1, vec![], revision).unwrap();
        storage.update_block_number(3);
        assert!(
            query_context(&storage).is_err(),
            "old filter target 5 must not shrink to rechecked range end 3"
        );
        coverage::save_filters(&storage, 4, 2, vec![], revision).unwrap();
        storage.update_block_number(5);
        assert_eq!(
            positional_capacity(&storage).unwrap(),
            0,
            "spent output must not resurrect"
        );
        assert!(!repair_pending(&storage).unwrap());
        let history = crate::service::LightClientService::new(Arc::new(storage.clone()))
            .get_transactions(
                crate::service::SearchKey {
                    script: storage.get_filter_scripts().remove(0).script.into(),
                    ..Default::default()
                },
                crate::service::Order::Asc,
                100u32.into(),
                None,
            )
            .unwrap();
        assert_eq!(history.objects.len(), 2);
        assert_eq!(
            storage
                .get(
                    crate::storage::Key::TxHash(
                        &genesis.transactions().get(0).unwrap().calc_tx_hash()
                    )
                    .into_vec()
                )
                .unwrap(),
            primary
        );
        drop(storage);
        let storage = Storage::new(directory.path());
        storage.init_genesis_block(genesis);
        assert_eq!(positional_capacity(&storage).unwrap(), 0);
        eprintln!("recheck/page failure after={after}: physical reopen, target=5, spent capacity=0, history=2");
    }
}

#[test]
fn positional_completion_requires_exact_unique_members_and_indexed_bodies() {
    use super::super::coverage;
    let (_directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    for bad in [
        vec![(1, blocks[0].hash()), (1, blocks[1].hash())],
        vec![(1, blocks[0].hash()), (2, blocks[0].hash())],
        vec![(3, blocks[0].hash())],
    ] {
        assert!(coverage::save_filters(&storage, 1, 2, bad, revision).is_err());
        assert!(storage.get_earliest_matched_blocks().is_none());
        assert_eq!(storage.get_min_filtered_block_number(), 0);
    }
    coverage::save_filters(
        &storage,
        1,
        2,
        vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        revision,
    )
    .unwrap();
    assert!(
        coverage::check_bodies(&storage, &[blocks[0].data()]).is_err(),
        "missing body cannot complete"
    );
    assert!(
        coverage::check_bodies(&storage, &[blocks[0].data(), blocks[0].data()]).is_err(),
        "duplicate body cannot complete"
    );
    coverage::prepare(&storage).unwrap();
    // Duplicate/wrong response rejection may require a recheck; supply the
    // same already validated honest page and retry the full obligation.
    coverage::recheck(&storage, 1).unwrap();
    coverage::save_filters(
        &storage,
        1,
        2,
        vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        revision,
    )
    .unwrap();
    assert!(
        coverage::check_bodies(&storage, &[blocks[1].data(), blocks[0].data()]).is_ok(),
        "wire/body ordering alone must not disable legitimate work"
    );
    assert!(finish_index(&storage, 1, 2).is_err());
    begin_index(&storage).unwrap();
    storage.filter_block(blocks[0].data());
    assert!(
        finish_index(&storage, 1, 2).is_err(),
        "partial indexing is incomplete"
    );
    storage.filter_block(blocks[1].data());
    let original = storage.get(member_key(2)).unwrap().unwrap();
    storage
        .put(member_key(2), blocks[2].hash().as_slice().to_vec())
        .unwrap();
    assert!(
        finish_index(&storage, 1, 2).is_err(),
        "a different canonical position cannot reuse an indexed flag"
    );
    storage.put(member_key(2), original).unwrap();
    finish_index(&storage, 1, 2).unwrap();
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
}

#[test]
fn positional_index_batch_failure_replays_without_certifying_partial_rows() {
    use super::super::coverage;
    for after in [false, true] {
        let (directory, storage, blocks) = positional_fixture();
        let genesis = storage.get_genesis_block();
        storage.add_positioned_matched_blocks(
            1,
            2,
            vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        );
        begin_index(&storage).unwrap();
        let fault = Fault {
            storage: storage.clone(),
            prefix: coverage::key(1),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || fault.filter_block(blocks[0].data())
        ))
        .is_err());
        assert!(fault.fired.load(Ordering::SeqCst));
        assert!(query_context(&storage).is_err());
        drop(fault);
        drop(storage);
        let storage = Storage::new(directory.path());
        storage.init_genesis_block(genesis);
        assert_eq!(storage.get(meta(INDEX_WRITING)).unwrap(), Some(vec![1]));
        assert!(
            !coverage::prepare(&storage).unwrap(),
            "valid [1] range must replay directly"
        );
        assert!(finish_index(&storage, 1, 2).is_err());
        storage.filter_block(blocks[0].data());
        storage.filter_block(blocks[1].data());
        finish_index(&storage, 1, 2).unwrap();
        assert_eq!(positional_capacity(&storage).unwrap(), 0);
    }
}

#[test]
fn positional_revision_change_and_legacy_partial_index_require_recheck() {
    use super::super::coverage;
    let (_directory, storage, blocks) = positional_fixture();
    storage.add_positioned_matched_blocks(1, 2, vec![(1, blocks[0].hash()), (2, blocks[1].hash())]);
    let mut batch = storage.batch();
    coverage::change_scripts(&storage, &mut batch).unwrap();
    batch.commit().unwrap();
    assert!(coverage::prepare(&storage).unwrap());
    assert_eq!(storage.get_min_filtered_block_number(), 0);
    assert!(query_context(&storage).is_err());
    assert!(storage.get(meta(INDEX_UNCERTAIN)).unwrap().is_none());
    storage.add_matched_blocks(1, 2, vec![(blocks[0].hash(), true)]);
    begin_index(&storage).unwrap();
    assert!(coverage::prepare(&storage).unwrap());
    assert!(storage.get_earliest_matched_blocks().is_none());
    assert!(repair_pending(&storage).unwrap());
    assert_eq!(storage.get_filter_scripts()[0].block_number, 0);
    assert!(
        query_context(&storage).is_err(),
        "clearing ambiguous rows does not certify saved target 2"
    );
}

#[test]
fn positional_swapped_members_wrong_hashes_and_late_filter_pages_cannot_certify_coverage() {
    use super::super::coverage;
    let (_directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(
        &storage,
        1,
        2,
        vec![(1, blocks[1].hash()), (2, blocks[0].hash())],
        revision,
    )
    .unwrap();
    assert!(coverage::check_headers(&storage, &[blocks[0].header(), blocks[1].header()]).is_err());
    assert!(query_context(&storage).is_err());
    assert!(storage.get(meta(INDEX_UNCERTAIN)).unwrap().is_none());
    coverage::save_filters(
        &storage,
        1,
        2,
        vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        revision,
    )
    .unwrap();
    assert!(
        coverage::check_headers(&storage, &[blocks[2].header()]).is_err(),
        "canonical but unrequested hash is not a positional match"
    );
    coverage::save_filters(
        &storage,
        1,
        2,
        vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        revision,
    )
    .unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(blocks[0].data());
    // A later no-match filter page must not retire the interrupted [1] fence.
    coverage::save_filters(&storage, 3, 1, vec![], revision).unwrap();
    assert_eq!(storage.get(meta(INDEX_WRITING)).unwrap(), Some(vec![1]));
    assert!(query_context(&storage).is_err());
    storage.filter_block(blocks[1].data());
    finish_index(&storage, 1, 2).unwrap();
    storage.update_block_number(3);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
}

#[test]
fn positional_fork_overlap_preserves_goals_and_requires_replacement_evidence() {
    use super::super::coverage;
    for old_end in [2, 5] {
        let (_directory, storage, blocks) = positional_fixture();
        // A pending range spans the common block 1 and the detached block 2.
        storage.add_positioned_matched_blocks(
            1,
            old_end,
            vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
        );
        let replacement = core::BlockBuilder::default()
            .number(2u64)
            .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
            .parent_hash(blocks[0].hash())
            .nonce(99u128)
            .build();
        let new_tip = core::HeaderBuilder::default()
            .number(3u64)
            .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
            .parent_hash(replacement.hash())
            .nonce(100u128)
            .build();
        accept_with_rollback(
            &storage,
            &U256::from(8u64),
            &new_tip.data(),
            &[
                storage.get_genesis_block().into_view().header(),
                blocks[0].header(),
                replacement.header(),
            ],
            1,
        )
        .unwrap();
        assert_eq!(
            storage.get_min_filtered_block_number(),
            0,
            "valid prefix of overlapping range must be refiltered"
        );
        assert!(
            repair_pending(&storage).unwrap(),
            "deleting obsolete bindings must preserve the coverage goal"
        );
        assert!(query_context(&storage).is_err());
        assert!(!anchor_current(&storage, &blocks[1].header().data()).unwrap());
        let revised_end = old_end.min(3);
        let revision = coverage::scripts_revision(&storage).unwrap();
        coverage::save_filters(
            &storage,
            1,
            revised_end,
            vec![(1, blocks[0].hash()), (2, replacement.hash())],
            revision,
        )
        .unwrap();
        assert!(
            coverage::check_headers(&storage, &[blocks[1].header()]).is_err(),
            "detached proof cannot fill replacement position"
        );
        coverage::save_filters(
            &storage,
            1,
            revised_end,
            vec![(1, blocks[0].hash()), (2, replacement.hash())],
            revision,
        )
        .unwrap();
        store_proved_header(
            &storage,
            &crate::storage::HeaderWithExtension {
                header: replacement.header().data(),
                extension: None,
            },
            &new_tip.data(),
        )
        .unwrap();
        assert!(coverage::check_bodies(&storage, &[replacement.data(), blocks[0].data()]).is_ok());
        begin_index(&storage).unwrap();
        storage.filter_block(blocks[0].data());
        storage.filter_block(replacement.data());
        finish_index(&storage, 1, revised_end).unwrap();
        assert_eq!(positional_capacity(&storage).unwrap(), 100);
        assert!(!repair_pending(&storage).unwrap());
    }
}

#[test]
fn positional_recheck_crosses_existing_ranges_without_overwrite_or_stall() {
    use super::super::coverage;
    let (_directory, storage, blocks) = positional_fixture();
    let revision = coverage::scripts_revision(&storage).unwrap();
    storage.add_positioned_matched_blocks(1, 1, vec![(1, blocks[0].hash())]);
    storage.add_positioned_matched_blocks(3, 1, vec![(3, blocks[2].hash())]);
    coverage::recheck(&storage, 1).unwrap();
    assert_eq!(coverage::recheck_limit(&storage, 1, 100).unwrap(), 1);
    coverage::save_filters(&storage, 1, 1, vec![(1, blocks[0].hash())], revision).unwrap();
    assert_eq!(coverage::recheck_limit(&storage, 2, 100).unwrap(), 1);
    coverage::save_filters(&storage, 2, 1, vec![], revision).unwrap();
    // A formerly valid later range must be replaceable during the saved-target
    // recheck, without dropping it or returning an unrecoverable "already exists".
    coverage::save_filters(&storage, 3, 1, vec![(3, blocks[2].hash())], revision).unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(blocks[0].data());
    finish_index(&storage, 1, 1).unwrap();
    begin_index(&storage).unwrap();
    storage.filter_block(blocks[2].data());
    finish_index(&storage, 3, 3).unwrap();
    assert_eq!(positional_capacity(&storage).unwrap(), 100);
    // Old versions could store overlapping ranges. Splitting one must merge
    // its unfinished tail with an existing key rather than shorten that goal.
    storage.add_matched_blocks(1, 3, vec![(blocks[0].hash(), false)]);
    storage.add_matched_blocks(2, 4, vec![(blocks[1].hash(), false)]);
    coverage::prepare(&storage).unwrap();
    assert_eq!(coverage::recheck_limit(&storage, 1, 100).unwrap(), 1);
    coverage::save_filters(&storage, 1, 1, vec![], revision).unwrap();
    let tail = storage.get_earliest_matched_blocks().unwrap();
    assert_eq!((tail.start_number, tail.blocks_count), (2, 4));
    assert!(query_context(&storage).is_err());
}

#[test]
fn positional_recheck_target_intent_failure_never_loses_the_original_obligation() {
    use super::super::coverage;
    for after in [false, true] {
        let (directory, storage, blocks) = positional_fixture();
        let genesis = storage.get_genesis_block();
        storage.add_matched_blocks(1, 2, vec![(blocks[1].hash(), true)]);
        storage.update_min_filtered_block_number(2);
        let before = storage.get(coverage::key(1)).unwrap();
        let fault = Fault {
            storage: storage.clone(),
            prefix: meta(REPAIR),
            after,
            fired: Arc::new(AtomicBool::new(false)),
        };
        assert!(coverage::recheck(&fault, 1).is_err());
        assert!(fault.fired.load(Ordering::SeqCst));
        assert_eq!(storage.get(coverage::key(1)).unwrap(), before);
        assert_eq!(storage.get_min_filtered_block_number(), 2);
        assert!(query_context(&storage).is_err());
        drop(fault);
        drop(storage);
        let storage = Storage::new(directory.path());
        storage.init_genesis_block(genesis);
        assert_eq!(storage.get_min_filtered_block_number(), 0);
        assert!(repair_pending(&storage).unwrap());
        let revision = coverage::scripts_revision(&storage).unwrap();
        coverage::save_filters(
            &storage,
            1,
            2,
            vec![(1, blocks[0].hash()), (2, blocks[1].hash())],
            revision,
        )
        .unwrap();
        begin_index(&storage).unwrap();
        storage.filter_block(blocks[0].data());
        storage.filter_block(blocks[1].data());
        finish_index(&storage, 1, 2).unwrap();
        assert_eq!(positional_capacity(&storage).unwrap(), 0);
    }
}

#[test]
fn positional_stale_active_batch_cannot_block_a_new_positive_range() {
    use crate::protocols::Peers;
    let (_directory, storage, blocks) = positional_fixture();
    storage.add_positioned_matched_blocks(1, 2, vec![(1, blocks[0].hash()), (2, blocks[1].hash())]);
    let peers = Peers::new(2, 2000, storage.get_last_check_point(), 10);
    let mut cache = std::collections::HashMap::new();
    cache.insert(blocks[2].hash().unpack(), (true, None));
    crate::utils::network::index_downloaded_blocks(&storage, &peers, &mut cache).unwrap();
    assert_eq!(cache.len(), 2);
    assert!(
        !cache.contains_key(&blocks[2].hash().unpack()),
        "do not wait for a stale batch's missing body"
    );
    assert!(storage.get_earliest_matched_blocks().is_some());
    for block in &blocks[..2] {
        cache.insert(block.hash().unpack(), (true, Some(block.data())));
    }
    crate::utils::network::index_downloaded_blocks(&storage, &peers, &mut cache).unwrap();
    assert!(cache.is_empty());
    assert!(storage.get_earliest_matched_blocks().is_none());
    assert_eq!(storage.get_filter_scripts()[0].block_number, 2);
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
}

#[test]
fn positional_no_match_page_commit_before_cursor_publication_recovers_on_reopen() {
    use super::super::coverage;
    let (directory, storage, blocks) = positional_fixture();
    let genesis = storage.get_genesis_block();
    let never_matched = packed::Script::new_builder()
        .args(b"no-match-recheck-scope".as_slice().pack())
        .build();
    assert!(blocks
        .iter()
        .flat_map(|b| b.transactions())
        .flat_map(|t| t.outputs().into_iter())
        .all(|output| output.lock() != never_matched));
    // This scope has no matches in either body. Save a legacy ambiguous
    // obligation and replay a trusted validated no-match page for that scope.
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: never_matched,
            script_type: crate::storage::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );
    storage.add_matched_blocks(1, 2, vec![(blocks[0].hash(), true)]);
    coverage::prepare(&storage).unwrap();
    let revision = coverage::scripts_revision(&storage).unwrap();
    coverage::save_filters(&storage, 1, 2, vec![], revision).unwrap();
    assert!(storage.get_earliest_matched_blocks().is_none());
    assert_eq!(storage.get_min_filtered_block_number(), 2);
    assert_eq!(storage.get_filter_scripts()[0].block_number, 0);
    assert!(query_context(&storage).is_err());
    drop(storage);
    let storage = Storage::new(directory.path());
    storage.init_genesis_block(genesis);
    assert_eq!(storage.get_filter_scripts()[0].block_number, 2);
    assert!(storage.get(meta(REPAIR)).unwrap().is_none());
    assert_eq!(positional_capacity(&storage).unwrap(), 0);
}
