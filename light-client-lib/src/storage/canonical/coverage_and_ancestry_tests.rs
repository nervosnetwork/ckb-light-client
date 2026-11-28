use std::sync::Arc;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_jsonrpc_types::Uint32;
use ckb_types::{
    core, packed,
    prelude::{Builder, Entity, Pack},
    U256,
};

use super::{positional_fixture_at, replay_target_page};
use crate::service::{LightClientService, Order, SearchKey};
use crate::storage::{
    canonical, HeaderWithExtension, LightClientStorage, ScriptStatus, ScriptType,
    SetScriptsCommand, Storage,
};

fn accept_block_three(
    storage: &Storage,
    block_two: &core::BlockView,
    block_three: &core::BlockView,
) {
    let tip = block_three.header();
    canonical::accept_with_rollback(
        storage,
        &U256::from(8u64),
        &tip.data(),
        &[block_two.header()],
        2,
    )
    .unwrap();
    canonical::store_proved_header(
        storage,
        &HeaderWithExtension {
            header: tip.data(),
            extension: None,
        },
        &tip.data(),
    )
    .unwrap();
}

fn indexed_prefix_at_tip_three() -> (tempfile::TempDir, Storage, Vec<core::BlockView>) {
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), true);
    accept_block_three(&storage, &blocks[1], &blocks[2]);
    replay_target_page(&storage, 1, 2, &blocks[..2]);
    (directory, storage, blocks)
}

fn watched_search(script: packed::Script) -> SearchKey {
    SearchKey {
        script: script.into(),
        ..Default::default()
    }
}

fn spending_at_block_three_fixture() -> (
    tempfile::TempDir,
    Storage,
    packed::Script,
    Vec<core::BlockView>,
) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let genesis = ConsensusBuilder::default().build().genesis_block().clone();
    storage.init_genesis_block(genesis.data());
    let script = packed::Script::new_builder()
        .args(b"wo48-spend-at-three".as_slice().pack())
        .build();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );

    let creator = core::TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .lock(script.clone())
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
    let two = core::BlockBuilder::default()
        .number(2u64)
        .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
        .parent_hash(one.hash())
        .build();
    let spend = core::TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(packed::OutPoint::new(creator.hash(), 0))
                .build(),
        )
        .build();
    let three = core::BlockBuilder::default()
        .number(3u64)
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .parent_hash(two.hash())
        .transaction(spend)
        .build();

    storage.update_last_state(&U256::from(7u64), &two.header().data(), &[]);
    for block in [&one, &two] {
        canonical::store_proved_header(
            &storage,
            &HeaderWithExtension {
                header: block.header().data(),
                extension: None,
            },
            &two.header().data(),
        )
        .unwrap();
    }
    (directory, storage, script, vec![one, two, three])
}

#[test]
fn lagging_script_queries_use_the_indexed_prefix_without_pending_ranges() {
    let (_directory, storage, _blocks) = indexed_prefix_at_tip_three();
    let script = storage.get_filter_scripts().remove(0).script;
    let service = LightClientService::new(Arc::new(storage));

    let cells = service.get_cells(
        watched_search(script.clone()),
        Order::Asc,
        Uint32::from(10),
        None,
    );
    let transactions = service.get_transactions(
        watched_search(script.clone()),
        Order::Asc,
        Uint32::from(10),
        None,
    );
    let capacity = service.get_cells_capacity(watched_search(script));
    let errors = [
        cells
            .as_ref()
            .err()
            .map(|error| format!("get_cells: {error}")),
        transactions
            .as_ref()
            .err()
            .map(|error| format!("get_transactions: {error}")),
        capacity
            .as_ref()
            .err()
            .map(|error| format!("get_cells_capacity: {error}")),
    ];
    assert!(
        errors.iter().all(Option::is_none),
        "queries at the certified cursor should remain available: {errors:?}"
    );
    let cells = cells.unwrap();
    assert!(
        cells.objects.is_empty(),
        "the cell was spent by indexed block 2"
    );
    let transactions = transactions.unwrap();
    assert_eq!(transactions.objects.len(), 2);
    let capacity = capacity.unwrap();
    assert_eq!(capacity.capacity.value(), 0);
    assert_eq!(capacity.block_number.value(), 2);
}

#[test]
fn prefix_capacity_requires_compatible_contributing_cursors() {
    let (_directory, storage, _blocks) = indexed_prefix_at_tip_three();
    let base = packed::Script::new_builder()
        .args(b"wo48-prefix".as_slice().pack())
        .build();
    let longer = packed::Script::new_builder()
        .args(b"wo48-prefix-extra".as_slice().pack())
        .build();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: base.clone(),
            script_type: ScriptType::Lock,
            block_number: 2,
        }],
        SetScriptsCommand::Partial,
    );
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: longer,
            script_type: ScriptType::Lock,
            block_number: 1,
        }],
        SetScriptsCommand::Partial,
    );
    let mut scope = base.as_slice().to_vec();
    scope.push(0);
    assert!(!canonical::coverage::prefix_query_available(&storage, &scope, 3).unwrap());
}

#[test]
fn deleted_and_readded_script_does_not_publish_old_rows_at_height_zero() {
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), true);
    replay_target_page(&storage, 1, 1, &blocks[..1]);
    let script_status = storage.get_filter_scripts().remove(0);
    let script = script_status.script.clone();
    storage.update_filter_scripts(vec![script_status], SetScriptsCommand::Delete);
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: crate::storage::ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::All,
    );

    let result =
        LightClientService::new(Arc::new(storage)).get_cells_capacity(watched_search(script));
    if let Ok(capacity) = &result {
        eprintln!(
            "delete/re-add observed capacity={} at height={}",
            capacity.capacity.value(),
            capacity.block_number.value()
        );
    }
    assert!(
        result.as_ref().map_or(true, |capacity| {
            capacity.block_number.value() != 0 || capacity.capacity.value() == 0
        }),
        "re-registration must not attribute a retained cell row to block 0"
    );
}

#[test]
fn higher_registration_height_does_not_certify_the_unscanned_gap() {
    let (_directory, storage, script, blocks) = spending_at_block_three_fixture();
    assert!(blocks[1].transactions().is_empty(), "block 2 must be empty");
    assert_eq!(blocks[2].transactions().len(), 1, "block 3 spends the cell");
    replay_target_page(&storage, 1, 2, &blocks[..2]);

    let service = LightClientService::new(Arc::new(storage.clone()));
    let cursor_before = storage.get_filter_scripts()[0].block_number;
    assert_eq!(cursor_before, 2);
    let cells_before = service
        .get_cells(
            watched_search(script.clone()),
            Order::Asc,
            Uint32::from(10),
            None,
        )
        .unwrap();
    assert_eq!(cells_before.objects.len(), 1);
    assert_eq!(cells_before.objects[0].block_number.value(), 1);
    assert_eq!(cells_before.objects[0].output.capacity.value(), 100);
    let capacity_before = service
        .get_cells_capacity(watched_search(script.clone()))
        .unwrap();
    assert_eq!(capacity_before.capacity.value(), 100);
    assert_eq!(capacity_before.block_number.value(), 2);

    accept_block_three(&storage, &blocks[1], &blocks[2]);
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: script.clone(),
            script_type: crate::storage::ScriptType::Lock,
            block_number: 3,
        }],
        SetScriptsCommand::All,
    );

    let cursor_after = storage.get_filter_scripts()[0].block_number;
    let interim_cells = service
        .get_cells(
            watched_search(script.clone()),
            Order::Asc,
            Uint32::from(10),
            None,
        )
        .unwrap();
    let interim_capacity = service
        .get_cells_capacity(watched_search(script.clone()))
        .unwrap();
    assert_eq!(cursor_after, 2);
    assert_eq!(interim_cells.objects.len(), 1);
    assert_eq!(interim_capacity.capacity.value(), 100);
    assert_eq!(interim_capacity.block_number.value(), 2);

    replay_target_page(&storage, 3, 1, &[blocks[2].clone()]);
    let cells_after = service.get_cells(
        watched_search(script.clone()),
        Order::Asc,
        Uint32::from(10),
        None,
    );
    let capacity_after = service.get_cells_capacity(watched_search(script));
    let live_cell_count = cells_after.as_ref().map(|cells| cells.objects.len());
    let capacity_snapshot = capacity_after
        .as_ref()
        .map(|capacity| (capacity.capacity.value(), capacity.block_number.value()));
    eprintln!(
        "height-3 spend after re-registration: cursor={cursor_after}, live_cells={live_cell_count:?}, capacity={capacity_snapshot:?}"
    );
    let cursor_is_bounded = cursor_after == 2;
    let no_stale_live_cell = cells_after
        .as_ref()
        .map_or(true, |cells| cells.objects.is_empty());
    let indexed_capacity_is_zero_at_three = capacity_after
        .as_ref()
        .is_ok_and(|capacity| capacity.capacity.value() == 0 && capacity.block_number.value() == 3);
    assert!(
        cursor_is_bounded && no_stale_live_cell && indexed_capacity_is_zero_at_three,
        "indexed block 3 spend was not reflected correctly: cursor={cursor_after}, live_cells={live_cell_count:?}, capacity={capacity_snapshot:?}"
    );
}

#[test]
fn unbound_or_invalid_recent_windows_cannot_prove_a_common_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    let (storage, blocks) = positional_fixture_at(directory.path(), false);
    let tip = blocks[2].header();
    storage.update_last_state(
        &U256::from(8u64),
        &tip.data(),
        &[blocks[0].header(), blocks[1].header()],
    );

    let accepted = canonical::accepted_recent_window(&storage, &tip.data()).unwrap();
    assert_eq!(accepted.as_ref().map(Vec::len), Some(2));

    storage.update_last_n_headers(&[blocks[0].header(), blocks[2].header()]);
    let unbound = canonical::accepted_recent_window(&storage, &tip.data()).unwrap();
    assert!(
        unbound.is_none(),
        "a standalone height cache is not evidence"
    );

    storage.update_last_state(
        &U256::from(8u64),
        &tip.data(),
        &[blocks[0].header(), blocks[2].header()],
    );
    let invalid = canonical::accepted_recent_window(&storage, &tip.data()).unwrap();
    assert!(
        invalid.is_none(),
        "a non-contiguous window cannot be evidence"
    );

    let wrong_parent = blocks[1]
        .header()
        .as_advanced_builder()
        .nonce(123456u128)
        .build();
    assert_ne!(wrong_parent.hash(), tip.parent_hash());
    storage.update_last_state(
        &U256::from(8u64),
        &tip.data(),
        &[blocks[0].header(), wrong_parent],
    );
    let inconsistent_parent = canonical::accepted_recent_window(&storage, &tip.data()).unwrap();
    assert!(
        inconsistent_parent.is_none(),
        "consecutive heights cannot establish a window whose final hash differs from the accepted tip parent"
    );
}
