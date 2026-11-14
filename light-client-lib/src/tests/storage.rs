use ckb_types::packed::Script;

use crate::storage::{self, LightClientStorage};
use crate::tests::utils::new_storage;

#[test]
fn test_forget_update_min_filtred_number() {
    let (storage, _tmp_dir) = new_storage("forget_update_min_filtred_block");
    storage.update_min_filtered_block_number(66);
    storage.update_filter_scripts(
        vec![
            storage::ScriptStatus {
                script: Script::default(),
                script_type: storage::ScriptType::Lock,
                block_number: 33,
            },
            storage::ScriptStatus {
                script: Script::default(),
                script_type: storage::ScriptType::Type,
                block_number: 44,
            },
        ],
        Default::default(),
    );
    assert_eq!(storage.get_min_filtered_block_number(), 33);
}

use crate::storage::{HeaderWithExtension, Key, ScriptStatus, ScriptType, SetScriptsCommand};
use ckb_types::{
    bytes::Bytes,
    core::{BlockBuilder, TransactionBuilder},
    packed,
    prelude::*,
};

fn replay_fixture() -> (
    Script,
    Script,
    packed::Block,
    packed::Block,
    packed::Transaction,
) {
    let wallet = Script::new_builder()
        .args(Bytes::from_static(b"wallet").pack())
        .build();
    let cluster = Script::new_builder()
        .args(Bytes::from_static(b"cluster").pack())
        .build();
    let created = TransactionBuilder::default()
        .output(
            packed::CellOutput::new_builder()
                .capacity(1000u64)
                .lock(wallet.clone())
                .type_(Some(cluster.clone()).pack())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output(
            packed::CellOutput::new_builder()
                .capacity(2000u64)
                .lock(wallet.clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let spent = TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash(created.hash())
                        .index(1u32)
                        .build(),
                )
                .build(),
        )
        .output(
            packed::CellOutput::new_builder()
                .capacity(1900u64)
                .lock(wallet.clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let first = BlockBuilder::default()
        .number(1u64)
        .transaction(created.clone())
        .build();
    let second = BlockBuilder::default()
        .number(2u64)
        .transaction(spent)
        .build();
    (wallet, cluster, first.data(), second.data(), created.data())
}

#[test]
fn historical_subscription_replay_does_not_resurrect_spent_wallet_change() {
    let (storage, _tmp) = new_storage("script-replay-isolation");
    storage.init_genesis_block(BlockBuilder::default().build().data());
    let (wallet, cluster, first, second, created) = replay_fixture();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: wallet.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    storage.filter_block(first.clone());
    storage.update_block_number(1);
    storage.filter_block(second);
    storage.update_block_number(2);
    let wallet_key = Key::CellLockScript(&wallet, 1, 0, 1).into_vec();
    assert!(storage.get(wallet_key.clone()).unwrap().is_none());
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: cluster.clone(),
            script_type: ScriptType::Type,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    storage.filter_block(first);
    assert!(
        storage.get(wallet_key).unwrap().is_none(),
        "new Cluster subscription resurrected spent wallet change"
    );
    assert_eq!(
        storage
            .get(Key::CellTypeScript(&cluster, 1, 0, 0).into_vec())
            .unwrap(),
        Some(created.calc_tx_hash().as_slice().to_vec())
    );
    assert!(storage
        .get(Key::CellLockScript(&wallet, 2, 0, 0).into_vec())
        .unwrap()
        .is_some());
}

#[test]
fn late_transaction_proof_preserves_index_used_to_delete_spent_cells() {
    let (storage, _tmp) = new_storage("late-proof-index");
    storage.init_genesis_block(BlockBuilder::default().build().data());
    let (wallet, _, first, second, created) = replay_fixture();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: wallet.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    storage.filter_block(first.clone());
    storage.update_block_number(1);
    storage.add_fetched_tx(
        &created,
        &HeaderWithExtension {
            header: first.header(),
            extension: None,
        },
    );
    assert_eq!(
        storage.get_transaction(&created.calc_tx_hash()).unwrap().1,
        0
    );
    storage.filter_block(second);
    assert!(storage
        .get(Key::CellLockScript(&wallet, 1, 0, 1).into_vec())
        .unwrap()
        .is_none());
}

#[test]
fn transaction_proof_for_different_block_does_not_reuse_old_ordinal() {
    let (storage, _tmp) = new_storage("proof-different-block-index");
    storage.init_genesis_block(BlockBuilder::default().build().data());
    let (wallet, _, first, _, created) = replay_fixture();
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: wallet,
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    storage.filter_block(first.clone());
    let other_header = first
        .header()
        .as_builder()
        .raw(first.header().raw().as_builder().timestamp(999u64).build())
        .build();
    storage.add_fetched_tx(
        &created,
        &HeaderWithExtension {
            header: other_header,
            extension: None,
        },
    );
    assert_eq!(
        storage.get_transaction(&created.calc_tx_hash()).unwrap().1,
        u32::MAX
    );
}

#[test]
fn zero_cursor_still_indexes_configured_genesis_outputs() {
    let (storage, _tmp) = new_storage("genesis-script-cursor");
    let (wallet, _, first, _, _) = replay_fixture();
    let genesis = first
        .clone()
        .as_builder()
        .header(
            first
                .header()
                .as_builder()
                .raw(first.header().raw().as_builder().number(0u64).build())
                .build(),
        )
        .build();
    storage.init_genesis_block(genesis);
    storage.update_filter_scripts(
        vec![ScriptStatus {
            script: wallet.clone(),
            script_type: ScriptType::Lock,
            block_number: 0,
        }],
        SetScriptsCommand::Partial,
    );
    assert!(storage
        .get(Key::CellLockScript(&wallet, 0, 0, 1).into_vec())
        .unwrap()
        .is_some());
}
