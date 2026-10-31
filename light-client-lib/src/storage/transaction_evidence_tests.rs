//! Trusted storage fixtures test observation/atomicity, not proof acceptance.
//! Proof acceptance is separately tested through the real protocol handler.
use super::*;
use crate::storage::{LightClientStorage, Storage};
use ckb_types::{core, U256};

fn fixture() -> (
    Storage,
    tempfile::TempDir,
    packed::Transaction,
    HeaderWithExtension,
    packed::Header,
) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let tx = core::TransactionBuilder::default()
        .output(packed::CellOutput::default())
        .output_data(packed::Bytes::default())
        .build()
        .data();
    let header = core::HeaderBuilder::default()
        .number(10u64)
        .epoch(core::EpochNumberWithFraction::new(0, 10, 100))
        .build()
        .data();
    let anchor = core::HeaderBuilder::default()
        .number(20u64)
        .epoch(core::EpochNumberWithFraction::new(0, 20, 100))
        .build()
        .data();
    storage.update_last_state(&U256::one(), &anchor, &[]);
    let hwe = HeaderWithExtension {
        header,
        extension: None,
    };
    store_fetched_transaction(&storage, &tx, &hwe, Some(&anchor)).unwrap();
    (storage, directory, tx, hwe, anchor)
}

#[test]
fn binds_transaction_header_height_and_anchor_and_survives_reopen() {
    let (storage, directory, tx, hwe, anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let evidence = observe(&storage, &hash).unwrap();
    assert_eq!(evidence.state, TransactionEvidenceState::VerifiedCurrent);
    assert_eq!(
        evidence.block_hash,
        Some(hwe.header.calc_header_hash().unpack())
    );
    assert_eq!(
        evidence.proof_anchor_hash,
        Some(anchor.calc_header_hash().unpack())
    );
    drop(storage);
    let reopened = Storage::new(directory.path());
    assert_eq!(
        observe(&reopened, &hash).unwrap().state,
        TransactionEvidenceState::VerifiedCurrent
    );
}

#[test]
fn tip_extension_fork_and_rollback_do_not_reuse_current_status() {
    let (storage, _directory, tx, _hwe, anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    for (number, nonce) in [(21u64, 0u128), (20, 1), (19, 2)] {
        let changed = anchor
            .clone()
            .into_view()
            .as_advanced_builder()
            .number(number)
            .nonce(nonce)
            .build();
        storage.update_last_state(&U256::one(), &changed.data(), &[]);
        assert_eq!(
            observe(&storage, &hash).unwrap().state,
            TransactionEvidenceState::VerifiedOtherAnchor
        );
    }
    storage.rollback_to_block(10);
    assert_ne!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::VerifiedCurrent
    );
}

#[test]
fn malformed_receipt_and_header_fail_closed_without_panicking() {
    let (storage, _directory, tx, hwe, _anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let key = receipt_key(&tx.calc_tx_hash());
    let original = storage.get(key.clone()).unwrap().unwrap();
    for bytes in [vec![], vec![2], original[..80].to_vec()] {
        storage.put(key.clone(), bytes).unwrap();
        assert_eq!(
            observe(&storage, &hash).unwrap().state,
            TransactionEvidenceState::StoredWithoutEvidence
        );
    }
    storage.put(key, original).unwrap();
    storage
        .put(
            Key::BlockHash(&hwe.header.calc_header_hash()).into_vec(),
            vec![0],
        )
        .unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::StoredWithoutEvidence
    );
}

#[test]
fn malformed_transaction_anchor_and_hash_mismatch_are_errors() {
    let (storage, _directory, tx, _hwe, _anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let key = Key::TxHash(&tx.calc_tx_hash()).into_vec();
    let original = storage.get(key.clone()).unwrap().unwrap();
    for bytes in [vec![], original[..11].to_vec()] {
        storage.put(key.clone(), bytes).unwrap();
        assert!(observe(&storage, &hash).is_err());
    }
    storage.put(key, original.clone()).unwrap();
    let other = packed::Byte32::new([1; 32]);
    storage
        .put(Key::TxHash(&other).into_vec(), original)
        .unwrap();
    assert!(observe(&storage, &other.unpack()).is_err());
    storage
        .put(Key::Meta(LAST_STATE_KEY).into_vec(), vec![0])
        .unwrap();
    assert!(observe(&storage, &hash).is_err());
}

#[test]
fn altered_inclusion_hash_or_height_cannot_be_promoted() {
    let (storage, _directory, tx, hwe, _anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let key = receipt_key(&tx.calc_tx_hash());
    let bytes = storage.get(key.clone()).unwrap().unwrap();
    let mut receipt = TransactionProofReceipt::decode(&bytes).unwrap();
    receipt.block_number += 1;
    storage.put(key.clone(), receipt.encode()).unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::StoredWithoutEvidence
    );
    receipt.block_number -= 1;
    receipt.block_hash = [5; 32];
    // Even a same-height header under the wrong key cannot satisfy hash binding.
    storage
        .put(
            Key::BlockHash(&H256::from(receipt.block_hash).pack()).into_vec(),
            hwe.header.as_slice().to_vec(),
        )
        .unwrap();
    storage.put(key, receipt.encode()).unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::StoredWithoutEvidence
    );
}

#[test]
fn legacy_write_clears_receipt_and_missing_transaction_is_not_verified() {
    let (storage, _directory, tx, hwe, _anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    storage.add_fetched_tx(&tx, &hwe);
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::StoredWithoutEvidence
    );
    storage
        .delete(&Key::TxHash(&tx.calc_tx_hash()).into_vec())
        .unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::Unknown
    );
}

#[test]
fn late_old_receipt_cannot_claim_current_after_newer_response() {
    let (storage, _directory, tx, hwe, old) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let new = old
        .clone()
        .into_view()
        .as_advanced_builder()
        .nonce(99u128)
        .build()
        .data();
    storage.update_last_state(&U256::one(), &new, &[]);
    store_fetched_transaction(&storage, &tx, &hwe, Some(&new)).unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::VerifiedCurrent
    );
    store_fetched_transaction(&storage, &tx, &hwe, Some(&old)).unwrap();
    assert_eq!(
        observe(&storage, &hash).unwrap().state,
        TransactionEvidenceState::VerifiedOtherAnchor
    );
}

#[test]
fn concurrent_atomic_updates_never_mix_receipt_and_accepted_anchor() {
    let (storage, _directory, tx, _hwe, anchor) = fixture();
    let hash = tx.calc_tx_hash().unpack();
    let key = receipt_key(&tx.calc_tx_hash());
    let receipt =
        TransactionProofReceipt::decode(&storage.get(key.clone()).unwrap().unwrap()).unwrap();
    let writer = storage.clone();
    let handle = std::thread::spawn(move || {
        for nonce in 1..300u128 {
            let header = anchor
                .clone()
                .into_view()
                .as_advanced_builder()
                .nonce(nonce)
                .build();
            let mut receipt = receipt.clone();
            receipt.anchor_hash = header.hash().as_slice().try_into().unwrap();
            let mut batch = writer.batch();
            let mut state = U256::one().to_le_bytes().to_vec();
            state.extend_from_slice(header.data().as_slice());
            batch.put(&Key::Meta(LAST_STATE_KEY).into_vec(), &state);
            batch.put(&key, &receipt.encode());
            batch.commit().unwrap();
        }
    });
    for _ in 0..300 {
        let evidence = observe(&storage, &hash).unwrap();
        assert!(matches!(
            evidence.state,
            TransactionEvidenceState::VerifiedCurrent
                | TransactionEvidenceState::ObservationChanged
        ));
        if evidence.state == TransactionEvidenceState::VerifiedCurrent {
            assert_eq!(
                evidence.proof_anchor_hash.as_ref(),
                Some(&evidence.accepted_anchor.hash)
            );
        }
    }
    handle.join().unwrap();
}

#[test]
fn changed_receipt_between_key_selection_and_snapshot_is_retryable() {
    use crate::storage::{FilterMapFn, IteratorDirection, IteratorStart, KVPair, TakeWhileFn};
    struct Changing(Storage);
    impl StorageBackend for Changing {
        type Batch = <Storage as StorageBackend>::Batch;
        fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
            let previous = self.0.get(key.clone())?;
            self.0.delete(&key)?;
            Ok(previous)
        }
        fn get_many(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
            self.0.get_many(keys)
        }
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
            self.0.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.0.delete(key)
        }
        fn batch(&self) -> Self::Batch {
            self.0.batch()
        }
        fn collect_iterator(
            &self,
            start: IteratorStart,
            direction: IteratorDirection,
            take: TakeWhileFn,
            filter: FilterMapFn,
            limit: usize,
        ) -> Vec<KVPair> {
            self.0
                .collect_iterator(start, direction, take, filter, limit)
        }
    }
    let (storage, _directory, tx, _hwe, _anchor) = fixture();
    let result = observe(&Changing(storage), &tx.calc_tx_hash().unpack()).unwrap();
    assert_eq!(result.state, TransactionEvidenceState::ObservationChanged);
    assert!(result.transaction.is_none());
    assert!(result.proof_anchor_hash.is_none());
}

#[cfg(feature = "sqlite")]
#[test]
fn receipt_write_failure_rolls_back_transaction_and_header_writes() {
    let (storage, directory, tx, hwe, anchor) = fixture();
    let connection = rusqlite::Connection::open(directory.path().join("db.sqlite")).unwrap();
    let prefix = Key::Meta("TX_PROOF_V1:")
        .into_vec()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    connection.execute_batch(&format!("CREATE TRIGGER reject_receipt BEFORE INSERT ON kv_store WHEN hex(NEW.key) LIKE '{prefix}%' BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;")).unwrap();
    let new_tx = tx
        .into_view()
        .as_advanced_builder()
        .version(1u32)
        .build()
        .data();
    let new_hwe = HeaderWithExtension {
        header: hwe
            .header
            .into_view()
            .as_advanced_builder()
            .number(11u64)
            .epoch(core::EpochNumberWithFraction::new(0, 11, 100))
            .nonce(99u128)
            .build()
            .data(),
        extension: None,
    };
    let keys = vec![
        Key::TxHash(&new_tx.calc_tx_hash()).into_vec(),
        receipt_key(&new_tx.calc_tx_hash()),
        Key::BlockHash(&new_hwe.header.calc_header_hash()).into_vec(),
        Key::BlockNumber(11).into_vec(),
    ];
    let before = storage.get_many(&keys).unwrap();
    assert!(before.iter().all(Option::is_none));
    assert!(store_fetched_transaction(&storage, &new_tx, &new_hwe, Some(&anchor)).is_err());
    assert_eq!(storage.get_many(&keys).unwrap(), before);
}
