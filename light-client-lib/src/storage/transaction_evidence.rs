//! Versioned receipt for transaction inclusion checked by SendTransactionsProof.
//! Exact-anchor equality is deliberately conservative: extensions expire receipts too.
//! This is provenance in the trusted local store, not a portable cryptographic proof.

use super::{BatchWriter, HeaderWithExtension, Key, StorageBackend, Value, LAST_STATE_KEY};
use crate::{
    error::{Error, Result},
    service::{TransactionEvidence, TransactionEvidenceState},
};
use ckb_types::{packed, prelude::*, H256};

pub(crate) fn receipt_key(hash: &packed::Byte32) -> Vec<u8> {
    let mut key = Key::Meta("TX_PROOF_V1:").into_vec();
    key.extend_from_slice(hash.as_slice());
    key
}

/// Crate-internal trusted write boundary. The sole production caller supplying
/// an anchor is SendTransactionsProofProcess, after all response checks succeed.
/// A stale response may replace a newer receipt, but cannot assert currentness:
/// currentness is computed from one database snapshot by the observer.
pub(crate) fn store_fetched_transaction<S: StorageBackend + ?Sized>(
    storage: &S,
    tx: &packed::Transaction,
    hwe: &HeaderWithExtension,
    proof_anchor: Option<&packed::Header>,
) -> Result<()> {
    let mut batch = storage.batch();
    let block_hash = hwe.header.calc_header_hash();
    let number: u64 = hwe.header.raw().number().unpack();
    let header_value: Vec<u8> = Value::HeaderWithExtension(hwe).into();
    batch.put(&Key::BlockHash(&block_hash).into_vec(), &header_value);
    batch.put(&Key::BlockNumber(number).into_vec(), block_hash.as_slice());
    let tx_hash = tx.calc_tx_hash();
    let value: Vec<u8> = Value::Transaction(number, u32::MAX, tx).into();
    batch.put(&Key::TxHash(&tx_hash).into_vec(), &value);
    let key = receipt_key(&tx_hash);
    if let Some(anchor) = proof_anchor {
        let receipt = TransactionProofReceipt {
            block_hash: block_hash.as_slice().try_into().expect("Byte32"),
            block_number: number,
            anchor_hash: anchor
                .calc_header_hash()
                .as_slice()
                .try_into()
                .expect("Byte32"),
            anchor_number: anchor.raw().number().unpack(),
        };
        batch.put(&key, &receipt.encode());
    } else {
        batch.delete(&key);
    }
    batch.commit()
}

/// Observe stored inclusion provenance at one database snapshot. The first read
/// only chooses the header key; the receipt is read and compared in the snapshot.
pub(crate) fn observe<S: StorageBackend>(storage: &S, hash: &H256) -> Result<TransactionEvidence> {
    let key = receipt_key(&hash.pack());
    let preview = storage.get(key.clone())?;
    let receipt = preview.as_deref().and_then(TransactionProofReceipt::decode);
    let mut keys = vec![
        Key::Meta(LAST_STATE_KEY).into_vec(),
        Key::TxHash(&hash.pack()).into_vec(),
        key,
    ];
    if let Some(receipt) = &receipt {
        keys.push(Key::BlockHash(&H256::from(receipt.block_hash).pack()).into_vec());
    }
    let rows = storage.get_many(&keys)?;
    if rows.len() != keys.len() {
        return Err(Error::runtime("incomplete evidence snapshot"));
    }
    let accepted = rows[0]
        .as_deref()
        .and_then(|row| row.get(32..))
        .and_then(|bytes| packed::Header::from_slice(bytes).ok())
        .ok_or_else(|| Error::runtime("invalid or missing accepted anchor"))?
        .into_view();
    let mut result = TransactionEvidence {
        state: TransactionEvidenceState::Unknown,
        transaction: None,
        accepted_anchor: accepted.clone().into(),
        proof_anchor_hash: None,
        proof_anchor_number: None,
        block_hash: None,
        block_number: None,
    };
    if preview != rows[2] {
        result.state = TransactionEvidenceState::ObservationChanged;
        return Ok(result);
    }
    let Some(bytes) = rows[1].as_deref() else {
        return Ok(result);
    };
    let number = bytes
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| Error::runtime("invalid stored transaction metadata"))?;
    let tx = bytes
        .get(12..)
        .and_then(|bytes| packed::Transaction::from_slice(bytes).ok())
        .ok_or_else(|| Error::runtime("invalid stored transaction"))?;
    if tx.calc_tx_hash() != hash.pack() {
        return Err(Error::runtime("stored transaction hash mismatch"));
    }
    result.transaction = Some(tx.into_view().into());
    result.state = TransactionEvidenceState::StoredWithoutEvidence;
    let Some(receipt) = receipt else {
        return Ok(result);
    };
    let header = rows[3]
        .as_deref()
        .and_then(|row| row.get(..packed::Header::TOTAL_SIZE))
        .and_then(|bytes| packed::Header::from_slice(bytes).ok())
        .map(|header| header.into_view());
    if receipt.block_number != number
        || receipt.block_number > receipt.anchor_number
        || !header.is_some_and(|header| {
            header.number() == number && header.hash().as_slice() == receipt.block_hash
        })
    {
        return Ok(result);
    }
    result.proof_anchor_hash = Some(H256::from(receipt.anchor_hash));
    result.proof_anchor_number = Some(receipt.anchor_number.into());
    result.block_hash = Some(H256::from(receipt.block_hash));
    result.block_number = Some(number.into());
    result.state = if receipt.matches_anchor(
        accepted.hash().as_slice().try_into().expect("Byte32"),
        accepted.number(),
    ) {
        TransactionEvidenceState::VerifiedCurrent
    } else {
        TransactionEvidenceState::VerifiedOtherAnchor
    };
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransactionProofReceipt {
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub anchor_hash: [u8; 32],
    pub anchor_number: u64,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "transaction_evidence_tests.rs"]
mod storage_tests;

impl TransactionProofReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(81);
        bytes.push(1);
        bytes.extend(self.block_hash);
        bytes.extend(self.block_number.to_le_bytes());
        bytes.extend(self.anchor_hash);
        bytes.extend(self.anchor_number.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 81 || bytes[0] != 1 {
            return None;
        }
        Some(Self {
            block_hash: bytes[1..33].try_into().ok()?,
            block_number: u64::from_le_bytes(bytes[33..41].try_into().ok()?),
            anchor_hash: bytes[41..73].try_into().ok()?,
            anchor_number: u64::from_le_bytes(bytes[73..81].try_into().ok()?),
        })
    }

    pub fn matches_anchor(&self, hash: &[u8; 32], number: u64) -> bool {
        &self.anchor_hash == hash && self.anchor_number == number
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionProofReceipt;

    fn receipt() -> TransactionProofReceipt {
        TransactionProofReceipt {
            block_hash: [7; 32],
            block_number: 50,
            anchor_hash: [9; 32],
            anchor_number: 100,
        }
    }

    #[test]
    fn receipt_round_trip_and_empty_data_rejection() {
        let receipt = receipt();
        let reopened = TransactionProofReceipt::decode(&receipt.encode()).unwrap();
        assert_eq!(reopened, receipt);
        assert!(reopened.matches_anchor(&[9; 32], 100));
        assert!(TransactionProofReceipt::decode(&[]).is_none());
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() {
        let bytes = receipt().encode();
        for length in 0..81 {
            assert!(TransactionProofReceipt::decode(&bytes[..length]).is_none());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(TransactionProofReceipt::decode(&trailing).is_none());
    }

    #[test]
    fn unknown_version_is_not_verification() {
        let mut bytes = receipt().encode();
        bytes[0] = 2;
        assert!(TransactionProofReceipt::decode(&bytes).is_none());
    }

    #[test]
    fn extension_same_height_fork_and_rollback_expire_evidence() {
        let receipt = receipt();
        assert!(!receipt.matches_anchor(&[10; 32], 101));
        assert!(!receipt.matches_anchor(&[10; 32], 100));
        assert!(!receipt.matches_anchor(&[8; 32], 99));
        assert!(!receipt.matches_anchor(&[9; 32], 99));
    }
}
