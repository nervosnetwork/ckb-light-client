use ckb_network::{BoxedCKBProtocolContext, PeerIndex};
use ckb_types::{
    packed,
    prelude::*,
    utilities::{merkle_mountain_range::VerifiableHeader, merkle_root, MerkleProof},
};
use log::{debug, error};

use crate::{
    protocols::light_client::components::{verify_extra_hash, verify_legacy_extra_hash},
    storage::HeaderWithExtension,
};

use super::{
    super::{LightClientProtocol, Status, StatusCode},
    verify_mmr_proof,
};

pub(crate) struct SendTransactionsProofProcess<'a> {
    message: packed::SendTransactionsProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer_index: PeerIndex,
    _nc: &'a BoxedCKBProtocolContext,
}

impl<'a> SendTransactionsProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendTransactionsProofReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer_index: PeerIndex,
        nc: &'a BoxedCKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer_index,
            _nc: nc,
        }
    }

    pub(crate) async fn execute(self) -> Status {
        let mut retire_request = false;
        let status = self.execute_internally(&mut retire_request).await;
        if retire_request {
            // Preserve retry eligibility before removing the identified request's
            // hash list. Peer discipline may allow an invalid response without
            // immediately disconnecting the peer.
            if !status.is_ok() {
                self.protocol
                    .peers()
                    .mark_fetching_txs_timeout(self.peer_index);
            }
            self.protocol
                .peers()
                .update_txs_proof_request(self.peer_index, None);
        }
        status
    }

    async fn execute_internally(&self, retire_request: &mut bool) -> Status {
        let peer = return_if_failed!(self.protocol.get_peer(&self.peer_index));

        let original_request = if let Some(original_request) = peer.get_txs_proof_request() {
            original_request
        } else {
            error!("peer {} isn't waiting for a proof", self.peer_index);
            // A response can arrive after timeout/replacement/completion. Ignore it
            // without attributing peer fault or changing any fetch bookkeeping.
            return Status::ok();
        };

        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();
        let filtered_blocks_len = self.message.filtered_blocks().len();
        // Parse the V1 extra fields with a verifying reader up front, before any
        // early return, so that all later access is over validated bytes and can
        // never panic on malformed/unchecked input.
        let message_v1 = if self.message.count_extra_fields() >= 2 {
            match packed::SendTransactionsProofV1Reader::from_compatible_slice(
                self.message.as_slice(),
            ) {
                Ok(message_v1) => {
                    let uncle_hashes_len = message_v1.blocks_uncles_hash().len();
                    let extensions_len = message_v1.blocks_extension().len();
                    if uncle_hashes_len != filtered_blocks_len
                        || extensions_len != filtered_blocks_len
                    {
                        let error_message = format!(
                            "SendTransactionsProof v1 field length mismatch: \
                             filtered_blocks={}, uncle_hashes={}, extensions={}",
                            filtered_blocks_len, uncle_hashes_len, extensions_len
                        );
                        return StatusCode::MalformedProtocolMessage.with_context(error_message);
                    }
                    Some(message_v1)
                }
                Err(_) => {
                    return StatusCode::MalformedProtocolMessage
                        .with_context("SendTransactionsProof v1 extra fields are malformed");
                }
            }
        } else {
            None
        };

        // Update the last state if the response contains a new one.
        if original_request.last_hash() != last_header.header().hash() {
            if self.message.proof().is_empty()
                && self.message.filtered_blocks().is_empty()
                && self.message.missing_tx_hashes().is_empty()
            {
                // No requested hashes are echoed, so this may announce an old
                // operation. Update the peer hint without draining the active slot.
                // Its matching reply or the existing timeout will retire it.
                return_if_failed!(self
                    .protocol
                    .process_last_state(self.peer_index, last_header));
                return Status::ok();
            } else {
                // Since the last state is different, then no data should be contained.
                error!(
                    "peer {} send a proof with different last state",
                    self.peer_index
                );
                // A late response must not retire a different outstanding operation.
                return Status::ok();
            }
        }

        let filtered_blocks: Vec<packed::FilteredBlock> = self
            .message
            .filtered_blocks()
            .to_entity()
            .into_iter()
            .collect();
        let headers: Vec<_> = filtered_blocks
            .iter()
            .map(|block| block.header().into_view())
            .collect();

        // Check if the response is match the request.
        let received_tx_hashes = filtered_blocks
            .iter()
            .flat_map(|block| block.transactions().into_iter().map(|tx| tx.calc_tx_hash()))
            .collect::<Vec<_>>();
        let missing_tx_hashes = self
            .message
            .missing_tx_hashes()
            .to_entity()
            .into_iter()
            .collect::<Vec<_>>();
        // Duplicates/overlap are intrinsically invalid, independently of the request slot.
        let mut distinct = std::collections::HashSet::new();
        if received_tx_hashes
            .iter()
            .chain(missing_tx_hashes.iter())
            .any(|hash| !distinct.insert(hash))
        {
            return StatusCode::UnexpectedResponse.into();
        }
        if !original_request.check_tx_hashes(&received_tx_hashes, &missing_tx_hashes) {
            debug!(
                "peer {} response does not match the outstanding hashes",
                self.peer_index
            );
            return Status::ok();
        }

        // Retire only the operation identified by both anchor and requested hashes.
        *retire_request = true;

        // The original request slot is retained until this response is drained.
        // A valid old-fork response must neither complete a fetch nor mark it missing.
        match crate::storage::canonical::anchor_current(
            self.protocol.storage(),
            &last_header.header().data(),
        ) {
            Ok(true) => {}
            Ok(false) => {
                self.protocol
                    .peers()
                    .mark_fetching_txs_timeout(self.peer_index);
                return Status::ok();
            }
            Err(error) => {
                self.protocol
                    .peers()
                    .mark_fetching_txs_timeout(self.peer_index);
                return StatusCode::InternalError.with_context(error.to_string());
            }
        }

        // If all transactions are missing.
        if filtered_blocks.is_empty() {
            if !self.message.proof().is_empty() {
                error!(
                    "peer {} send a proof when all transactions are missing",
                    self.peer_index
                );
                return StatusCode::UnexpectedResponse.into();
            }
        } else {
            // Check PoW for blocks
            return_if_failed!(self.protocol.check_pow_for_headers(headers.iter()));

            // Check extra hash for blocks
            let extensions = if let Some(message_v1) = message_v1 {
                let uncle_hashes: Vec<_> = message_v1
                    .blocks_uncles_hash()
                    .iter()
                    .map(|uncle_hashes| uncle_hashes.to_entity())
                    .collect();
                let extensions: Vec<_> = message_v1
                    .blocks_extension()
                    .iter()
                    .map(|extension| extension.to_entity().to_opt())
                    .collect();

                return_if_failed!(verify_extra_hash(&headers, &uncle_hashes, &extensions));
                extensions
            } else {
                // A legacy (v0) response carries neither uncle hashes nor
                // block extensions. Only accept it for headers which commit
                // to no such data; otherwise a malicious peer could omit a
                // CKB2023 block extension and the client would verify
                // transactions against incomplete data.
                return_if_failed!(verify_legacy_extra_hash(&headers));
                vec![None; headers.len()]
            };

            // Verify the proof
            return_if_failed!(verify_mmr_proof(
                self.protocol.mmr_activated_epoch(),
                &last_header,
                self.message.proof(),
                headers.iter(),
            ));

            // verify filtered blocks (transactions)
            for filtered_block in &filtered_blocks {
                let witnesses_root = filtered_block.witnesses_root();
                let proof = filtered_block.proof();
                let indices: Vec<u32> = proof.indices().into_iter().map(|v| v.unpack()).collect();
                let lemmas: Vec<packed::Byte32> = proof.lemmas().into_iter().collect();
                let merkle_proof = MerkleProof::new(indices, lemmas);
                match merkle_proof
                    .root(
                        &filtered_block
                            .transactions()
                            .into_iter()
                            .map(|tx| tx.calc_tx_hash())
                            .collect::<Vec<_>>(),
                    )
                    .map(|raw_transactions_root| {
                        filtered_block.header().raw().transactions_root()
                            == merkle_root(&[raw_transactions_root, witnesses_root])
                    }) {
                    Some(true) => {}
                    _ => {
                        let errmsg = format!(
                        "failed to verify the transactions merkle proof of filtered block {:#x}",
                        filtered_block.header().calc_header_hash()
                    );
                        return StatusCode::InvalidProof.with_context(errmsg);
                    }
                }
            }
            debug!("verify SendTransactionsProof ok");

            for (filtered_block, extension) in filtered_blocks.into_iter().zip(extensions.iter()) {
                let header = filtered_block.header().into_view();
                // CBMT proof indices are heap positions, not transaction ordinals.
                // Only the one-leaf case determines an ordinal without a block body.
                let index = if filtered_block.proof().indices().len() == 1
                    && Unpack::<u32>::unpack(
                        &filtered_block.proof().indices().get(0).expect("one index"),
                    ) == 0
                {
                    0
                } else {
                    u32::MAX
                };
                for tx in filtered_block.transactions() {
                    if let Err(error) = crate::storage::canonical::store_proved_transaction(
                        self.protocol.storage(),
                        &tx,
                        index,
                        &HeaderWithExtension {
                            header: header.data(),
                            extension: extension.clone(),
                        },
                        &last_header.header().data(),
                    ) {
                        self.protocol
                            .peers()
                            .mark_fetching_txs_timeout(self.peer_index);
                        return StatusCode::InternalError.with_context(error.to_string());
                    }
                    self.protocol
                        .peers()
                        .remove_fetching_transaction(&tx.calc_tx_hash(), &header.hash());
                }
            }
        }
        self.protocol
            .peers()
            .mark_fetching_txs_missing(&missing_tx_hashes);
        Status::ok()
    }
}
