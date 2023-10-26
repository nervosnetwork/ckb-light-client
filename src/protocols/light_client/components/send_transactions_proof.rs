use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    packed,
    prelude::*,
    utilities::{merkle_mountain_range::VerifiableHeader, merkle_root, MerkleProof},
};
use log::{debug, error};

use crate::{protocols::light_client::components::verify_extra_hash, storage::HeaderWithExtension};

use super::{
    super::{LightClientProtocol, Status, StatusCode},
    verify_mmr_proof,
};

pub(crate) struct SendTransactionsProofProcess<'a> {
    message: packed::SendTransactionsProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer_index: PeerIndex,
    _nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendTransactionsProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendTransactionsProofReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer_index: PeerIndex,
        nc: &'a dyn CKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer_index,
            _nc: nc,
        }
    }

    pub(crate) fn execute(self) -> Status {
        let status = self.execute_internally();
        self.protocol
            .peers()
            .update_txs_proof_request(self.peer_index, None);
        status
    }

    fn execute_internally(&self) -> Status {
        let peer = return_if_failed!(self.protocol.get_peer(&self.peer_index));

        let original_request = if let Some(original_request) = peer.get_txs_proof_request() {
            original_request
        } else {
            error!("peer {} isn't waiting for a proof", self.peer_index);
            return StatusCode::PeerIsNotOnProcess.into();
        };

        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();

        // Update the last state if the response contains a new one.
        if original_request.last_hash() != last_header.header().hash() {
            if self.message.proof().is_empty()
                && self.message.filtered_blocks().is_empty()
                && self.message.missing_tx_hashes().is_empty()
            {
                return_if_failed!(self
                    .protocol
                    .process_last_state(self.peer_index, last_header));
                self.protocol
                    .peers()
                    .mark_fetching_txs_timeout(self.peer_index);
                return Status::ok();
            } else {
                // Since the last state is different, then no data should be contained.
                error!(
                    "peer {} send a proof with different last state",
                    self.peer_index
                );
                return StatusCode::UnexpectedResponse.into();
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
        if !original_request.check_tx_hashes(&received_tx_hashes, &missing_tx_hashes) {
            error!("peer {} send an unknown proof", self.peer_index);
            return StatusCode::UnexpectedResponse.into();
        }

        // If all transactions are missing.
        if self.message.filtered_blocks().is_empty() {
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
            let is_v1 = self.message.has_extra_fields() && self.message.count_extra_fields() >= 2;
            let extensions = if is_v1 {
                let message_v1 =
                    packed::SendTransactionsProofV1Reader::new_unchecked(self.message.as_slice());
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
            debug!("verify SendBlocksProof ok");

            for (filtered_block, extension) in filtered_blocks.into_iter().zip(extensions.iter()) {
                let header = filtered_block.header().into_view();
                for tx in filtered_block.transactions() {
                    if self
                        .protocol
                        .peers()
                        .remove_fetching_transaction(&tx.calc_tx_hash(), &header.hash())
                    {
                        self.protocol.storage().add_fetched_tx(
                            &tx,
                            &HeaderWithExtension {
                                header: header.data(),
                                extension: extension.as_ref().cloned(),
                            },
                        );
                    }
                }
            }
        }
        self.protocol
            .peers()
            .mark_fetching_txs_missing(&missing_tx_hashes);
        Status::ok()
    }
}
