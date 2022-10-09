use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader};
use log::{debug, error};
use rand::seq::SliceRandom;

use super::{
    super::{LightClientProtocol, Status, StatusCode},
    verify_mmr_proof,
};

pub(crate) struct SendBlocksProofProcess<'a> {
    message: packed::SendBlocksProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendBlocksProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendBlocksProofReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer: PeerIndex,
        nc: &'a dyn CKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer,
            nc,
        }
    }

    pub(crate) fn execute(self) -> Status {
        let status = self.execute_internally();
        self.protocol
            .peers()
            .update_blocks_proof_request(self.peer, None);
        status
    }

    fn execute_internally(&self) -> Status {
        let peer_state = return_if_failed!(self.protocol.get_peer_state(&self.peer));

        let original_request = if let Some(original_request) = peer_state.get_blocks_proof_request()
        {
            original_request
        } else {
            error!("peer {} isn't waiting for a proof", self.peer);
            return StatusCode::PeerIsNotOnProcess.into();
        };

        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();

        // Update the last state if the response contains a new one.
        if self.message.proof().is_empty() {
            return_if_failed!(self.protocol.process_last_state(self.peer, last_header));
            self.protocol
                .peers()
                .mark_fetching_headers_timeout(self.peer);
            return Status::ok();
        }

        let headers: Vec<_> = self
            .message
            .headers()
            .iter()
            .map(|header| header.to_entity().into_view())
            .collect();

        // Check if the response is match the request.
        {
            let received_block_hashes = headers
                .iter()
                .map(|header| header.hash())
                .collect::<Vec<_>>();
            if !original_request.is_same_as(&last_header.header().hash(), &received_block_hashes) {
                error!("peer {} send an unknown proof", self.peer);
                return StatusCode::UnexpectedResponse.into();
            }
        }

        // Check PoW for blocks
        return_if_failed!(self.protocol.check_pow_for_headers(headers.iter()));

        // Verify the proof
        return_if_failed!(verify_mmr_proof(
            self.protocol.mmr_activated_epoch(),
            &last_header,
            self.message.proof(),
            headers.iter(),
        ));

        // Get blocks
        {
            let block_hashes: Vec<packed::Byte32> =
                headers.iter().map(|header| header.hash()).collect();
            {
                let mut matched_blocks = self
                    .protocol
                    .peers()
                    .matched_blocks()
                    .write()
                    .expect("poisoned");
                self.protocol
                    .peers
                    .mark_matched_blocks_proved(&mut matched_blocks, &block_hashes);
            }

            let best_peers: Vec<_> = self
                .protocol
                .peers
                .get_best_proved_peers(&last_header.header().data())
                .into_iter()
                .filter_map(|peer| {
                    self.protocol
                        .peers
                        .get_state(&peer)
                        .map(|state| (peer, state))
                })
                .collect();

            if let Some((peer, _)) = best_peers
                .iter()
                .filter(|(_peer, peer_state)| peer_state.get_blocks_request().is_none())
                .collect::<Vec<_>>()
                .choose(&mut rand::thread_rng())
            {
                self.protocol
                    .peers
                    .update_blocks_request(*peer, Some(block_hashes.clone()));
                debug!(
                    "send get blocks request to peer: {}, matched_count: {}",
                    peer,
                    block_hashes.len()
                );
                for hashes in block_hashes.chunks(self.protocol.init_blocks_in_transit_per_peer()) {
                    let content = packed::GetBlocks::new_builder()
                        .block_hashes(hashes.to_vec().pack())
                        .build();
                    let message = packed::SyncMessage::new_builder()
                        .set(content)
                        .build()
                        .as_bytes();
                    if let Err(err) =
                        self.nc
                            .send_message(SupportProtocols::Sync.protocol_id(), *peer, message)
                    {
                        let error_message =
                            format!("nc.send_message SyncMessage, error: {:?}", err);
                        error!("{}", error_message);
                        return StatusCode::Network.with_context(error_message);
                    }
                }
            }
        }

        for header in headers {
            self.protocol.peers().add_header(header);
        }
        Status::ok()
    }
}
