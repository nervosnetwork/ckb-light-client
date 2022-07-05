use crate::protocols::FilterProtocol;
use crate::protocols::{Status, StatusCode};
use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};
use log::{error, info, trace, warn};
use std::sync::Arc;

pub struct BlockFiltersProcess<'a> {
    message: packed::BlockFiltersReader<'a>,
    filter: &'a FilterProtocol,
    nc: Arc<dyn CKBProtocolContext>,
    peer: PeerIndex,
}

impl<'a> BlockFiltersProcess<'a> {
    pub fn new(
        message: packed::BlockFiltersReader<'a>,
        filter: &'a FilterProtocol,
        nc: Arc<dyn CKBProtocolContext>,
        peer: PeerIndex,
    ) -> Self {
        Self {
            message,
            nc,
            filter,
            peer,
        }
    }

    pub fn execute(self) -> Status {
        let peer_state = self.filter.peers.get_state(&self.peer);
        if peer_state.is_none() {
            info!("ignoring, peer {} is disconnected", self.peer);
            return Status::ok();
        }

        let (prove_state_block_number, prove_state_block_hash) = if let Some(header) = peer_state
            .expect("checked Some")
            .get_prove_state()
            .map(|prove_state| prove_state.get_last_header().header())
        {
            (header.number(), header.hash())
        } else {
            warn!("ignoring, peer {} prove state is none", self.peer);
            return Status::ok();
        };

        let block_filters = self.message.to_entity();
        let start_number: BlockNumber = block_filters.start_number().unpack();
        let pending_peer = &self.filter.pending_peer;

        if pending_peer.min_block_number() != start_number {
            info!(
                "ignoring, start_number is not match, pending_peer: {}, block_filters: {}",
                pending_peer.min_block_number(),
                start_number
            );
        } else {
            let filters_count = block_filters.filters().len();
            if filters_count == 0 {
                info!("no new filters, ignore peer: {}", self.peer);
                return Status::ok();
            }

            let blocks_count = block_filters.block_hashes().len();
            if filters_count != blocks_count {
                let error_message = format!(
                    "filters length ({}) not equal to block_hashes length ({})",
                    filters_count, blocks_count
                );
                return StatusCode::MalformedProtocolMessage.with_context(error_message);
            }

            // send GetBlock message to peer
            if prove_state_block_number < start_number {
                warn!(
                    "ignoring, peer {} prove_state_block_number {} is smaller than start_nuber {}",
                    self.peer, prove_state_block_number, start_number
                );
                return Status::ok();
            }
            let limit = (prove_state_block_number - start_number + 1) as usize;
            let possible_match_blocks = pending_peer.check_filters_data(block_filters, limit);
            {
                trace!(
                    "send get block proof to peer: {}, matched blocks: {}",
                    self.peer,
                    possible_match_blocks.len()
                );
                let content = packed::GetBlockProof::new_builder()
                    .block_hashes(possible_match_blocks.pack())
                    .tip_hash(prove_state_block_hash)
                    .build();

                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build();

                if let Err(err) = self.nc.send_message(
                    SupportProtocols::LightClient.protocol_id(),
                    self.peer,
                    message.as_bytes(),
                ) {
                    let error_message =
                        format!("nc.send_message LightClientMessage, error: {:?}", err);
                    error!("{}", error_message);
                    return StatusCode::Network.with_context(error_message);
                } else {
                    self.filter
                        .peers
                        .push_block_proof_request(self.peer, content);
                }
            }

            let next_batch_start_number = start_number + blocks_count.min(limit) as BlockNumber;
            // send next batch GetBlockFilters message to peer
            pending_peer.update_block_number(next_batch_start_number);
            {
                let content = packed::GetBlockFilters::new_builder()
                    .start_number((next_batch_start_number).pack())
                    .build();

                let message = packed::BlockFilterMessage::new_builder()
                    .set(content)
                    .build();

                if let Err(err) = self.nc.send_message_to(self.peer, message.as_bytes()) {
                    let error_message =
                        format!("nc.send_message BlockFilterMessage, error: {:?}", err);
                    error!("{}", error_message);
                    return StatusCode::Network.with_context(error_message);
                }
            }
        }
        Status::ok()
    }
}
