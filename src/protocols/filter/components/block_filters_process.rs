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
        let peer_state_opt = self.filter.peers.get_state(&self.peer);
        if peer_state_opt.is_none() {
            info!("ignoring, peer {} is disconnected", self.peer);
            return Status::ok();
        }
        let peer_state = peer_state_opt.expect("checked Some");

        let (prove_state_block_number, prove_state_block_hash) = if let Some(header) = peer_state
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

        let min_filtered_block_number = pending_peer.min_filtered_block_number();
        if min_filtered_block_number + 1 != start_number {
            info!(
                "ignoring, the start_number of block_filters message {} is not continuous with min_filtered_block_number: {}",
                start_number,
                min_filtered_block_number
            );
        } else {
            let filters_count = block_filters.filters().len();
            let blocks_count = block_filters.block_hashes().len();

            if filters_count != blocks_count {
                let error_message = format!(
                    "filters length ({}) not equal to block_hashes length ({})",
                    filters_count, blocks_count
                );
                return StatusCode::MalformedProtocolMessage.with_context(error_message);
            }

            if filters_count == 0 {
                info!("no new filters, ignore peer: {}", self.peer);
                return Status::ok();
            }

            if prove_state_block_number < start_number {
                warn!(
                    "ignoring, peer {} prove_state_block_number {} is smaller than start_number {}",
                    self.peer, prove_state_block_number, start_number
                );
                return Status::ok();
            }
            let limit = (prove_state_block_number - start_number + 1) as usize;
            let mut possible_match_blocks = pending_peer.check_filters_data(block_filters, limit);
            let possible_match_blocks_len = possible_match_blocks.len();
            trace!(
                "peer {}, matched blocks: {}",
                self.peer,
                possible_match_blocks_len
            );
            if possible_match_blocks_len != 0 {
                if peer_state.get_block_proof_request().is_some() {
                    warn!("peer {} has an inflight GetBlocksProof request", self.peer);
                } else {
                    // if the only matched block is the prove state block, then request block data directly
                    possible_match_blocks
                        .retain(|block_hash| block_hash != &prove_state_block_hash);
                    if possible_match_blocks.is_empty() {
                        let content = packed::GetBlocks::new_builder()
                            .block_hashes(vec![prove_state_block_hash].pack())
                            .build();
                        let message = packed::SyncMessage::new_builder().set(content).build();

                        if let Err(err) = self.nc.send_message(
                            SupportProtocols::Sync.protocol_id(),
                            self.peer,
                            message.as_bytes(),
                        ) {
                            let error_message =
                                format!("nc.send_message SyncMessage, error: {:?}", err);
                            error!("{}", error_message);
                            return StatusCode::Network.with_context(error_message);
                        }
                    } else {
                        let fetch_tip = possible_match_blocks_len != possible_match_blocks.len();

                        if peer_state
                            .get_block_proof_request()
                            .map(|req| {
                                req.is_same_as(&prove_state_block_hash, &possible_match_blocks)
                            })
                            .unwrap_or(false)
                        {
                            trace!("already sent block proof request to peer: {}", self.peer);
                        } else {
                            trace!("send block proof request to peer: {}", self.peer);
                            let content = packed::GetBlocksProof::new_builder()
                                .block_hashes(possible_match_blocks.pack())
                                .last_hash(prove_state_block_hash)
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
                                self.filter.peers.update_block_proof_request(
                                    self.peer,
                                    Some((content, fetch_tip)),
                                );
                            }
                        }
                    }
                }
            }

            let filtered_block_number = start_number - 1 + blocks_count.min(limit) as BlockNumber;
            pending_peer.update_block_number(filtered_block_number);
            // send next batch GetBlockFilters message to peer
            {
                let content = packed::GetBlockFilters::new_builder()
                    .start_number((filtered_block_number + 1).pack())
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
