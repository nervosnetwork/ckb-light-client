use crate::protocols::FilterProtocol;
use crate::protocols::{Status, StatusCode};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};
use log::{info, trace, warn};
use std::sync::Arc;

pub struct BlockFiltersProcess<'a> {
    message: packed::BlockFiltersReader<'a>,
    filter: &'a FilterProtocol,
    nc: Arc<dyn CKBProtocolContext + Sync>,
    peer: PeerIndex,
}

impl<'a> BlockFiltersProcess<'a> {
    pub fn new(
        message: packed::BlockFiltersReader<'a>,
        filter: &'a FilterProtocol,
        nc: Arc<dyn CKBProtocolContext + Sync>,
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
            let actual_blocks_count = blocks_count.min(limit);
            if possible_match_blocks_len != 0 {
                let mut matched_blocks = self
                    .filter
                    .peers
                    .matched_blocks()
                    .write()
                    .expect("poisoned");
                let blocks = possible_match_blocks
                    .iter()
                    .map(|block_hash| (block_hash.clone(), block_hash == &prove_state_block_hash))
                    .collect::<Vec<_>>();
                possible_match_blocks.retain(|block_hash| block_hash != &prove_state_block_hash);
                if possible_match_blocks.len() != possible_match_blocks_len {
                    self.filter.peers.add_matched_blocks(
                        &mut matched_blocks,
                        vec![(prove_state_block_hash, true)],
                    );
                }
                self.filter.peers.add_matched_blocks(
                    &mut matched_blocks,
                    possible_match_blocks
                        .into_iter()
                        .map(|hash| (hash, false))
                        .collect(),
                );
                self.filter
                    .prove_or_download_matched_blocks(&matched_blocks, self.peer, self.nc);
                // NOTE must insert matched blocks in storage later
                self.filter.pending_peer.storage.update_matched_blocks(
                    start_number,
                    actual_blocks_count as u64,
                    blocks,
                );
            } else {
                let filtered_block_number = start_number - 1 + actual_blocks_count as BlockNumber;
                pending_peer.update_block_number(filtered_block_number);
                // send next batch GetBlockFilters message to peer
                self.filter
                    .send_get_block_filters(self.nc, self.peer, filtered_block_number + 1);
            }
        }
        Status::ok()
    }
}
