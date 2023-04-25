use crate::protocols::FilterProtocol;
use crate::protocols::{Status, StatusCode};
use crate::utils::network::prove_or_download_matched_blocks;
use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::core::BlockNumber;
use ckb_types::utilities::calc_filter_hash;
use ckb_types::{packed, prelude::*};
use log::{info, trace, warn};
use rand::seq::SliceRandom;
use std::{cmp, sync::Arc};

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
        if self.filter.storage.is_filter_scripts_empty() {
            info!("ignoring, filter scripts may have been cleared during syncing");
            return Status::ok();
        }
        let peer_state_opt = self.filter.peers.get_state(&self.peer);
        if peer_state_opt.is_none() {
            info!("ignoring, peer {} is disconnected", self.peer);
            return Status::ok();
        }
        let peer_state = peer_state_opt.expect("checked Some");

        let prove_state_block_hash = if let Some(header) = peer_state
            .get_prove_state()
            .map(|prove_state| prove_state.get_last_header().header())
        {
            header.hash()
        } else {
            warn!("ignoring, peer {} prove state is none", self.peer);
            return Status::ok();
        };

        let block_filters = self.message.to_entity();
        let start_number: BlockNumber = block_filters.start_number().unpack();

        let min_filtered_block_number = self.filter.storage.get_min_filtered_block_number();
        if min_filtered_block_number + 1 != start_number {
            info!(
                "ignoring, the start_number of block_filters message {} is not continuous with min_filtered_block_number: {}",
                start_number,
                min_filtered_block_number
            );
            // Get matched blocks finished, update filter scripts block number
            if self.filter.storage.get_earliest_matched_blocks().is_none() {
                self.filter
                    .storage
                    .update_block_number(min_filtered_block_number);
            }
            return Status::ok();
        }

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

        let (finalized_check_point_index, finalized_check_point_hash) =
            self.filter.storage.get_last_check_point();
        let finalized_check_point_number = self
            .filter
            .peers
            .calc_check_point_number(finalized_check_point_index);

        let (mut parent_block_filter_hash, expected_block_filter_hashes) =
            if start_number <= finalized_check_point_number {
                // Use cached block filter hashes to check the block filters.
                let (cached_check_point_index, mut cached_block_filter_hashes) =
                    self.filter.peers.get_cached_block_filter_hashes();
                let cached_check_point_number = self
                    .filter
                    .peers
                    .calc_check_point_number(cached_check_point_index);
                let next_cached_check_point_number = self
                    .filter
                    .peers
                    .calc_check_point_number(cached_check_point_index + 1);
                trace!(
                    "check block filters (start: {}, len: {}), \
                     with cached block filter hashes: ({},{}]",
                    start_number,
                    filters_count,
                    cached_check_point_number,
                    next_cached_check_point_number
                );
                if start_number <= cached_check_point_number
                    || start_number > next_cached_check_point_number
                {
                    let errmsg = format!(
                        "first block filter (number: {}) could not be checked \
                         with cached block filter hashes ({},{}]",
                        start_number, cached_check_point_number, next_cached_check_point_number
                    );
                    return StatusCode::Ignore.with_context(errmsg);
                }
                if cached_block_filter_hashes.is_empty() {
                    let errmsg = "cached block filter hashes is empty";
                    return StatusCode::Ignore.with_context(errmsg);
                }
                if start_number == cached_check_point_number + 1 {
                    let cached_check_point = self
                        .filter
                        .storage
                        .get_check_points(cached_check_point_index, 1)
                        .get(0)
                        .cloned()
                        .expect("all check points before finalized should be existed");
                    (cached_check_point, cached_block_filter_hashes)
                } else {
                    let start_index = (start_number - cached_check_point_number) as usize - 2;
                    let parent_hash = cached_block_filter_hashes[start_index].clone();
                    cached_block_filter_hashes.drain(..=start_index);
                    (parent_hash, cached_block_filter_hashes)
                }
            } else {
                // Use latest block filter hashes to check the block filters.
                let mut latest_block_filter_hashes = self
                    .filter
                    .peers
                    .get_latest_block_filter_hashes(finalized_check_point_index);
                if start_number == finalized_check_point_number + 1 {
                    (finalized_check_point_hash, latest_block_filter_hashes)
                } else {
                    let start_index = (start_number - finalized_check_point_number) as usize - 2;
                    let parent_hash = latest_block_filter_hashes[start_index].clone();
                    latest_block_filter_hashes.drain(..=start_index);
                    (parent_hash, latest_block_filter_hashes)
                }
            };

        let limit = cmp::min(filters_count, expected_block_filter_hashes.len());

        for (index, (filter, expected_hash)) in block_filters
            .filters()
            .into_iter()
            .take(limit)
            .zip(expected_block_filter_hashes.into_iter())
            .enumerate()
        {
            let current_hash = calc_filter_hash(&parent_block_filter_hash, &filter).pack();
            if current_hash != expected_hash {
                let errmsg = format!(
                    "peer {}: block filter hash for block {} expect {:#x} but got {:#x}",
                    self.peer,
                    start_number + index as BlockNumber,
                    expected_hash,
                    current_hash,
                );
                return StatusCode::BlockFilterDataIsUnexpected.with_context(errmsg);
            }
            parent_block_filter_hash = current_hash;
        }

        let possible_match_blocks = self.filter.check_filters_data(block_filters, limit);
        let possible_match_blocks_len = possible_match_blocks.len();
        trace!(
            "peer {}, matched blocks: {}",
            self.peer,
            possible_match_blocks_len
        );
        let actual_blocks_count = blocks_count.min(limit);
        let tip_header = self.filter.storage.get_tip_header();
        let filtered_block_number = start_number - 1 + actual_blocks_count as BlockNumber;

        let mut matched_blocks = self
            .filter
            .peers
            .matched_blocks()
            .write()
            .expect("poisoned");
        if possible_match_blocks_len != 0 {
            let blocks = possible_match_blocks
                .iter()
                .map(|block_hash| (block_hash.clone(), block_hash == &prove_state_block_hash))
                .collect::<Vec<_>>();
            self.filter.storage.add_matched_blocks(
                start_number,
                actual_blocks_count as u64,
                blocks,
            );
            if matched_blocks.is_empty() {
                if let Some((_start_number, _blocks_count, db_blocks)) =
                    self.filter.storage.get_earliest_matched_blocks()
                {
                    self.filter
                        .peers
                        .add_matched_blocks(&mut matched_blocks, db_blocks);
                    prove_or_download_matched_blocks(
                        Arc::clone(&self.filter.peers),
                        &tip_header,
                        &matched_blocks,
                        self.nc.as_ref(),
                        INIT_BLOCKS_IN_TRANSIT_PER_PEER,
                    );
                }
            }
        } else if matched_blocks.is_empty() {
            self.filter
                .storage
                .update_block_number(filtered_block_number)
        }

        self.filter
            .update_min_filtered_block_number(filtered_block_number);

        let could_request_more_block_filters = self.filter.peers.could_request_more_block_filters(
            finalized_check_point_index,
            filtered_block_number + 1,
        );
        if could_request_more_block_filters {
            // send next batch GetBlockFilters message to a random best peer
            let best_peer = self
                .filter
                .peers
                .get_best_proved_peers(&tip_header)
                .into_iter()
                .filter(|peer| *peer != self.peer)
                .collect::<Vec<_>>()
                .choose(&mut rand::thread_rng())
                .cloned()
                .unwrap_or(self.peer);
            self.filter
                .send_get_block_filters(self.nc, best_peer, filtered_block_number + 1);
        } else {
            // if couldn't request more block filters,
            // check if could request more block filter hashes.
            self.filter.try_send_get_block_filter_hashes(self.nc);
        }

        Status::ok()
    }
}
