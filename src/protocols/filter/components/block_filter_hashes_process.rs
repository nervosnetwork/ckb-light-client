use std::sync::Arc;

use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};
use log::trace;
use rand::seq::SliceRandom as _;

use crate::protocols::{FilterProtocol, Status, StatusCode};

pub struct BlockFilterHashesProcess<'a> {
    message: packed::BlockFilterHashesReader<'a>,
    protocol: &'a FilterProtocol,
    nc: Arc<dyn CKBProtocolContext + Sync>,
    peer_index: PeerIndex,
}

impl<'a> BlockFilterHashesProcess<'a> {
    pub fn new(
        message: packed::BlockFilterHashesReader<'a>,
        protocol: &'a FilterProtocol,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
    ) -> Self {
        Self {
            message,
            nc,
            protocol,
            peer_index,
        }
    }

    pub fn execute(self) -> Status {
        let peer_state = if let Some(peer_state) = self.protocol.peers.get_state(&self.peer_index) {
            peer_state
        } else {
            let errmsg = "peer is disconnected";
            return StatusCode::Ignore.with_context(errmsg);
        };

        let prove_number = if let Some(prove_state) = peer_state.get_prove_state() {
            prove_state.get_last_header().header().number()
        } else {
            let errmsg = "peer is not proved";
            return StatusCode::Ignore.with_context(errmsg);
        };

        let start_number: BlockNumber = self.message.start_number().unpack();
        let parent_block_filter_hash = self.message.parent_block_filter_hash().to_entity();
        let block_filter_hashes = self
            .message
            .block_filter_hashes()
            .iter()
            .map(|item| item.to_entity())
            .collect::<Vec<_>>();

        trace!(
            "peer {}: last-state: {}, add block filter hashes (start: {}, len: {}) \
            and parent block filter hash is {:#x}",
            self.peer_index,
            peer_state,
            start_number,
            block_filter_hashes.len(),
            parent_block_filter_hash
        );

        let (finalized_check_point_index, finalized_check_point) =
            self.protocol.storage.get_last_check_point();
        let finalized_check_point_number = self
            .protocol
            .peers
            .calc_check_point_number(finalized_check_point_index);

        let (cached_check_point_index, cached_hashes) =
            self.protocol.peers.get_cached_block_filter_hashes();
        let cached_check_point_number = self
            .protocol
            .peers
            .calc_check_point_number(cached_check_point_index);
        let next_cached_check_point_number = self
            .protocol
            .peers
            .calc_check_point_number(cached_check_point_index + 1);

        trace!(
            "finalized: index {}, number {}; \
             cached: index {}, number {}, length {}; \
             next cached: number {}",
            finalized_check_point_index,
            finalized_check_point_number,
            cached_check_point_index,
            cached_check_point_number,
            cached_hashes.len(),
            next_cached_check_point_number
        );

        if start_number <= finalized_check_point_number
            && cached_check_point_number < start_number
            && start_number <= next_cached_check_point_number
        {
            // Check block numbers.
            let cached_last_number = cached_check_point_number + cached_hashes.len() as BlockNumber;
            if start_number > cached_last_number + 1 {
                let errmsg = format!(
                    "start number ({}) is continuous with cached last number ({})",
                    start_number, cached_last_number
                );
                return StatusCode::Ignore.with_context(errmsg);
            }

            // Check cached block filter hashes.
            let (cached_check_point, next_cached_check_point) = {
                let cached_check_points = self
                    .protocol
                    .storage
                    .get_check_points(cached_check_point_index, 2);
                (
                    cached_check_points[0].clone(),
                    cached_check_points[1].clone(),
                )
            };

            if start_number == cached_check_point_number + 1 {
                if cached_check_point != parent_block_filter_hash {
                    let errmsg = format!(
                        "check point for block {} is {:#x} but parent hash is {:#x}",
                        start_number, cached_check_point, parent_block_filter_hash
                    );
                    return StatusCode::BlockFilterHashesIsUnexpected.with_context(errmsg);
                }
            } else {
                // This branch must be satisfied `start_number > cached_check_point_number + 1`.
                let diff = start_number - cached_check_point_number;
                let index = diff as usize - 2;
                let cached_hash = &cached_hashes[index];
                if *cached_hash != parent_block_filter_hash {
                    let errmsg = format!(
                        "cached hash for block {} is {:#x} but parent hash is {:#x}",
                        start_number - 1,
                        cached_hash,
                        parent_block_filter_hash
                    );
                    return StatusCode::Ignore.with_context(errmsg);
                }
            };
            let end_number = start_number + block_filter_hashes.len() as BlockNumber - 1;
            if end_number > next_cached_check_point_number {
                let diff = end_number - next_cached_check_point_number;
                let index = block_filter_hashes.len() - (diff as usize) - 1;
                let new_hash = &block_filter_hashes[index];
                if next_cached_check_point != *new_hash {
                    let errmsg = format!(
                        "check point for block {} is {:#x} but got {:#}",
                        next_cached_check_point_number, next_cached_check_point, new_hash
                    );
                    return StatusCode::BlockFilterHashesIsUnexpected.with_context(errmsg);
                }
            }
            let index_offset = (start_number - (cached_check_point_number + 1)) as usize;
            for (index, (old_hash, new_hash)) in cached_hashes[index_offset..]
                .iter()
                .zip(block_filter_hashes.iter())
                .enumerate()
            {
                if old_hash != new_hash {
                    let number = start_number + (index_offset + index) as BlockNumber;
                    let errmsg = format!(
                        "cached hash for block {} is {:#x} but new is {:#}",
                        number, old_hash, new_hash
                    );
                    return StatusCode::Ignore.with_context(errmsg);
                }
            }

            // Update cached block filter hashes.
            let start_index = cached_hashes[index_offset..].len();
            let mut new_cached_hashes = cached_hashes;
            if end_number > next_cached_check_point_number {
                let excess_size = (end_number - next_cached_check_point_number) as usize;
                let new_size = block_filter_hashes.len() - excess_size;
                new_cached_hashes.extend_from_slice(&block_filter_hashes[start_index..new_size]);
            } else {
                new_cached_hashes.extend_from_slice(&block_filter_hashes[start_index..]);
            }
            self.protocol
                .peers
                .update_cached_block_filter_hashes(new_cached_hashes);

            if end_number < next_cached_check_point_number {
                let best_peers = self
                    .protocol
                    .peers
                    .get_all_proved_check_points()
                    .into_iter()
                    .filter_map(|(peer_index, (cpindex, _check_points))| {
                        if peer_index == self.peer_index {
                            None
                        } else if cpindex >= finalized_check_point_index {
                            Some(peer_index)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let best_peer = best_peers
                    .choose(&mut rand::thread_rng())
                    .cloned()
                    .unwrap_or(self.peer_index);
                self.protocol
                    .send_get_block_filter_hashes(self.nc, best_peer, end_number + 1);
            } else {
                // if couldn't request more block filter hashes,
                // check if could request more block filters.
                self.protocol.try_send_get_block_filters(self.nc, true);
            }
        } else if start_number > finalized_check_point_number {
            let next_start_number_opt =
                return_if_failed!(self.protocol.peers.update_latest_block_filter_hashes(
                    self.peer_index,
                    prove_number,
                    finalized_check_point_index,
                    &finalized_check_point,
                    start_number,
                    &parent_block_filter_hash,
                    &block_filter_hashes
                ));

            if let Some(next_start_number) = next_start_number_opt {
                self.protocol.send_get_block_filter_hashes(
                    self.nc,
                    self.peer_index,
                    next_start_number,
                );
            }
        } else {
            let errmsg = format!(
                "unknown start block number: {}, \
                cached in ({},{}], finalized starts at {}",
                start_number,
                cached_check_point_number,
                next_cached_check_point_number,
                finalized_check_point_number
            );
            return StatusCode::Ignore.with_context(errmsg);
        }

        Status::ok()
    }
}
