use crate::protocols::FilterProtocol;
use crate::protocols::{Status, StatusCode};
use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};
use log::{error, info};
use std::sync::Arc;

const BATCH_SIZE: BlockNumber = 100;

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
        let block_filters = self.message.to_entity();
        let block_number: BlockNumber = block_filters.start_number().unpack();
        let pending_peer = &self.filter.pending_peer;

        if pending_peer.min_block_number() != block_number {
            info!(
                "ignoring, block_number is not match, pending_peer: {}, block_filters: {}",
                pending_peer.min_block_number(),
                block_number
            );
        } else {
            if block_filters.filters().len() != block_filters.block_hashes().len() {
                let error_message = format!("filters length not equal to block_hashes length");
                return StatusCode::MalformedProtocolMessage.with_context(error_message);
            }

            // send GetBlock message to peer
            let possible_match_blocks = pending_peer.check_filters_data(block_filters);
            {
                let content = packed::GetBlocks::new_builder()
                    .block_hashes(possible_match_blocks.pack())
                    .build();

                let message = packed::SyncMessage::new_builder().set(content).build();

                if let Err(err) = self.nc.send_message(
                    SupportProtocols::Sync.protocol_id(),
                    self.peer,
                    message.as_bytes(),
                ) {
                    let error_message = format!("nc.send_message SyncMessage, error: {:?}", err);
                    error!("{}", error_message);
                    return StatusCode::Network.with_context(error_message);
                }
            }

            // send next batch GetBlockFilters message to peer
            pending_peer.update_block_number(block_number + BATCH_SIZE);
            {
                let content = packed::GetBlockFilters::new_builder()
                    .start_number((block_number + BATCH_SIZE).pack())
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
