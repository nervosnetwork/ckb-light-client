use crate::protocols::FilterProtocol;
use crate::protocols::{Status, StatusCode};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};
use log::{error, info};
use std::sync::Arc;
use std::time::Instant;

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
        let mut pending_peer = self
            .filter
            .pending_peer
            .write()
            .expect("accuire pending_peer write lock");

        if pending_peer.block_number != block_number {
            info!(
                "ignoring, block_number is not match, pending_peer: {}, block_filters: {}",
                pending_peer.block_number, block_number
            );
        } else {
            pending_peer.check_filters_data(block_filters);
            pending_peer.last_ask_time = Some(Instant::now());
            pending_peer.block_number = block_number + BATCH_SIZE;

            let content = packed::GetBlockFilters::new_builder()
                .start_number((block_number + BATCH_SIZE).pack())
                .build();

            let message = packed::BlockFilterMessage::new_builder()
                .set(content)
                .build();

            if let Err(err) = self.nc.send_message_to(self.peer, message.as_bytes()) {
                let error_message = format!("nc.send_message BlockFilterMessage, error: {:?}", err);
                error!("{}", error_message);
                return StatusCode::Network.with_context(error_message);
            }
        }
        Status::ok()
    }
}
