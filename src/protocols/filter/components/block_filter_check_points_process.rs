use std::sync::Arc;

use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};
use log::trace;

use crate::protocols::{FilterProtocol, Status, StatusCode};

pub struct BlockFilterCheckPointsProcess<'a> {
    message: packed::BlockFilterCheckPointsReader<'a>,
    protocol: &'a FilterProtocol,
    nc: Arc<dyn CKBProtocolContext + Sync>,
    peer_index: PeerIndex,
}

impl<'a> BlockFilterCheckPointsProcess<'a> {
    pub fn new(
        message: packed::BlockFilterCheckPointsReader<'a>,
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
        let check_points = self
            .message
            .block_filter_hashes()
            .iter()
            .map(|item| item.to_entity())
            .collect::<Vec<_>>();

        trace!(
            "peer {}: last-state: {}, add check points (start: {}, len: {})",
            self.peer_index,
            peer_state,
            start_number,
            check_points.len()
        );

        let next_start_number_opt = return_if_failed!(self.protocol.peers.add_check_points(
            self.peer_index,
            prove_number,
            start_number,
            &check_points
        ));

        if let Some(next_start_number) = next_start_number_opt {
            self.protocol.send_get_block_filter_check_points(
                self.nc,
                self.peer_index,
                next_start_number,
            );
        }

        Status::ok()
    }
}
