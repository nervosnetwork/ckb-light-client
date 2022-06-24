use super::super::{LastState, LightClientProtocol, Status, StatusCode};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256};
use log::trace;

pub(crate) struct SendLastStateProcess<'a> {
    message: packed::SendLastStateReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendLastStateProcess<'a> {
    pub(crate) fn new(
        message: packed::SendLastStateReader<'a>,
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
        let tip_header: VerifiableHeader = self.message.tip_header().to_entity().into();
        let tip_total_difficulty: U256 = self.message.total_difficulty().unpack();

        if !tip_header.is_valid(self.protocol.mmr_activated_number(), None) {
            return StatusCode::InvalidLastState.into();
        }

        let peer_state = self
            .protocol
            .peers()
            .get_state(&self.peer)
            .expect("checked: should have state");

        let is_initial = peer_state.get_last_state().is_none();
        if peer_state
            .get_last_state()
            .map(|last_state| last_state.total_difficulty < tip_total_difficulty)
            .unwrap_or(true)
        {
            trace!("peer {}: update last state", self.peer);
            self.protocol
                .peers()
                .update_last_state(self.peer, LastState::new(tip_header, tip_total_difficulty));
        }

        if is_initial {
            self.protocol.get_block_samples(self.nc, self.peer);
        }
        Status::ok()
    }
}
