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
        let peer_state = return_if_failed!(self.protocol.get_peer_state(&self.peer));

        let last_state = {
            let tip_header: VerifiableHeader = self.message.tip_header().to_entity().into();
            let tip_total_difficulty: U256 = self.message.total_difficulty().unpack();
            LastState::new(tip_header, tip_total_difficulty)
        };

        if !last_state
            .tip_header
            .is_valid(self.protocol.mmr_activated_epoch(), None)
        {
            return StatusCode::InvalidLastState.into();
        }

        self.protocol
            .peers()
            .update_last_state(self.peer, last_state.clone());

        if let Some(prev_last_state) = peer_state.get_last_state() {
            trace!("peer {}: update last state", self.peer);
            if prev_last_state.total_difficulty < last_state.total_difficulty {
                if let Some(prove_state) = peer_state.get_prove_state() {
                    let last_proved_header = prove_state.get_last_header();
                    if last_state.tip_header.header().parent_hash()
                        == last_proved_header.header().hash()
                        && self
                            .protocol
                            .check_pow_for_header(last_state.tip_header.header())
                            .is_ok()
                    {
                        trace!("peer {}: new last state could be trusted", self.peer);
                        let child_prove_state = prove_state.new_child(last_state);
                        self.protocol
                            .update_prove_state_to_child(self.peer, child_prove_state);
                    }
                }
            }
        } else {
            trace!("peer {}: initialize last state", self.peer);
            self.protocol.get_block_samples(self.nc, self.peer);
        }

        Status::ok()
    }
}
