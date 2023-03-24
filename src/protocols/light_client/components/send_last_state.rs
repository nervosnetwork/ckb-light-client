use super::super::{LastState, LightClientProtocol, Status};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader};
use log::{debug, trace};

pub(crate) struct SendLastStateProcess<'a> {
    message: packed::SendLastStateReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer_index: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendLastStateProcess<'a> {
    pub(crate) fn new(
        message: packed::SendLastStateReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer_index: PeerIndex,
        nc: &'a dyn CKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer_index,
            nc,
        }
    }

    pub(crate) fn execute(self) -> Status {
        let peer_state = return_if_failed!(self.protocol.get_peer_state(&self.peer_index));

        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();
        return_if_failed!(self.protocol.check_verifiable_header(&last_header));

        let last_state = LastState::new(last_header);

        return_if_failed!(self
            .protocol
            .peers()
            .update_last_state(self.peer_index, last_state.clone()));

        if let Some(prev_last_state) = peer_state.get_last_state() {
            trace!(
                "peer {}: update last state from {} to {}",
                self.peer_index,
                prev_last_state,
                last_state,
            );
            if prev_last_state.total_difficulty() < last_state.total_difficulty() {
                if let Some(prove_state) = peer_state.get_prove_state() {
                    if prove_state.is_parent_of(&last_state) {
                        trace!("peer {}: new last state could be trusted", self.peer_index);
                        let last_n_blocks = self.protocol.last_n_blocks() as usize;
                        let child_prove_state = prove_state.new_child(last_state, last_n_blocks);
                        return_if_failed!(self
                            .protocol
                            .update_prove_state_to_child(self.peer_index, child_prove_state));
                    }
                }
            }
        } else {
            trace!("peer {}: initialize last state", self.peer_index);
            let is_sent =
                return_if_failed!(self.protocol.get_last_state_proof(self.nc, self.peer_index));
            if !is_sent {
                debug!(
                    "peer {} skip sending a request for last state proof",
                    self.peer_index
                );
            }
        }

        Status::ok()
    }
}
