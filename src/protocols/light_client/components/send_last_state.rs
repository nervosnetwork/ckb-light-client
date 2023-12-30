use super::super::{LastState, LightClientProtocol, Status, StatusCode};
use ckb_constant::sync::MAX_TIP_AGE;
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_systemtime::unix_time_as_millis;
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
        return_if_failed!(check_last_state(&last_header));

        let last_state = LastState::new(last_header);

        if let Some(prev_last_state) = peer_state.get_last_state() {
            if last_state.is_same_as(prev_last_state) {
                trace!(
                    "peer {}: receive the same last state as previous {}",
                    self.peer_index,
                    last_state,
                );
                // Do NOT update the timestamp for same last state,
                // so it could be banned after timeout check.
            } else {
                trace!(
                    "peer {}: update last state from {} to {}",
                    self.peer_index,
                    prev_last_state,
                    last_state,
                );

                return_if_failed!(self
                    .protocol
                    .peers()
                    .update_last_state(self.peer_index, last_state.clone()));

                if prev_last_state.total_difficulty() < last_state.total_difficulty() {
                    if let Some(prove_state) = peer_state.get_prove_state() {
                        if prove_state.is_parent_of(&last_state) {
                            trace!("peer {}: new last state could be trusted", self.peer_index);
                            let last_n_blocks = self.protocol.last_n_blocks() as usize;
                            let child_prove_state =
                                prove_state.new_child(last_state, last_n_blocks);
                            return_if_failed!(self
                                .protocol
                                .update_prove_state_to_child(self.peer_index, child_prove_state));
                        }
                    }
                }
            }
        } else {
            trace!(
                "peer {}: initialize last state {}",
                self.peer_index,
                last_state
            );

            return_if_failed!(self
                .protocol
                .peers()
                .update_last_state(self.peer_index, last_state));

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

fn check_last_state(last_header: &VerifiableHeader) -> Result<(), Status> {
    let now = unix_time_as_millis();
    let timestamp = last_header.header().timestamp();
    if now.saturating_sub(timestamp) > MAX_TIP_AGE {
        let errmsg = format!(
            "still in initial block download with a very high probability \
            since {now} - {timestamp} > {MAX_TIP_AGE}",
        );
        return Err(StatusCode::PeerIsInIBD.with_context(errmsg));
    }
    Ok(())
}
