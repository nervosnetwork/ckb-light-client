use super::super::{
    peers::ProveRequest, prelude::*, LastState, LightClientProtocol, Status, StatusCode,
};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256};
use faketime::unix_time_as_millis;
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

        if peer_state
            .get_last_state()
            .map(|last_state| last_state.total_difficulty < tip_total_difficulty)
            .unwrap_or(true)
        {
            trace!("peer {}: update last state", self.peer);
            self.protocol.peers().update_last_state(
                self.peer,
                LastState::new(tip_header.clone(), tip_total_difficulty.clone()),
            );
        }

        let is_proved = peer_state
            .get_prove_state()
            .map(|inner| inner.is_same_as(&tip_header, &tip_total_difficulty))
            .unwrap_or(false);

        // Skipped is the state is proved.
        if is_proved {
            return Status::ok();
        }

        let is_requested = peer_state
            .get_prove_request()
            .map(|inner| inner.is_same_as(&tip_header, &tip_total_difficulty))
            .unwrap_or(false);

        // Send the old request again.
        let content = if is_requested {
            let now = unix_time_as_millis();
            let content = peer_state
                .get_prove_request()
                .expect("checked: it should be existed since it's already requested")
                .get_request()
                .to_owned();
            self.protocol.peers().update_timestamp(self.peer, now);

            content
        } else {
            let content = self.protocol.build_prove_request_content(
                &peer_state,
                &tip_header,
                &tip_total_difficulty,
            );
            let prove_request = ProveRequest::new(
                LastState::new(tip_header, tip_total_difficulty),
                content.clone(),
            );
            self.protocol
                .peers()
                .submit_prove_request(self.peer, prove_request);

            content
        };

        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        self.nc.reply(self.peer, &message);

        Status::ok()
    }
}
