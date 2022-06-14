use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    core::BlockNumber, packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256,
};
use faketime::unix_time_as_millis;

use super::super::{peers::ProveRequest, prelude::*, LightClientProtocol, Status, StatusCode};

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
        let mmr_activated_number: BlockNumber = self.message.mmr_activated_number().unpack();
        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();
        let last_total_difficulty: U256 = self.message.total_difficulty().unpack();

        if !last_header.is_valid(mmr_activated_number, None) {
            return StatusCode::InvalidLastState.into();
        }

        let peer_state = self
            .protocol
            .peers()
            .get_state(&self.peer)
            .expect("checked: should have state");

        let is_proved = peer_state
            .get_prove_state()
            .map(|inner| {
                inner.is_same_as(mmr_activated_number, &last_header, &last_total_difficulty)
            })
            .unwrap_or(false);

        // Skipped is the state is proved.
        if is_proved {
            return Status::ok();
        }

        let is_requested = peer_state
            .get_prove_request()
            .map(|inner| {
                inner.is_same_as(mmr_activated_number, &last_header, &last_total_difficulty)
            })
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
                &last_header,
                &last_total_difficulty,
            );
            let prove_request = ProveRequest::new(
                mmr_activated_number,
                last_header,
                last_total_difficulty,
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
