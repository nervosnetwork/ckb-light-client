use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};

use super::super::{prelude::*, strategies::BlockSamplingStrategy, LightClientProtocol, Status};

pub(crate) struct SendChainInfoProcess<'a, S: BlockSamplingStrategy> {
    message: packed::SendChainInfoReader<'a>,
    protocol: &'a mut LightClientProtocol<S>,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a, S: BlockSamplingStrategy> SendChainInfoProcess<'a, S> {
    pub(crate) fn new(
        message: packed::SendChainInfoReader<'a>,
        protocol: &'a mut LightClientProtocol<S>,
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
        self.protocol
            .mut_peers()
            .update_mmr_activated_number(self.peer, mmr_activated_number);
        let now = faketime::unix_time_as_millis();
        self.protocol.get_last_header(self.nc, self.peer);
        self.protocol.mut_peers().update_timestamp(self.peer, now);
        Status::ok()
    }
}
