use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{packed, prelude::*};
use log::warn;

use super::super::{prelude::*, strategies::BlockSamplingStrategy, LightClientProtocol, Status};

pub(crate) struct SendLastHeaderProcess<'a, S: BlockSamplingStrategy> {
    message: packed::SendLastHeaderReader<'a>,
    protocol: &'a mut LightClientProtocol<S>,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a, S: BlockSamplingStrategy> SendLastHeaderProcess<'a, S> {
    pub(crate) fn new(
        message: packed::SendLastHeaderReader<'a>,
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
        let last_header = self.message.header().to_entity().into_view();
        let last_number = last_header.number();

        if let Some(mmr_activated_number) =
            self.protocol.peers().get_mmr_activated_number(&self.peer)
        {
            if mmr_activated_number < last_number {
                self.protocol
                    .mut_peers()
                    .update_last_header(self.peer, last_header.clone());
            } else {
                warn!(
                    "mmr_activated_number({}) >= last_number({})",
                    mmr_activated_number, last_number
                );
            }
        } else {
            warn!("mmr_activated_number is not existed");
        }

        Status::ok()
    }
}
