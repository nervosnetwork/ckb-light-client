use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::packed;

use super::super::{
    prelude::*, strategies::BlockSamplingStrategy, LightClientProtocol, Status, StatusCode,
};

pub(crate) struct SendBlockProofProcess<'a, S: BlockSamplingStrategy> {
    message: packed::SendBlockProofReader<'a>,
    protocol: &'a mut LightClientProtocol<S>,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a, S: BlockSamplingStrategy> SendBlockProofProcess<'a, S> {
    pub(crate) fn new(
        message: packed::SendBlockProofReader<'a>,
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
        self.protocol
            .strategy
            .handle_block_proof(self.peer, self.message)
    }
}
