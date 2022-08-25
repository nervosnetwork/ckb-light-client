use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader};
use log::error;

use super::{
    super::{LightClientProtocol, Status, StatusCode},
    send_block_samples::verify_mmr_proof,
};

pub(crate) struct SendBlockProofProcess<'a> {
    message: packed::SendBlockProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendBlockProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendBlockProofReader<'a>,
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
        if self.message.as_slice() == packed::SendBlockProof::default().as_slice() {
            // The tip_hash is not on the chain, just ignore the message and wait for timeout retry.
            return Status::ok();
        }

        let tip_header: VerifiableHeader = self.message.tip_header().to_entity().into();
        let headers: Vec<_> = self
            .message
            .headers()
            .iter()
            .map(|header| header.to_entity().into_view())
            .collect();

        // check request match the response
        let response_hashes = headers
            .iter()
            .map(|header| header.hash())
            .collect::<Vec<_>>();
        let expected_request = packed::GetBlockProof::new_builder()
            .block_hashes(response_hashes.pack())
            .tip_hash(tip_header.header().hash())
            .build();
        let request = self
            .protocol
            .peers()
            .remove_block_proof_request(self.peer, &expected_request);
        if request.is_none() {
            error!(
                "peer {}: SendBlockProof response without a GetBlockProof request",
                self.peer
            );
            return StatusCode::PeerIsNotOnProcess.into();
        }

        // Check PoW
        return_if_failed!(self
            .protocol
            .check_pow_for_headers(headers.iter().chain(Some(tip_header.header()))));

        // Verify the proof
        return_if_failed!(verify_mmr_proof(
            self.protocol.mmr_activated_epoch(),
            &tip_header,
            self.message.root().to_entity(),
            self.message.proof(),
            headers.iter(),
        ));

        // Send get blocks
        let block_hashes: Vec<packed::Byte32> = headers
            .iter()
            .chain(if request.expect("checked Some").1 {
                Some(tip_header.header())
            } else {
                None
            })
            .map(|header| header.hash())
            .collect();

        for hashes in block_hashes.chunks(INIT_BLOCKS_IN_TRANSIT_PER_PEER) {
            let content = packed::GetBlocks::new_builder()
                .block_hashes(hashes.to_vec().pack())
                .build();
            let message = packed::SyncMessage::new_builder().set(content).build();

            if let Err(err) = self.nc.send_message(
                SupportProtocols::Sync.protocol_id(),
                self.peer,
                message.as_bytes(),
            ) {
                let error_message = format!("nc.send_message SyncMessage, error: {:?}", err);
                error!("{}", error_message);
                return StatusCode::Network.with_context(error_message);
            }
        }
        Status::ok()
    }
}
