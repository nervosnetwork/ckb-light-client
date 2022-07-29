use super::super::{LightClientProtocol, Status, StatusCode};
use ckb_merkle_mountain_range::leaf_index_to_pos;
use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{
    packed,
    prelude::*,
    utilities::merkle_mountain_range::{MMRProof, VerifiableHeader},
};
use log::{error, trace};

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

        let root = self.message.root().to_entity();
        let proof: MMRProof = self.message.proof().unpack();
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
        if self
            .protocol
            .peers()
            .remove_block_proof_request(self.peer, &expected_request)
            .is_none()
        {
            error!(
                "peer {}: SendBlockProof response without a GetBlockProof request",
                self.peer
            );
            return StatusCode::PeerIsNotOnProcess.into();
        }

        // Check PoW
        let pow_engine = self.protocol.pow_engine();
        for header in headers.iter().chain(Some(tip_header.header())) {
            if !pow_engine.verify(&header.data()) {
                let errmsg = format!(
                    "failed to verify nonce for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return StatusCode::InvalidNonce.with_context(errmsg);
            }
        }

        // Verify the proof
        let digests_with_positions = {
            let res = headers
                .iter()
                .filter(|header| header.number() != tip_header.header().number())
                .map(|header| {
                    let position = leaf_index_to_pos(header.number());
                    let digest = header.digest();
                    digest.verify()?;
                    Ok((position, digest))
                })
                .collect::<Result<Vec<_>, String>>();
            match res {
                Ok(tmp) => tmp,
                Err(err) => {
                    let errmsg = format!("failed to verify all digest since {}", err);
                    return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
                }
            }
        };
        let verify_result = match proof.verify(root.clone(), digests_with_positions) {
            Ok(verify_result) => verify_result,
            Err(err) => {
                let errmsg = format!("failed to do verify the proof since {}", err);
                return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
            }
        };
        if verify_result {
            trace!(
                "peer {}: verify mmr proof passed, headers.length = {}",
                self.peer,
                headers.len()
            );
        } else {
            error!(
                "peer {}: verify mmr proof failed, headers.length = {}",
                self.peer,
                headers.len()
            );
            return StatusCode::FailedToVerifyTheProof.into();
        }
        let mmr_activated_epoch = self.protocol.mmr_activated_epoch();
        let expected_root_hash = root.calc_mmr_hash();
        let check_extra_hash_result =
            tip_header.is_valid(mmr_activated_epoch, Some(&expected_root_hash));
        if check_extra_hash_result {
            trace!(
                "passed: verify extra hash for block-{} ({:#x})",
                tip_header.header().number(),
                tip_header.header().hash(),
            );
        } else {
            error!(
                "failed: verify extra hash for block-{} ({:#x})",
                tip_header.header().number(),
                tip_header.header().hash(),
            );
            let errmsg = "failed to do verify the extra hash";
            return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
        };

        // Send get blocks
        let content = packed::GetBlocks::new_builder()
            .block_hashes(headers.iter().map(|header| header.hash()).pack())
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
        Status::ok()
    }
}
