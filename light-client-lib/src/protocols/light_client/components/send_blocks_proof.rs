use ckb_network::{BoxedCKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{
    core::{ExtraHashView, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
};
use log::{debug, error, info};
use rand::seq::SliceRandom;

use crate::storage::{HeaderWithExtension, LightClientStorage};

use super::{
    super::{peers::BlocksProofRequest, LightClientProtocol, Status, StatusCode},
    verify_mmr_proof,
};

pub(crate) struct SendBlocksProofProcess<'a> {
    message: packed::SendBlocksProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer_index: PeerIndex,
    nc: &'a BoxedCKBProtocolContext,
}

impl<'a> SendBlocksProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendBlocksProofReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer_index: PeerIndex,
        nc: &'a BoxedCKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer_index,
            nc,
        }
    }

    pub(crate) async fn execute(self) -> Status {
        let mut retire_request = None;
        let status = self.execute_internally(&mut retire_request).await;
        debug!("block proof status: {}", status);
        if let Some(request) = retire_request {
            self.protocol.peers().finish_blocks_proof_request(
                self.peer_index,
                &request,
                !status.is_ok(),
                false,
            );
        }
        status
    }

    async fn execute_internally(&self, retire_request: &mut Option<BlocksProofRequest>) -> Status {
        let peer = return_if_failed!(self.protocol.get_peer(&self.peer_index));

        let original_request = if let Some(original_request) = peer.get_blocks_proof_request() {
            original_request
        } else {
            debug!("peer {} has no outstanding proof request", self.peer_index);
            return StatusCode::PeerIsNotOnProcess.into();
        };

        let last_header: VerifiableHeader = self.message.last_header().to_entity().into();
        let headers_len = self.message.headers().len();
        // Parse the V1 extra fields with a verifying reader up front, before any
        // early return, so that all later access is over validated bytes and can
        // never panic on malformed/unchecked input.
        let message_v1 = if self.message.count_extra_fields() >= 2 {
            match packed::SendBlocksProofV1Reader::from_compatible_slice(self.message.as_slice()) {
                Ok(message_v1) => {
                    let uncle_hashes_len = message_v1.blocks_uncles_hash().len();
                    let extensions_len = message_v1.blocks_extension().len();
                    if uncle_hashes_len != headers_len || extensions_len != headers_len {
                        let error_message = format!(
                            "SendBlocksProof v1 field length mismatch: \
                             headers={}, uncle_hashes={}, extensions={}",
                            headers_len, uncle_hashes_len, extensions_len
                        );
                        return StatusCode::MalformedProtocolMessage.with_context(error_message);
                    }
                    Some(message_v1)
                }
                Err(_) => {
                    return StatusCode::MalformedProtocolMessage
                        .with_context("SendBlocksProof v1 extra fields are malformed");
                }
            }
        } else {
            None
        };

        // Update the last state if the response contains a new one.
        if original_request.last_hash() != last_header.header().hash() {
            if self.message.proof().is_empty()
                && self.message.headers().is_empty()
                && self.message.missing_block_hashes().is_empty()
            {
                return_if_failed!(self
                    .protocol
                    .process_last_state(self.peer_index, last_header));
                // This hint carries no request identity; an accepted reorg retires old anchors.
                return Status::ok();
            } else {
                // Since the last state is different, then no data should be contained.
                error!(
                    "peer {} send a proof with different last state",
                    self.peer_index
                );
                return StatusCode::UnexpectedResponse.into();
            }
        }

        let headers: Vec<_> = self
            .message
            .headers()
            .iter()
            .map(|header| header.to_entity().into_view())
            .collect();

        // Check if the response is match the request.
        let received_block_hashes = headers
            .iter()
            .map(|header| header.hash())
            .collect::<Vec<_>>();
        let missing_block_hashes = self
            .message
            .missing_block_hashes()
            .to_entity()
            .into_iter()
            .collect::<Vec<_>>();

        debug!("got block proof: missing {:?}", &missing_block_hashes);

        if !original_request.check_block_hashes(&received_block_hashes, &missing_block_hashes) {
            // Preserve the owner, but retain protocol penalties for invalid data.
            return StatusCode::UnexpectedResponse.into();
        }
        *retire_request = Some(original_request.clone());

        let pending_bridge = self
            .protocol
            .peers()
            .pending_continuity(self.peer_index)
            .filter(|(previous, state)| {
                *previous == self.protocol.storage().get_tip_header().calc_header_hash()
                    && state.get_last_header().header().hash() == last_header.header().hash()
                    && original_request.block_hashes()
                        == vec![if state.needs_genesis_bridge {
                            self.protocol
                                .storage()
                                .get_genesis_block()
                                .calc_header_hash()
                                .unpack()
                        } else {
                            previous.unpack()
                        }]
            });
        if pending_bridge.is_none() {
            // The original request slot is retained until this response is drained.
            // A valid old-fork response must neither complete a fetch nor mark it missing.
            match crate::storage::canonical::anchor_current(
                self.protocol.storage(),
                &last_header.header().data(),
            ) {
                Ok(true) => {}
                Ok(false) => {
                    self.protocol
                        .peers()
                        .mark_fetching_headers_timeout(self.peer_index);
                    return Status::ok();
                }
                Err(error) => {
                    self.protocol
                        .peers()
                        .mark_fetching_headers_timeout(self.peer_index);
                    return StatusCode::InternalError.with_context(error.to_string());
                }
            }
        }
        // If all blocks are missing.
        if headers.is_empty() {
            if !self.message.proof().is_empty() {
                error!(
                    "peer {} send a proof when all blocks are missing",
                    self.peer_index
                );
                return StatusCode::UnexpectedResponse.into();
            }
        } else {
            // Check PoW for blocks
            return_if_failed!(self.protocol.check_pow_for_headers(headers.iter()));

            // Check extra hash for blocks
            let extensions = if let Some(message_v1) = message_v1 {
                let uncle_hashes: Vec<_> = message_v1
                    .blocks_uncles_hash()
                    .iter()
                    .map(|uncle_hashes| uncle_hashes.to_entity())
                    .collect();
                let extensions: Vec<_> = message_v1
                    .blocks_extension()
                    .iter()
                    .map(|extension| extension.to_entity().to_opt())
                    .collect();

                return_if_failed!(verify_extra_hash(&headers, &uncle_hashes, &extensions));
                extensions
            } else {
                // A legacy (v0) response carries neither uncle hashes nor
                // block extensions. Only accept it for headers which commit
                // to no such data; otherwise a malicious peer could omit a
                // CKB2023 block extension and the client would verify
                // transactions against incomplete data.
                return_if_failed!(verify_legacy_extra_hash(&headers));
                vec![None; headers.len()]
            };

            // Verify the proof
            return_if_failed!(verify_mmr_proof(
                self.protocol.mmr_activated_epoch(),
                &last_header,
                self.message.proof(),
                headers.iter(),
            ));

            if let Some((previous, mut candidate)) = pending_bridge.clone() {
                let expected = if candidate.needs_genesis_bridge {
                    self.protocol
                        .storage()
                        .get_genesis_block()
                        .calc_header_hash()
                } else {
                    previous
                };
                if headers.len() != 1 || headers[0].hash() != expected {
                    return StatusCode::InvalidProof.into();
                }
                if !self
                    .protocol
                    .peers()
                    .owns_blocks_proof_request(self.peer_index, original_request)
                {
                    return Status::ok();
                }
                candidate.proved_headers.push(headers[0].clone());
                return match self
                    .protocol
                    .commit_prove_state(self.peer_index, candidate)
                    .await
                {
                    Ok(true) => Status::ok(),
                    Ok(false) => StatusCode::RequireRecheck.into(),
                    Err(status) => status,
                };
            }

            // Serialize positional admission/provenance with script changes and acceptance.
            let mut matched_blocks = self.protocol.peers().matched_blocks().write().await;
            // A valid response must still own the slot before it changes persisted state.
            if !self
                .protocol
                .peers()
                .owns_blocks_proof_request(self.peer_index, original_request)
            {
                return Status::ok();
            }
            if original_request.should_get_blocks() {
                match crate::storage::canonical::coverage::check_headers(
                    self.protocol.storage(),
                    &headers,
                ) {
                    Ok(true) => {}
                    Ok(false) => return Status::ok(),
                    Err(error) => {
                        self.protocol
                            .peers()
                            .clear_matched_blocks(&mut matched_blocks);
                        return StatusCode::InvalidProof.with_context(error.to_string());
                    }
                }
            }
            // Record only headers which passed the existing PoW/extra-hash/MMR checks.
            for (header, extension) in headers.iter().zip(extensions.iter()) {
                if let Err(error) = crate::storage::canonical::store_proved_header(
                    self.protocol.storage(),
                    &HeaderWithExtension {
                        header: header.data(),
                        extension: extension.clone(),
                    },
                    &last_header.header().data(),
                ) {
                    self.protocol
                        .peers()
                        .mark_fetching_headers_timeout(self.peer_index);
                    return StatusCode::InternalError.with_context(error.to_string());
                }
            }

            // Get blocks
            if original_request.should_get_blocks() {
                let block_hashes: Vec<packed::Byte32> =
                    headers.iter().map(|header| header.hash()).collect();
                self.protocol
                    .peers
                    .mark_matched_blocks_proved(&mut matched_blocks, &block_hashes);
                drop(matched_blocks);

                let best_peers: Vec<_> = self
                    .protocol
                    .peers
                    .get_best_proved_peers(&last_header.header().data())
                    .into_iter()
                    .filter_map(|peer_index| {
                        self.protocol
                            .peers
                            .get_peer(&peer_index)
                            .map(|peer| (peer_index, peer))
                    })
                    .collect();

                if let Some((peer_index, _)) = best_peers
                    .iter()
                    .filter(|(_peer_index, peer)| peer.get_blocks_request().is_none())
                    .collect::<Vec<_>>()
                    .choose(&mut rand::thread_rng())
                {
                    self.protocol
                        .peers
                        .update_blocks_request(*peer_index, Some(block_hashes.clone()));
                    debug!(
                        "send get blocks request to peer: {}, matched_count: {}",
                        peer_index,
                        block_hashes.len()
                    );
                    for hashes in
                        block_hashes.chunks(self.protocol.init_blocks_in_transit_per_peer())
                    {
                        let content = packed::GetBlocks::new_builder()
                            .block_hashes(hashes.to_vec().pack())
                            .build();
                        let message = packed::SyncMessage::new_builder()
                            .set(content)
                            .build()
                            .as_bytes();
                        if let Err(err) = self.nc.send_message(
                            SupportProtocols::Sync.protocol_id(),
                            *peer_index,
                            message,
                        ) {
                            let error_message =
                                format!("nc.send_message SyncMessage, error: {:?}", err);
                            info!("{}", error_message);
                            return StatusCode::Network.with_context(error_message);
                        }
                    }
                }
            }

            for header in headers {
                self.protocol.peers().remove_fetching_header(&header.hash());
            }
        }
        if pending_bridge.is_some() {
            return Status::ok();
        }
        if original_request.should_get_blocks() {
            self.protocol.peers().note_matched_misses(
                self.peer_index,
                original_request,
                &missing_block_hashes,
            );
        } else {
            // Preserve the public one-shot header-fetch result. This negative
            // cache never certifies completion of watched matched work.
            self.protocol
                .peers()
                .mark_fetching_headers_missing(&missing_block_hashes);
        }

        Status::ok()
    }
}

pub(crate) fn verify_extra_hash(
    headers: &[HeaderView],
    uncle_hashes: &[packed::Byte32],
    extensions: &[Option<packed::Bytes>],
) -> Result<(), Status> {
    if headers.len() != uncle_hashes.len() || headers.len() != extensions.len() {
        return Err(StatusCode::InvalidProof.into());
    }

    for ((header, uncle_hash), extension) in headers
        .iter()
        .zip(uncle_hashes.iter())
        .zip(extensions.iter())
    {
        let expected_extension_hash = extension
            .as_ref()
            .map(|extension| extension.calc_raw_data_hash());
        let extra_hash_view = ExtraHashView::new(uncle_hash.clone(), expected_extension_hash);
        let expected_extra_hash = extra_hash_view.extra_hash();
        let actual_extra_hash = header.extra_hash();
        if expected_extra_hash != actual_extra_hash {
            return Err(StatusCode::InvalidProof.into());
        }
    }

    Ok(())
}

/// Verifies that headers in a legacy (v0) proof message commit to no extra
/// data.
///
/// A legacy `SendBlocksProof`/`SendTransactionsProof` message carries neither
/// uncle hashes nor block extensions. For a block without uncles and without
/// an extension, `extra_hash` is `Byte32::zero()`; any other value commits to
/// data the legacy message cannot provide. Accepting such a header would let
/// a malicious peer omit a CKB2023 block extension and make the client verify
/// transactions against incomplete data.
pub(crate) fn verify_legacy_extra_hash(headers: &[HeaderView]) -> Result<(), Status> {
    for header in headers {
        if header.extra_hash() != packed::Byte32::zero() {
            let errmsg = format!(
                "legacy proof message omits uncle hashes/extensions committed by block#{} (hash: {:#x})",
                header.number(),
                header.hash(),
            );
            return Err(StatusCode::InvalidProof.with_context(errmsg));
        }
    }
    Ok(())
}
