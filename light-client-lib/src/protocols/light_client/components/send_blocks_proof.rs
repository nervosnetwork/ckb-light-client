use ckb_network::{BoxedCKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{
    core::{BlockNumber, ExtraHashView, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
};
use log::{debug, error, info, warn};
use rand::seq::SliceRandom;
use std::collections::HashSet;

use crate::storage::{HeaderWithExtension, LightClientStorage};

use super::{
    super::{LightClientProtocol, Status, StatusCode, BAD_MESSAGE_BAN_TIME},
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
        let status = self.execute_internally().await;
        debug!("block proof status: {}", status);
        self.protocol
            .peers()
            .update_blocks_proof_request(self.peer_index, None, false);
        status
    }

    async fn execute_internally(&self) -> Status {
        let peer = return_if_failed!(self.protocol.get_peer(&self.peer_index));

        let original_request = if let Some(original_request) = peer.get_blocks_proof_request() {
            original_request
        } else {
            error!("peer {} isn't waiting for a proof", self.peer_index);
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
                self.protocol
                    .peers()
                    .mark_fetching_headers_timeout(self.peer_index);
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
            error!("peer {} send an unknown proof", self.peer_index);
            return StatusCode::UnexpectedResponse.into();
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
                vec![None; headers.len()]
            };

            // Verify the proof
            return_if_failed!(verify_mmr_proof(
                self.protocol.mmr_activated_epoch(),
                &last_header,
                self.message.proof(),
                headers.iter(),
            ));

            // Get blocks
            if original_request.should_get_blocks() {
                let block_hashes: Vec<packed::Byte32> =
                    headers.iter().map(|header| header.hash()).collect();
                {
                    let mut matched_blocks = self.protocol.peers().matched_blocks().write().await;

                    self.protocol
                        .peers
                        .mark_matched_blocks_proved(&mut matched_blocks, &block_hashes);
                }

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

            for (header, extension) in headers.into_iter().zip(extensions) {
                if self.protocol.peers().remove_fetching_header(&header.hash()) {
                    self.protocol
                        .storage()
                        .add_fetched_header(&HeaderWithExtension {
                            header: header.data(),
                            extension,
                        });
                }
            }
        }
        self.protocol
            .peers()
            .mark_fetching_headers_missing(&missing_block_hashes);

        // Handle missing blocks: if we know which peer provided the hash via
        // BlockFilters, a missing response may indicate a malicious peer sent
        // a fake block_hash. Roll back the filter cursor and retry from a
        // different peer (up to MAX_MISSING_RETRIES times). If we don't know
        // the source (DB recovery) or retries are exhausted, remove silently.
        const MAX_MISSING_RETRIES: u8 = 3;
        if original_request.should_get_blocks() && !missing_block_hashes.is_empty() {
            let mut matched_blocks = self.protocol.peers().matched_blocks().write().await;
            let mut removed_count = 0;
            let mut retried_count = 0;

            // Phase 1: collect decisions (must drop borrow before remove)
            enum Action {
                Retry {
                    bad_peer: PeerIndex,
                    block_number: BlockNumber,
                },
                Remove,
            }
            let mut actions: Vec<(packed::Byte32, Action)> = Vec::new();

            for missing_hash in &missing_block_hashes {
                let hash_key = missing_hash.unpack();
                if let Some(state) = matched_blocks.get_mut(&hash_key) {
                    let action = match state.filter_source {
                        Some(bad_peer) if state.missing_count < MAX_MISSING_RETRIES => {
                            state.missing_count += 1;
                            Action::Retry {
                                bad_peer,
                                block_number: state.block_number,
                            }
                        }
                        _ => Action::Remove,
                    };
                    actions.push((hash_key.pack(), action));
                }
            }

            // Phase 2: apply actions (no active borrow on matched_blocks)
            let mut lowest_rollback: Option<BlockNumber> = None;
            let mut skipped_peers: HashSet<PeerIndex> = HashSet::new();
            for (hash, action) in actions {
                match action {
                    Action::Retry {
                        bad_peer,
                        block_number,
                    } => {
                        let rollback_to = block_number.saturating_sub(1);

                        warn!(
                            "Block {:#x} (height {}) from peer {} not found in MMR. \
                             Rolling back filter cursor to {} and banning peer.",
                            hash, block_number, bad_peer, rollback_to
                        );

                        self.nc.ban_peer(
                            bad_peer,
                            BAD_MESSAGE_BAN_TIME,
                            format!(
                                "sent block hash {:#x} via BlockFilters \
                                 that is not in the MMR",
                                hash,
                            ),
                        );

                        self.protocol
                            .storage()
                            .update_min_filtered_block_number(rollback_to);

                        lowest_rollback = Some(match lowest_rollback {
                            Some(cur) => cur.min(rollback_to),
                            None => rollback_to,
                        });
                        skipped_peers.insert(bad_peer);

                        matched_blocks.remove(&hash.unpack());
                        retried_count += 1;
                    }
                    Action::Remove => {
                        matched_blocks.remove(&hash.unpack());
                        removed_count += 1;
                        debug!("Removed missing block {:#x} from matched_blocks", hash);
                    }
                }
            }

            if removed_count > 0 {
                info!(
                    "Removed {} missing block(s) from matched_blocks \
                     (genuinely unavailable or retries exhausted).",
                    removed_count
                );
            }
            if retried_count > 0 {
                info!(
                    "Rolled back filter cursor for {} block(s); \
                     will re-fetch BlockFilters from different peers.",
                    retried_count
                );

                // Immediately send a GetBlockFilters request so the retry
                // doesn't wait for the FilterProtocol timer to fire.
                if let Some(rollback_to) = lowest_rollback {
                    let start_number = rollback_to + 1;
                    let tip_header = self.protocol.storage().get_tip_header();
                    let best_peers: Vec<_> = self
                        .protocol
                        .peers()
                        .get_best_proved_peers(&tip_header)
                        .into_iter()
                        .filter(|p| !skipped_peers.contains(p))
                        .collect();
                    if let Some(peer) = best_peers.choose(&mut rand::thread_rng()) {
                        let content = packed::GetBlockFilters::new_builder()
                            .start_number(start_number)
                            .build();
                        let message = packed::BlockFilterMessage::new_builder()
                            .set(content)
                            .build();
                        debug!(
                            "Immediately sending GetBlockFilters to peer {}, start={}",
                            peer, start_number
                        );
                        if let Err(err) = self.nc.send_message(
                            SupportProtocols::Filter.protocol_id(),
                            *peer,
                            message.as_bytes(),
                        ) {
                            info!(
                                "Failed to send immediate GetBlockFilters to {}: {:?}",
                                peer, err
                            );
                        }
                    }
                }
            }

            // Check if batch is now complete
            let all_downloaded = self
                .protocol
                .peers()
                .all_matched_blocks_downloaded(&matched_blocks);

            if all_downloaded && !matched_blocks.is_empty() {
                info!(
                    "Batch complete after processing missing blocks, {} blocks ready",
                    matched_blocks.len()
                );
            } else if matched_blocks.is_empty() {
                debug!("matched_blocks now empty after processing missing blocks");
            }
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
