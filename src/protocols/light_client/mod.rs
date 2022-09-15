//! Client-side implementation for CKB light client protocol.
//!
//! TODO(light-client) More documentation.

use std::collections::HashMap;
use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_network::{async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{
    core::{BlockNumber, EpochNumber, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    U256,
};
use faketime::unix_time_as_millis;
use log::{debug, error, info, trace, warn};

mod components;
pub mod constant;
mod peers;
mod prelude;
mod sampling;

#[cfg(test)]
mod tests;

use prelude::*;

pub(crate) use self::peers::{LastState, PeerState, Peers, ProveRequest, ProveState};
use super::{
    status::{Status, StatusCode},
    BAD_MESSAGE_BAN_TIME,
};

use crate::protocols::LAST_N_BLOCKS;
use crate::storage::Storage;

pub struct LightClientProtocol {
    storage: Storage,
    peers: Arc<Peers>,
    consensus: Consensus,
}

#[async_trait]
impl CKBProtocolHandler for LightClientProtocol {
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        info!("LightClient.protocol initialized");
        nc.set_notify(
            constant::REFRESH_PEERS_DURATION,
            constant::REFRESH_PEERS_TOKEN,
        )
        .await
        .expect("set_notify should be ok");
        nc.set_notify(
            constant::CHECK_GET_BLOCK_PROOFS_DURATION,
            constant::CHECK_GET_BLOCK_PROOFS_TOKEN,
        )
        .await
        .expect("set_notify should be ok");
    }

    async fn connected(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("LightClient({}).connected peer={}", version, peer);
        self.peers().add_peer(peer);
        self.get_last_state(nc.as_ref(), peer);
    }

    async fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("LightClient.disconnected peer={}", peer);
        self.peers().remove_peer(peer);
    }

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        data: Bytes,
    ) {
        let msg = match packed::LightClientMessageReader::from_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "LightClient.received a malformed message from Peer({})",
                    peer
                );
                nc.ban_peer(
                    peer,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        let item_name = msg.item_name();
        let status = self.try_process(nc.as_ref(), peer, msg);
        trace!("LightClient.received peer={}, message={}", peer, item_name);
        if let Some(ban_time) = status.should_ban() {
            error!(
                "process {} from {}, ban {:?} since result is {}",
                item_name, peer, ban_time, status
            );
            nc.ban_peer(peer, ban_time, status.to_string());
        } else if status.should_warn() {
            warn!("process {} from {}, result is {}", item_name, peer, status);
        } else if !status.is_ok() {
            debug!("process {} from {}, result is {}", item_name, peer, status);
        }
    }

    async fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            constant::REFRESH_PEERS_TOKEN => {
                self.refresh_all_peers(nc.as_ref());
            }
            constant::CHECK_GET_BLOCK_PROOFS_TOKEN => {
                self.check_get_block_proof_requests(nc.as_ref());
            }
            _ => unreachable!(),
        }
    }
}

impl LightClientProtocol {
    fn try_process(
        &mut self,
        nc: &dyn CKBProtocolContext,
        peer: PeerIndex,
        message: packed::LightClientMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::LightClientMessageUnionReader::SendLastState(reader) => {
                components::SendLastStateProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlockSamples(reader) => {
                components::SendBlockSamplesProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlockProof(reader) => {
                components::SendBlockProofProcess::new(reader, self, peer, nc).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    fn get_last_state(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let content = packed::GetLastState::new_builder().build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        nc.reply(peer, &message);
    }

    fn get_block_samples(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let peer_state = self
            .peers()
            .get_state(&peer)
            .expect("checked: should have state");

        if let Some(last_state) = peer_state.get_last_state() {
            let tip_header = &last_state.tip_header;
            let tip_total_difficulty = &last_state.total_difficulty;

            let is_proved = peer_state
                .get_prove_state()
                .map(|inner| inner.is_same_as(tip_header, tip_total_difficulty))
                .unwrap_or(false);

            // Skipped is the state is proved.
            if is_proved {
                return;
            }
            let is_requested = peer_state
                .get_prove_request()
                .map(|inner| inner.is_same_as(tip_header, tip_total_difficulty))
                .unwrap_or(false);

            // Send the old request again.
            if is_requested {
                let now = unix_time_as_millis();
                self.peers().update_timestamp(peer, now);
            } else if let Some(content) =
                self.build_prove_request_content(&peer_state, tip_header, tip_total_difficulty)
            {
                let prove_request = ProveRequest::new(last_state.clone(), content);
                self.peers().submit_prove_request(peer, prove_request);
            } else {
                warn!("peer {}: build prove request failed", peer);
            }
        }

        // Copy the updated peer state again
        let peer_state = self
            .peers()
            .get_state(&peer)
            .expect("checked: should have state");
        if let Some(content) = peer_state
            .get_prove_request()
            .map(|request| request.get_request().to_owned())
        {
            trace!("peer {}: send get block samples", peer);
            let message = packed::LightClientMessage::new_builder()
                .set(content)
                .build();
            nc.reply(peer, &message);
        }
    }

    fn commit_prove_state(&self, peer: PeerIndex, new_prove_state: ProveState) {
        let (old_total_difficulty, _) = self.storage.get_last_state();
        if new_prove_state.get_total_difficulty() > &old_total_difficulty {
            if let Some(state) = self.peers().get_state(&peer) {
                if let Some(old_prove_state) = state.get_prove_state() {
                    let reorg_last_headers = new_prove_state.get_reorg_last_headers();
                    if !reorg_last_headers.is_empty() {
                        let last_headers: HashMap<_, _> = old_prove_state
                            .get_last_headers()
                            .iter()
                            .map(|header| (header.number(), header.hash()))
                            .collect();
                        let fork_number =
                            reorg_last_headers.iter().rev().find_map(|reorg_header| {
                                let number = reorg_header.number();
                                last_headers
                                    .get(&number)
                                    .map(|hash| {
                                        if reorg_header.hash().eq(hash) {
                                            None
                                        } else {
                                            Some(number)
                                        }
                                    })
                                    .unwrap_or(Some(number))
                            });
                        if let Some(to_number) = fork_number {
                            trace!("rollback to block#{}", to_number);
                            self.storage.rollback_to_block(to_number);
                        }
                    }
                }
            }

            self.storage.update_last_state(
                new_prove_state.get_total_difficulty(),
                &new_prove_state.get_last_header().header().data(),
            );
            self.peers().commit_prove_state(peer, new_prove_state);
        }
    }
}

impl LightClientProtocol {
    pub(crate) fn new(storage: Storage, peers: Arc<Peers>, consensus: Consensus) -> Self {
        Self {
            storage,
            peers,
            consensus,
        }
    }

    pub(crate) fn mmr_activated_epoch(&self) -> EpochNumber {
        // TODO remove this hard code when mmr is activated on testnet
        if self.consensus.is_public_chain() {
            EpochNumber::MAX
        } else {
            1
        }
    }

    pub(crate) fn check_pow_for_headers<'a, T: Iterator<Item = &'a HeaderView>>(
        &self,
        headers: T,
    ) -> Result<(), Status> {
        let pow_engine = self.consensus.pow_engine();
        for header in headers {
            if !pow_engine.verify(&header.data()) {
                let errmsg = format!(
                    "failed to verify nonce for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return Err(StatusCode::InvalidNonce.with_context(errmsg));
            }
        }
        Ok(())
    }

    pub(crate) fn peers(&self) -> &Peers {
        &self.peers
    }

    fn check_get_block_proof_requests(&self, nc: &dyn CKBProtocolContext) {
        for peer in self.peers().check_block_proof_requests() {
            warn!(
                "peer {}: too many inflight GetBlockProof requests or respond timeout",
                peer
            );
            if let Err(err) = nc.disconnect(
                peer,
                "too many inflight GetBlockProof requests or respond timeout",
            ) {
                error!("disconnect peer({}) error: {}", peer, err);
            };
        }
    }

    fn refresh_all_peers(&mut self, nc: &dyn CKBProtocolContext) {
        let now = faketime::unix_time_as_millis();
        let before = now - constant::REFRESH_PEERS_DURATION.as_millis() as u64;
        for peer in self.peers().get_peers_which_require_updating(before) {
            self.get_block_samples(nc, peer);
            self.peers().update_timestamp(peer, now);
        }
    }

    pub(crate) fn build_prove_request_content(
        &self,
        peer_state: &PeerState,
        last_header: &VerifiableHeader,
        last_total_difficulty: &U256,
    ) -> Option<packed::GetBlockSamples> {
        let last_n_blocks = LAST_N_BLOCKS;
        let last_number = last_header.header().number();
        let (start_hash, start_number, start_total_difficulty) = peer_state
            .get_prove_state()
            .map(|inner| {
                (
                    inner.get_last_header().header().hash(),
                    inner.get_last_header().header().number(),
                    inner.get_total_difficulty().to_owned(),
                )
            })
            .unwrap_or_else(|| {
                let (total_difficulty, last_tip) = self.storage.get_last_state();
                if &total_difficulty > last_total_difficulty {
                    warn!(
                        "total difficulty ({:#x}) in storage is greater than \
                        the total difficulty ({:#x}) which requires proving",
                        total_difficulty, last_total_difficulty
                    );
                }
                let start_number: BlockNumber = last_tip.raw().number().unpack();
                if start_number >= last_number {
                    warn!(
                        "block number ({}) in storage is greater than \
                        the block number ({}) which requires proving",
                        start_number, last_number
                    );
                }
                (last_tip.calc_header_hash(), start_number, total_difficulty)
            });
        if &start_total_difficulty > last_total_difficulty || start_number >= last_number {
            return None;
        }
        let builder = packed::GetBlockSamples::new_builder()
            .last_hash(last_header.header().hash())
            .start_hash(start_hash)
            .start_number(start_number.pack())
            .last_n_blocks(last_n_blocks.pack());
        let content = if last_number - start_number <= last_n_blocks {
            builder.difficulty_boundary(start_total_difficulty.pack())
        } else {
            let (difficulty_boundary, difficulties) = sampling::sample_blocks(
                start_number,
                &start_total_difficulty,
                last_number,
                last_total_difficulty,
                last_n_blocks,
            );
            builder
                .difficulty_boundary(difficulty_boundary.pack())
                .difficulties(difficulties.into_iter().map(|inner| inner.pack()).pack())
        }
        .build();
        Some(content)
    }
}
