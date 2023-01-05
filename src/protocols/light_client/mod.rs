//! Client-side implementation for CKB light client protocol.
//!
//! TODO(light-client) More documentation.

use std::collections::HashMap;
use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{
    async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
};
use ckb_types::{
    core::{BlockNumber, EpochNumber, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
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
#[cfg(test)]
pub(crate) use self::peers::FetchInfo;

use prelude::*;

pub(crate) use self::peers::{LastState, PeerState, Peers, ProveRequest, ProveState};
use super::{
    status::{Status, StatusCode},
    BAD_MESSAGE_BAN_TIME,
};

use crate::protocols::{GET_BLOCKS_PROOF_LIMIT, GET_TRANSACTIONS_PROOF_LIMIT, LAST_N_BLOCKS};
use crate::storage::Storage;
use crate::utils::network::prove_or_download_matched_blocks;

pub struct LightClientProtocol {
    storage: Storage,
    peers: Arc<Peers>,
    consensus: Consensus,
    mmr_activated_epoch: EpochNumber,
    last_n_blocks: BlockNumber,
    init_blocks_in_transit_per_peer: usize,
}

#[async_trait]
impl CKBProtocolHandler for LightClientProtocol {
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        info!("LightClient.protocol initialized");
        for (duration, token) in [
            (
                constant::REFRESH_PEERS_DURATION,
                constant::REFRESH_PEERS_TOKEN,
            ),
            (
                constant::FETCH_HEADER_TX_DURATION,
                constant::FETCH_HEADER_TX_TOKEN,
            ),
            (
                constant::GET_IDLE_BLOCKS_DURATION,
                constant::GET_IDLE_BLOCKS_TOKEN,
            ),
        ] {
            nc.set_notify(duration, token)
                .await
                .expect("set_notify should be ok");
        }
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
            constant::FETCH_HEADER_TX_TOKEN => {
                self.fetch_headers_txs(nc.as_ref());
            }
            constant::GET_IDLE_BLOCKS_TOKEN => {
                self.get_idle_blocks(nc.as_ref());
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
            packed::LightClientMessageUnionReader::SendLastStateProof(reader) => {
                components::SendLastStateProofProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlocksProof(reader) => {
                components::SendBlocksProofProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendTransactionsProof(reader) => {
                components::SendTransactionsProofProcess::new(reader, self, peer, nc).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    fn get_last_state(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let content = packed::GetLastState::new_builder()
            .subscribe(true.pack())
            .build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        nc.reply(peer, &message);
    }

    fn get_last_state_proof(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let peer_state = self
            .peers()
            .get_state(&peer)
            .expect("checked: should have state");

        if let Some(last_state) = peer_state.get_last_state() {
            let last_header = last_state.verifiable_header();

            let is_proved = peer_state
                .get_prove_state()
                .map(|inner| inner.is_same_as(last_header))
                .unwrap_or(false);

            // Skipped is the state is proved.
            if is_proved {
                return;
            }

            // Skipped is the request is sent.
            let is_requested = peer_state
                .get_prove_request()
                .map(|inner| inner.is_same_as(last_header))
                .unwrap_or(false);
            if is_requested {
                return;
            }

            // Skipped if the header is proved in other peers.
            if let Some((peer_copied_from, prove_state)) =
                self.peers().find_if_a_header_is_proved(last_header)
            {
                info!(
                    "peer {}: copy prove state from peer {}",
                    peer, peer_copied_from
                );
                self.peers().update_prove_state(peer, prove_state);
                return;
            }

            if let Some(content) = self.build_prove_request_content(&peer_state, last_header) {
                trace!("peer {}: send get last state proof", peer);
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build();
                nc.reply(peer, &message);
                let now = unix_time_as_millis();
                self.peers().update_timestamp(peer, now);
                let prove_request = ProveRequest::new(last_state.clone(), content);
                self.peers().update_prove_request(peer, Some(prove_request));
            } else {
                warn!("peer {}: build prove request failed", peer);
            }
        }
    }

    pub(crate) fn check_chain_root_for_headers<'a, T: Iterator<Item = &'a VerifiableHeader>>(
        &self,
        headers: T,
    ) -> Result<(), Status> {
        let mmr_activated_epoch = self.mmr_activated_epoch();
        for header in headers {
            if !header.is_valid(mmr_activated_epoch) {
                let header = header.header();
                let errmsg = format!(
                    "failed to verify chain root for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return Err(StatusCode::InvalidChainRoot.with_context(errmsg));
            }
        }
        Ok(())
    }

    fn check_verifiable_header(&self, verifiable_header: &VerifiableHeader) -> Result<(), Status> {
        let header = verifiable_header.header();
        // Check PoW
        if !self.consensus.pow_engine().verify(&header.data()) {
            let errmsg = format!(
                "failed to verify nonce for block#{}, hash: {:#x}",
                header.number(),
                header.hash()
            );
            return Err(StatusCode::InvalidNonce.with_context(errmsg));
        }
        // Check Chain Root
        if !verifiable_header.is_valid(self.mmr_activated_epoch()) {
            let errmsg = format!(
                "failed to verify chain root for block#{}, hash: {:#x}",
                header.number(),
                header.hash()
            );
            return Err(StatusCode::InvalidChainRoot.with_context(errmsg));
        }
        Ok(())
    }

    /// Processes a new last state that received from a peer which has a fork chain.
    fn process_last_state(
        &self,
        peer: PeerIndex,
        last_header: VerifiableHeader,
    ) -> Result<(), Status> {
        self.check_verifiable_header(&last_header)?;
        let last_state = LastState::new(last_header);
        trace!("peer {}: update last state", peer);
        self.peers().update_last_state(peer, last_state);
        Ok(())
    }

    /// Update the prove state to the child block.
    /// - Update the peer's cache.
    /// - Try to update the storage without caring about fork.
    fn update_prove_state_to_child(&self, peer: PeerIndex, new_prove_state: ProveState) {
        let (old_total_difficulty, _) = self.storage.get_last_state();
        let new_total_difficulty = new_prove_state.get_last_header().total_difficulty();
        if new_total_difficulty > old_total_difficulty {
            self.storage.update_last_state(
                &new_total_difficulty,
                &new_prove_state.get_last_header().header().data(),
                new_prove_state.get_last_headers(),
            );
        }
        self.peers().update_prove_state(peer, new_prove_state);
    }

    /// Update the prove state base on the previous request.
    /// - Update the peer's cache.
    /// - Try to update the storage and handle potential fork.
    pub(crate) fn commit_prove_state(&self, peer: PeerIndex, new_prove_state: ProveState) {
        let (old_total_difficulty, _) = self.storage.get_last_state();
        let new_total_difficulty = new_prove_state.get_last_header().total_difficulty();
        if new_total_difficulty > old_total_difficulty {
            let reorg_last_headers = new_prove_state.get_reorg_last_headers();
            if !reorg_last_headers.is_empty() {
                let old_last_headers: HashMap<_, _> =
                    self.storage.get_last_n_headers().into_iter().collect();
                let fork_number = reorg_last_headers.iter().rev().find_map(|reorg_header| {
                    let number = reorg_header.number();
                    old_last_headers
                        .get(&number)
                        .map(|hash| {
                            if &reorg_header.hash() == hash {
                                Some(number)
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default()
                });
                if let Some(to_number) = fork_number {
                    let mut matched_blocks = self.peers.matched_blocks().write().expect("poisoned");
                    let mut start_number_opt = None;
                    while let Some((start_number, _, _)) = self.storage.get_latest_matched_blocks()
                    {
                        if start_number > to_number {
                            debug!("remove matched blocks start from: {}", start_number);
                            self.storage.remove_matched_blocks(start_number);
                        } else {
                            start_number_opt = Some(start_number);
                            break;
                        }
                    }
                    let rollback_to = start_number_opt.unwrap_or(to_number) + 1;
                    debug!("rollback to block#{}", rollback_to);
                    self.storage.rollback_to_block(rollback_to);
                    matched_blocks.clear();
                } else {
                    error!("Long fork detected, please check if ckb-light-client is connected to the same network ckb node. If you connected ckb-light-client to a dev chain for testing purpose you should remove the storage of ckb-light-client to recover.");
                    panic!("long fork detected");
                }
            }

            self.storage.update_last_state(
                &new_total_difficulty,
                &new_prove_state.get_last_header().header().data(),
                new_prove_state.get_last_headers(),
            );
        }
        self.peers().commit_prove_state(peer, new_prove_state);
    }
}

impl LightClientProtocol {
    pub(crate) fn new(storage: Storage, peers: Arc<Peers>, consensus: Consensus) -> Self {
        // TODO remove this hard code when mmr is activated on testnet
        let mmr_activated_epoch = if consensus.is_public_chain() {
            EpochNumber::MAX
        } else {
            0
        };
        Self {
            storage,
            peers,
            consensus,
            mmr_activated_epoch,
            last_n_blocks: LAST_N_BLOCKS,
            init_blocks_in_transit_per_peer: INIT_BLOCKS_IN_TRANSIT_PER_PEER,
        }
    }

    pub(crate) fn last_n_blocks(&self) -> BlockNumber {
        self.last_n_blocks
    }

    #[cfg(test)]
    pub(crate) fn set_last_n_blocks(&mut self, last_n_blocks: BlockNumber) {
        self.last_n_blocks = last_n_blocks;
    }

    pub(crate) fn init_blocks_in_transit_per_peer(&self) -> usize {
        self.init_blocks_in_transit_per_peer
    }

    #[cfg(test)]
    pub(crate) fn set_init_blocks_in_transit_per_peer(&mut self, value: usize) {
        self.init_blocks_in_transit_per_peer = value;
    }

    #[cfg(test)]
    pub(crate) fn set_mmr_activated_epoch(&mut self, mmr_activated_epoch: EpochNumber) {
        self.mmr_activated_epoch = mmr_activated_epoch;
    }

    pub(crate) fn mmr_activated_epoch(&self) -> EpochNumber {
        self.mmr_activated_epoch
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

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub(crate) fn peers(&self) -> &Peers {
        &self.peers
    }

    pub(crate) fn get_peer_state(&self, peer: &PeerIndex) -> Result<PeerState, Status> {
        if let Some(state) = self.peers().get_state(peer) {
            Ok(state)
        } else {
            Err(StatusCode::PeerStateIsNotFound.into())
        }
    }

    fn refresh_all_peers(&mut self, nc: &dyn CKBProtocolContext) {
        let now = faketime::unix_time_as_millis();
        for peer in self.peers().get_peers_which_have_timeout(now) {
            self.peers().mark_fetching_headers_timeout(peer);
            self.peers().mark_fetching_txs_timeout(peer);

            warn!("peer {}: reach timeout", peer);
            if let Err(err) = nc.disconnect(peer, "reach timeout") {
                error!("disconnect peer({}) error: {}", peer, err);
            };
        }
        let before = now - constant::REFRESH_PEERS_DURATION.as_millis() as u64;
        for peer in self.peers().get_peers_which_require_updating(before) {
            // TODO Different messages should have different timeouts.
            self.get_last_state(nc, peer);
            self.get_last_state_proof(nc, peer);
        }
    }

    fn get_idle_blocks(&mut self, nc: &dyn CKBProtocolContext) {
        let tip_header = self.storage.get_tip_header();
        let matched_blocks = self.peers.matched_blocks().read().expect("poisoned");
        prove_or_download_matched_blocks(
            Arc::clone(&self.peers),
            &tip_header,
            &matched_blocks,
            nc,
            self.init_blocks_in_transit_per_peer(),
        );
    }

    fn fetch_headers_txs(&mut self, nc: &dyn CKBProtocolContext) {
        if !self.peers.has_fetching_info() {
            trace!("no fetching headers/transactions needed");
            return;
        }

        let tip_header = self.storage.get_tip_header();
        let best_peers: Vec<PeerIndex> = self.peers.get_best_proved_peers(&tip_header);
        if best_peers.is_empty() {
            debug!("no peers found for fetch headers and transactions");
            return;
        }

        let now = unix_time_as_millis();
        let last_hash = tip_header.calc_header_hash();
        for block_hashes_all in self
            .peers
            .get_headers_to_fetch()
            .chunks(GET_BLOCKS_PROOF_LIMIT)
        {
            if let Some(peer) = best_peers.iter().find(|peer| {
                self.peers
                    .get_state(peer)
                    .map(|peer_state| peer_state.get_blocks_proof_request().is_none())
                    .unwrap_or(false)
            }) {
                debug!("send block proof request to peer: {}", peer);
                let mut block_hashes = Vec::with_capacity(block_hashes_all.len());
                for block_hash in block_hashes_all {
                    if block_hash == &last_hash {
                        debug!("remove tip hash from block proof request {:#x}", last_hash);
                        if self.peers().add_header(&last_hash) {
                            debug!("fetching tip header, immediately add tip header to storage");
                            self.storage().add_fetched_header(&tip_header);
                        }
                    } else {
                        block_hashes.push(block_hash.clone());
                    }
                }
                if !block_hashes.is_empty() {
                    let content = packed::GetBlocksProof::new_builder()
                        .block_hashes(block_hashes.clone().pack())
                        .last_hash(last_hash.clone())
                        .build();
                    let message = packed::LightClientMessage::new_builder()
                        .set(content.clone())
                        .build()
                        .as_bytes();

                    self.peers.update_blocks_proof_request(*peer, Some(content));
                    if let Err(err) =
                        nc.send_message(SupportProtocols::LightClient.protocol_id(), *peer, message)
                    {
                        let error_message =
                            format!("nc.send_message LightClientMessage, error: {:?}", err);
                        error!("{}", error_message);
                    }
                    self.peers.fetching_idle_headers(&block_hashes, now);
                }
            } else {
                debug!("all valid peers are busy for fetching blocks proof (headers)");
                break;
            }
        }

        for tx_hashes in self
            .peers
            .get_txs_to_fetch()
            .chunks(GET_TRANSACTIONS_PROOF_LIMIT)
        {
            if let Some(peer) = best_peers.iter().find(|peer| {
                self.peers
                    .get_state(peer)
                    .map(|peer_state| peer_state.get_txs_proof_request().is_none())
                    .unwrap_or(false)
            }) {
                debug!("send transaction proof request to peer: {}", peer);
                let content = packed::GetTransactionsProof::new_builder()
                    .tx_hashes(tx_hashes.to_vec().pack())
                    .last_hash(last_hash.clone())
                    .build();
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build();

                self.peers.update_txs_proof_request(*peer, Some(content));
                if let Err(err) = nc.send_message(
                    SupportProtocols::LightClient.protocol_id(),
                    *peer,
                    message.as_bytes(),
                ) {
                    let error_message =
                        format!("nc.send_message LightClientMessage, error: {:?}", err);
                    error!("{}", error_message);
                }
                self.peers.fetching_idle_txs(tx_hashes, now);
            } else {
                debug!("all valid peers are busy for fetching transactions");
                break;
            }
        }
    }

    pub(crate) fn build_prove_request_content(
        &self,
        peer_state: &PeerState,
        last_header: &VerifiableHeader,
    ) -> Option<packed::GetLastStateProof> {
        let last_n_blocks = self.last_n_blocks();
        let last_number = last_header.header().number();
        let last_total_difficulty = last_header.total_difficulty();
        let (start_hash, start_number, start_total_difficulty) = peer_state
            .get_prove_state()
            .map(|inner| {
                let last_header = inner.get_last_header();
                (
                    last_header.header().hash(),
                    last_header.header().number(),
                    last_header.total_difficulty(),
                )
            })
            .unwrap_or_else(|| {
                let (total_difficulty, last_tip) = self.storage.get_last_state();
                if total_difficulty > last_total_difficulty {
                    warn!(
                        "total difficulty ({:#x}) in storage is greater than \
                        the total difficulty ({:#x}) which requires proving",
                        total_difficulty, last_total_difficulty
                    );
                }
                let start_number: BlockNumber = last_tip.raw().number().unpack();
                if start_number >= last_number {
                    warn!(
                        "block number ({}) in storage is not less than \
                        the block number ({}) which requires proving",
                        start_number, last_number
                    );
                }
                (last_tip.calc_header_hash(), start_number, total_difficulty)
            });
        if start_total_difficulty > last_total_difficulty || start_number >= last_number {
            return None;
        }
        let builder = packed::GetLastStateProof::new_builder()
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
                &last_total_difficulty,
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
