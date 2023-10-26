//! Client-side implementation for CKB light client protocol.
//!
//! TODO(light-client) More documentation.

use std::collections::HashMap;
use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_constant::{
    hardfork::{mainnet, testnet},
    sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER,
};
use ckb_network::{
    async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
};
use ckb_types::{
    core::{BlockNumber, EpochNumber, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    U256,
};

use ckb_systemtime::unix_time_as_millis;
use log::{debug, error, info, log_enabled, trace, warn, Level};

mod components;
pub mod constant;
mod peers;
pub(crate) mod prelude;
mod sampling;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use self::peers::FetchInfo;

use prelude::*;

pub(crate) use self::peers::{LastState, Peer, PeerState, Peers, ProveRequest, ProveState};
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
        peer_index: PeerIndex,
        version: &str,
    ) {
        info!("LightClient({}).connected peer={}", version, peer_index);
        self.peers().add_peer(peer_index);
        if let Err(err) = self.get_last_state(nc.as_ref(), peer_index) {
            error!(
                "failed to request last state from peer={} since {}",
                peer_index, err
            );
        }
    }

    async fn disconnected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
    ) {
        info!("LightClient.disconnected peer={}", peer_index);
        self.peers().remove_peer(peer_index);
    }

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        data: Bytes,
    ) {
        let msg = match packed::LightClientMessageReader::from_compatible_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "LightClient.received a malformed message from Peer({})",
                    peer_index
                );
                nc.ban_peer(
                    peer_index,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        let item_name = msg.item_name();
        let status = self.try_process(nc.as_ref(), peer_index, msg);
        status.process(nc, peer_index, "LightClient", item_name);
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
        peer_index: PeerIndex,
        message: packed::LightClientMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::LightClientMessageUnionReader::SendLastState(reader) => {
                components::SendLastStateProcess::new(reader, self, peer_index, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendLastStateProof(reader) => {
                components::SendLastStateProofProcess::new(reader, self, peer_index, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlocksProof(reader) => {
                components::SendBlocksProofProcess::new(reader, self, peer_index, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendTransactionsProof(reader) => {
                components::SendTransactionsProofProcess::new(reader, self, peer_index, nc)
                    .execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    fn get_last_state(
        &self,
        nc: &dyn CKBProtocolContext,
        peer_index: PeerIndex,
    ) -> Result<(), Status> {
        let content = packed::GetLastState::new_builder()
            .subscribe(true.pack())
            .build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        self.peers().request_last_state(peer_index)?;
        nc.reply(peer_index, &message);
        Ok(())
    }

    fn get_last_state_proof(
        &self,
        nc: &dyn CKBProtocolContext,
        peer_index: PeerIndex,
    ) -> Result<bool, Status> {
        let peer_state = self
            .peers()
            .get_state(&peer_index)
            .expect("checked: should have state");

        if let Some(last_state) = peer_state.get_last_state() {
            let last_header = last_state.as_ref();

            let is_proved = peer_state
                .get_prove_state()
                .map(|inner| inner.is_same_as(last_header))
                .unwrap_or(false);

            // Skipped is the state is proved.
            if is_proved {
                return Ok(false);
            }

            // Skipped is the request is sent.
            let is_requested = peer_state
                .get_prove_request()
                .map(|inner| inner.is_same_as(last_header))
                .unwrap_or(false);
            if is_requested {
                return Ok(false);
            }

            // Skipped if the header is proved in other peers.
            if let Some((peer_index_copied_from, prove_state)) =
                self.peers().find_if_a_header_is_proved(last_header)
            {
                trace!(
                    "peer {}: copy prove state from peer {}",
                    peer_index,
                    peer_index_copied_from
                );
                self.peers().update_prove_state(peer_index, prove_state)?;
                return Ok(false);
            }

            if let Some(content) = self.build_prove_request_content(&peer_state, last_header) {
                trace!("peer {}: send get last state proof", peer_index);
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build();
                nc.reply(peer_index, &message);
                let prove_request = ProveRequest::new(last_state.clone(), content);
                self.peers()
                    .update_prove_request(peer_index, prove_request)?;
                Ok(true)
            } else {
                warn!("peer {}: build prove request failed", peer_index);
                Ok(false)
            }
        } else {
            warn!("peer {}: no last state for building request", peer_index);
            Ok(false)
        }
    }

    pub(crate) fn check_chain_root_for_headers<'a, T: Iterator<Item = &'a VerifiableHeader>>(
        &self,
        headers: T,
    ) -> Result<(), Status> {
        let mmr_activated_epoch = self.mmr_activated_epoch();
        for header in headers {
            if !header.patched_is_valid(mmr_activated_epoch) {
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
        if !verifiable_header.patched_is_valid(self.mmr_activated_epoch()) {
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
        peer_index: PeerIndex,
        last_header: VerifiableHeader,
    ) -> Result<(), Status> {
        self.check_verifiable_header(&last_header)?;
        let last_state = LastState::new(last_header);
        trace!("peer {}: update last state", peer_index);
        self.peers().update_last_state(peer_index, last_state)?;
        Ok(())
    }

    /// Update the prove state to the child block.
    /// - Update the peer's cache.
    /// - Try to update the storage without caring about fork.
    fn update_prove_state_to_child(
        &self,
        peer_index: PeerIndex,
        new_prove_state: ProveState,
    ) -> Result<(), Status> {
        let (old_total_difficulty, _) = self.storage.get_last_state();
        let new_total_difficulty = new_prove_state.get_last_header().total_difficulty();
        if new_total_difficulty > old_total_difficulty {
            self.storage.update_last_state(
                &new_total_difficulty,
                &new_prove_state.get_last_header().header().data(),
                new_prove_state.get_last_headers(),
            );
        }
        self.peers().update_prove_state(peer_index, new_prove_state)
    }

    /// Update the prove state base on the previous request.
    /// - Update the peer's cache.
    /// - Try to update the storage and handle potential fork.
    pub(crate) fn commit_prove_state(
        &self,
        peer_index: PeerIndex,
        new_prove_state: ProveState,
    ) -> Result<bool, Status> {
        let (old_total_difficulty, prev_last_header) = self.storage.get_last_state();
        let new_total_difficulty = new_prove_state.get_last_header().total_difficulty();
        if new_total_difficulty > old_total_difficulty {
            let reorg_last_headers = new_prove_state.get_reorg_last_headers();
            if reorg_last_headers.is_empty() {
                let prev_last_header_number: BlockNumber = prev_last_header.raw().number().unpack();
                // If previous last header is block#1, that means there are no previous last n
                // headers, so we could NOT distinguish whether the block#1 is a fork block or not.
                // For safety, just remove the block#1.
                if prev_last_header_number == 1 {
                    info!("rollback to block#1 since previous last header number is 1");
                    let mut matched_blocks = self.peers.matched_blocks().write().expect("poisoned");
                    while let Some((start_number, _, _)) = self.storage.get_latest_matched_blocks()
                    {
                        if start_number > 0 {
                            self.storage.remove_matched_blocks(start_number);
                        }
                    }
                    self.storage.rollback_to_block(1);
                    matched_blocks.clear();
                }
            } else {
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
                    debug!("fork to number: {}", to_number);
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
                    info!("rollback to block#{}", rollback_to);
                    self.storage.rollback_to_block(rollback_to);
                    matched_blocks.clear();
                } else {
                    warn!("long fork detected");
                    return Ok(false);
                }
            }

            self.storage.update_last_state(
                &new_total_difficulty,
                &new_prove_state.get_last_header().header().data(),
                new_prove_state.get_last_headers(),
            );
        }
        self.peers()
            .update_prove_state(peer_index, new_prove_state)?;
        Ok(true)
    }
}

impl LightClientProtocol {
    pub(crate) fn new(storage: Storage, peers: Arc<Peers>, consensus: Consensus) -> Self {
        // Ref: https://github.com/nervosnetwork/rfcs/blob/01f3bc64ef8f54c94c7b0dcf9d30c84b6c8418b0/rfcs/0044-ckb-light-client/0044-ckb-light-client.md#deployment
        let mmr_activated_epoch = match consensus.id.as_str() {
            mainnet::CHAIN_SPEC_NAME => 8651,
            testnet::CHAIN_SPEC_NAME => 5711,
            _ => 0,
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

    pub(crate) fn get_peer(&self, peer_index: &PeerIndex) -> Result<Peer, Status> {
        if let Some(state) = self.peers().get_peer(peer_index) {
            Ok(state)
        } else {
            Err(StatusCode::PeerIsNotFound.into())
        }
    }

    pub(crate) fn get_peer_state(&self, peer_index: &PeerIndex) -> Result<PeerState, Status> {
        if let Some(state) = self.peers().get_state(peer_index) {
            Ok(state)
        } else {
            Err(StatusCode::PeerIsNotFound.into())
        }
    }

    fn refresh_all_peers(&mut self, nc: &dyn CKBProtocolContext) {
        let now = unix_time_as_millis();
        for peer_index in self.peers().get_peers_which_have_timeout(now) {
            self.peers().mark_fetching_headers_timeout(peer_index);
            self.peers().mark_fetching_txs_timeout(peer_index);

            warn!("peer {}: reach timeout", peer_index);
            if let Err(err) = nc.disconnect(peer_index, "reach timeout") {
                error!("disconnect peer({}) error: {}", peer_index, err);
            };
        }
        let before_ts = now - constant::REFRESH_PEERS_DURATION.as_millis() as u64;
        for index in self.peers().get_peers_which_require_new_state(before_ts) {
            if let Err(err) = self.get_last_state(nc, index) {
                error!(
                    "failed to request last state from peer={} since {}",
                    index, err
                );
            }
        }
        for index in self.peers().get_peers_which_require_new_proof() {
            if let Err(err) = self.get_last_state_proof(nc, index) {
                error!(
                    "failed to request last state proof from peer={} since {}",
                    index, err
                );
            }
        }
        self.finalize_check_points(nc);
    }

    fn finalize_check_points(&mut self, nc: &dyn CKBProtocolContext) {
        let peers = self.peers();
        let required_peers_count = peers.required_peers_count();
        let mut peers_with_data = peers.get_all_proved_check_points();
        if log_enabled!(Level::Trace) {
            for (peer_index, (start_cpindex, check_points)) in peers_with_data.iter() {
                trace!(
                    "check points for peer {} in [{},{}]",
                    peer_index,
                    start_cpindex,
                    start_cpindex + check_points.len() as u32 - 1,
                );
            }
        }

        if peers_with_data.len() < required_peers_count {
            debug!(
                "no enough peers for finalizing check points, \
                requires {} but got {}",
                required_peers_count,
                peers_with_data.len()
            );
            return;
        }
        trace!(
            "requires {} peers for finalizing check points and got {}",
            required_peers_count,
            peers_with_data.len()
        );
        let (last_cpindex, last_check_point) = self.storage.get_last_check_point();
        trace!(
            "finalized check point is {}, {:#x}",
            last_cpindex,
            last_check_point
        );
        // Clean finalized check points for new proved peers.
        {
            let mut peers_should_be_skipped = Vec::new();
            for (peer_index, (start_cpindex, check_points)) in peers_with_data.iter_mut() {
                if *start_cpindex > last_cpindex {
                    // Impossible, in fact.
                    error!(
                        "peer {} will be banned \
                        since start check point {} is later than finalized {}",
                        peer_index, start_cpindex, last_cpindex
                    );
                    peers_should_be_skipped.push((*peer_index, true));
                    continue;
                }
                let index = (last_cpindex - *start_cpindex) as usize;
                if index >= check_points.len() {
                    peers_should_be_skipped.push((*peer_index, false));
                    continue;
                }
                if check_points[index] != last_check_point {
                    info!(
                        "peer {} will be banned \
                        since its {}-th check point is {:#x} but finalized is {:#x}",
                        peer_index, last_cpindex, check_points[index], last_check_point
                    );
                    peers_should_be_skipped.push((*peer_index, true));
                    continue;
                }
                if index > 0 {
                    check_points.drain(..index);
                    *start_cpindex = last_cpindex;
                    peers.remove_first_n_check_points(*peer_index, index);
                    trace!(
                        "peer {} remove first {} check points, \
                        new start check point is {}, {:#x}",
                        peer_index,
                        index,
                        *start_cpindex,
                        check_points[0]
                    );
                }
            }
            for (peer_index, should_ban) in peers_should_be_skipped {
                if should_ban {
                    nc.ban_peer(
                        peer_index,
                        BAD_MESSAGE_BAN_TIME,
                        String::from("incorrect check points"),
                    );
                }
                peers_with_data.remove(&peer_index);
            }
        }
        if peers_with_data.len() < required_peers_count {
            trace!(
                "no enough peers for finalizing check points after cleaning, \
                requires {} but got {}",
                required_peers_count,
                peers_with_data.len()
            );
            return;
        }
        // Find a new check point to finalized.
        let check_point_opt =
            {
                let length_max = {
                    let mut check_points_sizes = peers_with_data
                        .values()
                        .map(|(_cpindex, check_points)| check_points.len())
                        .collect::<Vec<_>>();
                    check_points_sizes.sort();
                    check_points_sizes[required_peers_count - 1]
                };
                trace!(
                    "new last check point will be less than or equal to {}",
                    last_cpindex + length_max as u32 - 1
                );
                let mut check_point_opt = None;
                // Q. Why don't check from bigger to smaller?
                // A. We have to make sure if all check points are matched.
                //    To avoid that a bad peer sends us only start checkpoints and last points are correct.
                for index in 1..length_max {
                    let map = peers_with_data
                        .values()
                        .map(|(_cpindex, check_points)| check_points.get(index))
                        .fold(HashMap::new(), |mut map, cp_opt| {
                            if let Some(cp) = cp_opt {
                                *map.entry(cp.clone()).or_default() += 1;
                            }
                            map
                        });
                    let count_max = map.values().max().cloned().unwrap_or(0);
                    if count_max >= required_peers_count {
                        let cp_opt = map.into_iter().find_map(|(cp, count)| {
                            if count == count_max {
                                Some(cp)
                            } else {
                                None
                            }
                        });
                        let cp = cp_opt.expect("checked: must be found");
                        if count_max != peers_with_data.len() {
                            peers_with_data.retain(|_, (_, check_points)| {
                            matches!(check_points.get(index), Some(tmp) if *tmp == cp)
                        });
                        }
                        check_point_opt = Some((index, cp));
                    } else {
                        break;
                    }
                }
                check_point_opt
            };
        if let Some((index, check_point)) = check_point_opt {
            let new_last_cpindex = last_cpindex + index as u32;
            info!(
                "finalize {} new check points, stop at index {}, value {:#x}",
                index, new_last_cpindex, check_point
            );
            let (_, check_points) = peers_with_data.into_values().next().expect("always exists");
            self.storage
                .update_check_points(last_cpindex + 1, &check_points[1..=index]);
            self.storage.update_max_check_point_index(new_last_cpindex);
        } else {
            trace!("no check point is found which could be finalized");
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
        for block_hashes in self
            .peers
            .get_headers_to_fetch()
            .chunks(GET_BLOCKS_PROOF_LIMIT)
        {
            if let Some(peer_index) = best_peers.iter().find(|peer_index| {
                self.peers
                    .get_peer(peer_index)
                    .map(|peer| peer.get_blocks_proof_request().is_none())
                    .unwrap_or(false)
            }) {
                debug!("send block proof request to peer: {}", peer_index);
                if !block_hashes.is_empty() {
                    let content = packed::GetBlocksProof::new_builder()
                        .block_hashes(block_hashes.to_vec().pack())
                        .last_hash(last_hash.clone())
                        .build();
                    let message = packed::LightClientMessage::new_builder()
                        .set(content.clone())
                        .build()
                        .as_bytes();

                    self.peers
                        .update_blocks_proof_request(*peer_index, Some(content), false);
                    if let Err(err) = nc.send_message(
                        SupportProtocols::LightClient.protocol_id(),
                        *peer_index,
                        message,
                    ) {
                        let error_message =
                            format!("nc.send_message LightClientMessage, error: {:?}", err);
                        error!("{}", error_message);
                    }
                    self.peers.fetching_idle_headers(block_hashes, now);
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
            if let Some(peer_index) = best_peers.iter().find(|peer_index| {
                self.peers
                    .get_peer(peer_index)
                    .map(|peer| peer.get_txs_proof_request().is_none())
                    .unwrap_or(false)
            }) {
                debug!("send transaction proof request to peer: {}", peer_index);
                let content = packed::GetTransactionsProof::new_builder()
                    .tx_hashes(tx_hashes.to_vec().pack())
                    .last_hash(last_hash.clone())
                    .build();
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build();

                self.peers
                    .update_txs_proof_request(*peer_index, Some(content));
                if let Err(err) = nc.send_message(
                    SupportProtocols::LightClient.protocol_id(),
                    *peer_index,
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
            .last_n_blocks(last_n_blocks.pack());
        let content = if last_number - start_number <= last_n_blocks {
            let last_n_headers = self.storage.get_last_n_headers();

            let (real_start_number, real_start_hash) = last_n_headers
                .into_iter()
                .find(|(num, _)| *num < start_number && last_number <= num + last_n_blocks)
                .unwrap_or((start_number, start_hash));

            builder
                .start_hash(real_start_hash)
                .start_number(real_start_number.pack())
                .difficulty_boundary(start_total_difficulty.pack())
        } else {
            let (difficulty_boundary, difficulties) = sampling::sample_blocks(
                start_number,
                &start_total_difficulty,
                last_number,
                &last_total_difficulty,
                last_n_blocks,
            );
            builder
                .start_hash(start_hash)
                .start_number(start_number.pack())
                .difficulty_boundary(difficulty_boundary.pack())
                .difficulties(difficulties.into_iter().map(|inner| inner.pack()).pack())
        }
        .build();
        Some(content)
    }

    pub(crate) fn build_prove_request_content_from_genesis(
        &self,
        last_header: &VerifiableHeader,
    ) -> Option<packed::GetLastStateProof> {
        let last_n_blocks = self.last_n_blocks();
        let last_number = last_header.header().number();
        let last_total_difficulty = last_header.total_difficulty();
        let (start_hash, start_number, start_total_difficulty) = {
            let genesis = self.storage.get_genesis_block();
            (genesis.calc_header_hash(), 0, U256::zero())
        };
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
